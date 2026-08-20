#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Tests du rendu de nftables.conf
# =============================================================================
# Verifie que chaque valeur de config.env atterrit bien dans le pare-feu.
#
# Ce test existe parce que la substitution se fait par sed sur des ancres
# textuelles : une reformulation anodine de nftables.conf peut faire echouer
# une substitution sans le moindre message, et le serveur part alors avec des
# seuils par defaut qu'on croit avoir changes.
#
# Execution :  bash tests/test-templating.sh
# Ne touche a rien sur la machine : tout se passe dans un repertoire temporaire.
# =============================================================================

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$TEST_DIR")"
MODEL="${PROJECT_DIR}/nftables/nftables.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; FAIL=$((FAIL+1)); }

# Les fonctions de log de la lib sont silencieuses pendant les tests reussis
log_info()  { :; }
log_warn()  { echo "    (warn) $*"; }
log_error() { echo "    (error) $*"; }

# shellcheck source=../scripts/lib/nft-template.sh
source "${PROJECT_DIR}/scripts/lib/nft-template.sh"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# -----------------------------------------------------------------------------
# assert_contains <fichier> <motif grep -E> <description>
# -----------------------------------------------------------------------------
assert_contains() {
    local file="$1" pattern="$2" desc="$3"
    if grep -qE "$pattern" "$file"; then
        pass "$desc"
    else
        fail "$desc"
        echo "         motif absent : $pattern"
    fi
}

assert_not_contains() {
    local file="$1" pattern="$2" desc="$3"
    if grep -qE "$pattern" "$file"; then
        fail "$desc"
        echo "         motif present a tort : $pattern"
    else
        pass "$desc"
    fi
}

echo ""
echo "============================================="
echo "  Tests de rendu nftables.conf"
echo "============================================="
echo ""

# -----------------------------------------------------------------------------
# Cas 1 : valeurs personnalisees, mode strict, sans SYNPROXY
# -----------------------------------------------------------------------------
echo "--- Cas 1 : valeurs personnalisees, SSH strict ---"

CONF="$WORK/case1.conf"
cp "$MODEL" "$CONF"

SSH_PORT=2222 \
HTTP_PORT=8080 \
HTTPS_PORT=8443 \
ADMIN_NETS="{ 203.0.113.50/32 }" \
ADMIN_NETS6="{ 2001:db8::/32 }" \
NFT_SYN_RATE=250 \
NFT_SYN_BURST=400 \
NFT_HTTP_SYN_RATE=1500 \
NFT_HTTP_SYN_BURST=3000 \
SYNPROXY_ENABLED=false \
SSH_MODE=strict \
render_nftables_conf "$CONF"
RC=$?

[[ $RC -eq 0 ]] && pass "render_nftables_conf retourne 0" || fail "render_nftables_conf retourne $RC"

assert_contains "$CONF" '^define SSH_PORT   = 2222$'          "Port SSH applique"
assert_contains "$CONF" '^define HTTP_PORT  = 8080$'          "Port HTTP applique"
assert_contains "$CONF" '^define HTTPS_PORT = 8443$'          "Port HTTPS applique"
assert_contains "$CONF" '^define ADMIN_NETS  = \{ 203\.0\.113\.50/32 \}$'  "ADMIN_NETS applique"
assert_contains "$CONF" '^define ADMIN_NETS6 = \{ 2001:db8::/32 \}$'       "ADMIN_NETS6 applique"

# Rate per-IP sur les deux familles
assert_contains "$CONF" '@syn_flood4 \{ ip saddr limit rate over 250/second burst 400 packets \}'  "Rate per-IP IPv4 applique"
assert_contains "$CONF" '@syn_flood6 \{ ip6 saddr limit rate over 250/second burst 400 packets \}' "Rate per-IP IPv6 applique"

# Rate global HTTP
assert_contains "$CONF" '^[[:space:]]+limit rate 1500/second burst 3000 packets accept' "Rate global HTTP(S) applique"

# Regression : les limites ICMP ne doivent PAS etre touchees par le sed HTTP.
# C'est le piege exact rencontre pendant la mise a jour : le motif attrapait
# aussi les regles ICMP et faisait sauter leur limite a la valeur HTTP.
assert_contains "$CONF" '\} limit rate 10/second burst 20 packets accept' "Limites ICMP preservees"

# Regression : le rate limit SSH est en /minute, il ne doit pas etre reecrit
assert_contains "$CONF" 'limit rate 5/minute burst 10 packets accept' "Rate limit SSH preserve"

# Mode strict : les regles admin restent actives
assert_contains "$CONF" '^[[:space:]]+tcp dport \$SSH_PORT ip  saddr \$ADMIN_NETS ' "Mode strict : regle admin IPv4 active"
assert_contains "$CONF" '^[[:space:]]+tcp dport \$SSH_PORT ip6 saddr \$ADMIN_NETS6 ' "Mode strict : regle admin IPv6 active"

# SYNPROXY desactive : aucune regle ne doit etre decommentee
assert_not_contains "$CONF" '^[[:space:]]+chain prerouting \{' "SYNPROXY off : pas de chaine prerouting"
assert_not_contains "$CONF" '^[[:space:]]+tcp dport \{ \$HTTP_PORT, \$HTTPS_PORT \} ct state invalid,untracked' "SYNPROXY off : pas de regle synproxy"

echo ""

# -----------------------------------------------------------------------------
# Cas 2 : mode SSH ouvert
# -----------------------------------------------------------------------------
echo "--- Cas 2 : SSH ouvert a tous ---"

CONF2="$WORK/case2.conf"
cp "$MODEL" "$CONF2"

SSH_MODE=open SYNPROXY_ENABLED=false render_nftables_conf "$CONF2"

# Les DEUX lignes admin doivent etre commentees : n'en commenter qu'une
# laisserait l'autre famille filtree sans que personne ne s'en apercoive.
assert_contains "$CONF2" '^[[:space:]]+# tcp dport \$SSH_PORT ip  saddr \$ADMIN_NETS '  "Mode ouvert : regle admin IPv4 commentee"
assert_contains "$CONF2" '^[[:space:]]+# tcp dport \$SSH_PORT ip6 saddr \$ADMIN_NETS6 ' "Mode ouvert : regle admin IPv6 commentee"
assert_contains "$CONF2" 'tcp dport \$SSH_PORT ct state new limit rate' "Mode ouvert : rate limit SSH conserve"

echo ""

# -----------------------------------------------------------------------------
# Cas 3 : SYNPROXY active
# -----------------------------------------------------------------------------
echo "--- Cas 3 : SYNPROXY active ---"

CONF3="$WORK/case3.conf"
cp "$MODEL" "$CONF3"

SYNPROXY_ENABLED=true SYNPROXY_MSS=1400 SYNPROXY_WSCALE=8 SSH_MODE=strict \
    render_nftables_conf "$CONF3"

assert_contains "$CONF3" '^[[:space:]]+chain prerouting \{'                    "SYNPROXY : chaine prerouting decommentee"
assert_contains "$CONF3" 'type filter hook prerouting priority raw'            "SYNPROXY : hook raw present"
assert_contains "$CONF3" 'tcp flags syn notrack'                               "SYNPROXY : notrack present"
assert_contains "$CONF3" 'ct state invalid,untracked'                          "SYNPROXY : regle input decommentee"
assert_contains "$CONF3" 'synproxy mss 1400 wscale 8 timestamp sack-perm'      "SYNPROXY : mss/wscale appliques"

# L'ordre est critique : la regle synproxy doit preceder le drop des invalides,
# sinon l'ACK final du handshake est jete et plus aucune connexion n'aboutit.
LINE_SYNPROXY=$(grep -n 'synproxy mss' "$CONF3" | head -1 | cut -d: -f1)
LINE_INVALID=$(grep -n 'ct state invalid counter drop' "$CONF3" | head -1 | cut -d: -f1)
if [[ -n "$LINE_SYNPROXY" ]] && [[ -n "$LINE_INVALID" ]] && (( LINE_SYNPROXY < LINE_INVALID )); then
    pass "SYNPROXY : regle placee avant le drop des paquets invalides (ligne $LINE_SYNPROXY < $LINE_INVALID)"
else
    fail "SYNPROXY : ordre incorrect (synproxy=$LINE_SYNPROXY, invalid drop=$LINE_INVALID)"
fi

echo ""

# -----------------------------------------------------------------------------
# Cas 4 : detection d'une ancre disparue
# -----------------------------------------------------------------------------
echo "--- Cas 4 : ancre manquante detectee ---"

CONF4="$WORK/case4.conf"
cp "$MODEL" "$CONF4"
# Simuler une reformulation qui casse l'ancre du set dynamique
sed -i 's/@syn_flood4 { ip saddr limit rate over/@syn_flood4 { ip saddr limit rate OVER/' "$CONF4"

if SYNPROXY_ENABLED=false SSH_MODE=strict render_nftables_conf "$CONF4" 2>/dev/null; then
    fail "Une ancre cassee devrait faire echouer le rendu"
else
    pass "Ancre cassee correctement detectee (echec du rendu)"
fi

echo ""

# -----------------------------------------------------------------------------
# Cas 5 : valeurs par defaut si config.env est absent
# -----------------------------------------------------------------------------
echo "--- Cas 5 : valeurs par defaut ---"

CONF5="$WORK/case5.conf"
cp "$MODEL" "$CONF5"

env -u SSH_PORT -u HTTP_PORT -u HTTPS_PORT -u ADMIN_NETS -u ADMIN_NETS6 \
    -u NFT_SYN_RATE -u NFT_SYN_BURST -u NFT_HTTP_SYN_RATE -u NFT_HTTP_SYN_BURST \
    -u SYNPROXY_ENABLED -u SSH_MODE \
    bash -c "source '${PROJECT_DIR}/scripts/lib/nft-template.sh'; render_nftables_conf '$CONF5'" >/dev/null 2>&1

assert_contains "$CONF5" '^define SSH_PORT   = 22$'  "Defaut : port SSH 22"
assert_contains "$CONF5" '@syn_flood4 \{ ip saddr limit rate over 100/second burst 150 packets \}' "Defaut : rate per-IP 100/150"

echo ""

# -----------------------------------------------------------------------------
# Resume
# -----------------------------------------------------------------------------
echo "============================================="
echo -e "  ${GREEN}${PASS} PASS${NC}  ${RED}${FAIL} FAIL${NC}"
echo "============================================="
echo ""

[[ $FAIL -eq 0 ]] || exit 1
exit 0
