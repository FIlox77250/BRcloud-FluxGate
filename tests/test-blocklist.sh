#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Tests de la preservation des IP bloquees
# =============================================================================
# Ces tests existent a cause d'un incident reel : sur un serveur dont la
# blocklist etait vide, deploy.sh s'arretait en silence juste avant de
# redemarrer nftables. Le grep ne trouvait aucune IP, sortait en 1, et
# 'set -o pipefail' faisait echouer l'affectation.
#
# La blocklist vide est le cas NORMAL d'un premier deploiement : c'est le
# premier scenario teste ici.
#
# Execution : bash tests/test-blocklist.sh
# =============================================================================

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$TEST_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
PASS=0
FAIL=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; FAIL=$((FAIL+1)); }

# shellcheck source=../scripts/lib/blocklist.sh
source "${PROJECT_DIR}/scripts/lib/blocklist.sh"

echo ""
echo "============================================="
echo "  Tests de preservation des blocklists"
echo "============================================="
echo ""

# -----------------------------------------------------------------------------
# Cas 1 : blocklist vide - LE cas qui a casse un deploiement en production
# -----------------------------------------------------------------------------
echo "--- Cas 1 : blocklist vide ---"

EMPTY_SET='set blocklist4 {
        type ipv4_addr
        timeout 1h
        comment "IPs IPv4 bloquees dynamiquement"
}'

# Le point critique : sous pipefail, la fonction ne doit NI echouer NI
# interrompre le script appelant.
(
    set -euo pipefail
    source "${PROJECT_DIR}/scripts/lib/blocklist.sh"
    result=$(parse_blocklist_ips "$EMPTY_SET" 4)
    echo "MARQUEUR_FIN:${result}"
) > /tmp/fluxgate-test-empty.out 2>&1
RC=$?

if [[ $RC -eq 0 ]]; then
    pass "parse_blocklist_ips retourne 0 sur une blocklist vide"
else
    fail "parse_blocklist_ips retourne $RC sur une blocklist vide"
fi

if grep -q "MARQUEUR_FIN:" /tmp/fluxgate-test-empty.out; then
    pass "le script appelant poursuit son execution (pas de sortie silencieuse)"
else
    fail "le script appelant s'est interrompu - REGRESSION de l'incident initial"
fi

RESULT=$(parse_blocklist_ips "$EMPTY_SET" 4)
if [[ -z "${RESULT// }" ]]; then
    pass "aucune IP extraite d'une blocklist vide"
else
    fail "IP extraites a tort : '$RESULT'"
fi

echo ""

# -----------------------------------------------------------------------------
# Cas 2 : blocklist IPv4 peuplee
# -----------------------------------------------------------------------------
echo "--- Cas 2 : blocklist IPv4 peuplee ---"

FULL_SET4='set blocklist4 {
        type ipv4_addr
        flags timeout
        timeout 1h
        elements = { 203.0.113.50 expires 59m58s,
                     198.51.100.7 expires 12m3s,
                     192.0.2.1 expires 1h }
}'

RESULT=$(parse_blocklist_ips "$FULL_SET4" 4)
for ip in 203.0.113.50 198.51.100.7 192.0.2.1; do
    if grep -qw "$ip" <<< "$RESULT"; then
        pass "IP $ip extraite"
    else
        fail "IP $ip absente du resultat : '$RESULT'"
    fi
done

# Les durees d'expiration ne doivent pas etre confondues avec des adresses
if grep -qE '59m58s|expires' <<< "$RESULT"; then
    fail "des durees d'expiration ont ete extraites : '$RESULT'"
else
    pass "les durees d'expiration ne sont pas prises pour des adresses"
fi

NB=$(wc -w <<< "$RESULT")
[[ "$NB" -eq 3 ]] && pass "3 adresses extraites" || fail "$NB adresses extraites au lieu de 3"

echo ""

# -----------------------------------------------------------------------------
# Cas 3 : blocklist IPv6
# -----------------------------------------------------------------------------
echo "--- Cas 3 : blocklist IPv6 ---"

FULL_SET6='set blocklist6 {
        type ipv6_addr
        flags timeout
        elements = { 2001:db8::1 expires 30m,
                     fe80::dead:beef expires 1h }
}'

RESULT6=$(parse_blocklist_ips "$FULL_SET6" 6)
for ip in "2001:db8::1" "fe80::dead:beef"; do
    if grep -q "$ip" <<< "$RESULT6"; then
        pass "IPv6 $ip extraite"
    else
        fail "IPv6 $ip absente : '$RESULT6'"
    fi
done

echo ""

# -----------------------------------------------------------------------------
# Cas 4 : entrees vides ou aberrantes
# -----------------------------------------------------------------------------
echo "--- Cas 4 : entrees degradees ---"

for label in "chaine vide" "set inexistant"; do
    case "$label" in
        "chaine vide")    INPUT="" ;;
        "set inexistant") INPUT="Error: No such file or directory" ;;
    esac
    if OUT=$(parse_blocklist_ips "$INPUT" 4) && [[ -z "${OUT// }" ]]; then
        pass "$label : resultat vide, pas d'erreur"
    else
        fail "$label : comportement inattendu (rc=$?, out='$OUT')"
    fi
done

echo ""
echo "============================================="
echo -e "  ${GREEN}${PASS} PASS${NC}  ${RED}${FAIL} FAIL${NC}"
echo "============================================="
echo ""

rm -f /tmp/fluxgate-test-empty.out
[[ $FAIL -eq 0 ]] || exit 1
exit 0
