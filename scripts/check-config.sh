#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Validation de config.env
# =============================================================================
# Verifie que config.env est complet et coherent AVANT de toucher au serveur.
# Appele automatiquement par deploy.sh, utilisable seul :
#
#   bash scripts/check-config.sh
#
# Codes de sortie :
#   0 = configuration exploitable (des avertissements sont possibles)
#   1 = erreur bloquante, le deploiement doit etre annule
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${1:-${SCRIPT_DIR}/config.env}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

err()  { echo -e "  ${RED}[ERREUR]${NC} $*"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC}   $*"; WARNINGS=$((WARNINGS+1)); }
ok()   { echo -e "  ${GREEN}[OK]${NC}     $*"; }

echo ""
echo -e "${CYAN}=============================================${NC}"
echo "  BRCloud FluxGate - Validation config.env"
echo -e "${CYAN}=============================================${NC}"
echo ""

if [[ ! -f "$CONFIG_FILE" ]]; then
    err "Fichier introuvable : $CONFIG_FILE"
    echo ""
    echo "  Creer la configuration :"
    echo "    cp ${SCRIPT_DIR}/config.env.example ${SCRIPT_DIR}/config.env"
    echo ""
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# Verifie qu'une variable est definie et non vide
require_set() {
    local name="$1"
    if [[ -z "${!name:-}" ]]; then
        err "$name n'est pas defini (obligatoire)."
        return 1
    fi
    return 0
}

# Verifie qu'une variable est un entier dans un intervalle
require_int() {
    local name="$1" min="$2" max="$3"
    local val="${!name:-}"
    if [[ -z "$val" ]]; then
        err "$name n'est pas defini (obligatoire)."
        return 1
    fi
    if [[ ! "$val" =~ ^[0-9]+$ ]]; then
        err "$name doit etre un entier (valeur actuelle : '$val')."
        return 1
    fi
    if (( val < min || val > max )); then
        err "$name = $val hors de l'intervalle attendu [$min-$max]."
        return 1
    fi
    return 0
}

# Verifie un booleen true/false
require_bool() {
    local name="$1"
    local val="${!name:-}"
    if [[ "$val" != "true" && "$val" != "false" ]]; then
        err "$name doit valoir 'true' ou 'false' (valeur actuelle : '$val')."
        return 1
    fi
    return 0
}

# Verifie qu'une valeur ne contient pas de placeholder laisse en l'etat
reject_placeholder() {
    local name="$1"
    local val="${!name:-}"
    if [[ "$val" =~ (PLACEHOLDER|CHANGEME|TODO|A_REMPLIR|xxx|XXX) ]]; then
        err "$name contient encore un placeholder : '$val'."
        return 1
    fi
    return 0
}

# Verifie le format d'un set nftables : { a, b, c }
require_nft_set() {
    local name="$1"
    local val="${!name:-}"
    if [[ -z "$val" ]]; then
        err "$name n'est pas defini (obligatoire)."
        return 1
    fi
    if [[ ! "$val" =~ ^\{.*\}$ ]]; then
        err "$name doit etre au format nftables avec accolades, ex : { 192.168.0.0/24 } (valeur : '$val')."
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# 1. Variables obligatoires
# -----------------------------------------------------------------------------
echo "--- Variables obligatoires ---"

for v in IFACE SSH_PORT HTTP_PORT HTTPS_PORT ADMIN_NETS ADMIN_NETS6; do
    require_set "$v" && reject_placeholder "$v"
done

require_int SSH_PORT   1 65535 && ok "SSH_PORT = $SSH_PORT"
require_int HTTP_PORT  1 65535 && ok "HTTP_PORT = $HTTP_PORT"
require_int HTTPS_PORT 1 65535 && ok "HTTPS_PORT = $HTTPS_PORT"

require_nft_set ADMIN_NETS  && ok "ADMIN_NETS = $ADMIN_NETS"
require_nft_set ADMIN_NETS6 && ok "ADMIN_NETS6 = $ADMIN_NETS6"

echo ""

# -----------------------------------------------------------------------------
# 2. Coherence avec la machine
# -----------------------------------------------------------------------------
echo "--- Coherence avec la machine ---"

if command -v ip &>/dev/null; then
    if ip link show dev "$IFACE" &>/dev/null; then
        ok "Interface '$IFACE' presente."
    else
        err "Interface '$IFACE' introuvable. Interfaces disponibles : $(ip -br link 2>/dev/null | awk '{print $1}' | grep -v '^lo$' | tr '\n' ' ')"
    fi
else
    warn "Commande 'ip' absente : impossible de verifier l'interface."
fi

# Le port SSH declare doit correspondre a ce qui ecoute vraiment,
# sinon le pare-feu ferme la porte par laquelle on est entre.
if command -v ss &>/dev/null; then
    LISTENING_SSH=$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -u)
    if [[ -n "$LISTENING_SSH" ]]; then
        if echo "$LISTENING_SSH" | grep -qx "$SSH_PORT"; then
            ok "Un service ecoute bien sur le port SSH declare ($SSH_PORT)."
        else
            warn "Rien n'ecoute sur le port $SSH_PORT. Ports en ecoute : $(echo "$LISTENING_SSH" | tr '\n' ' ')"
            warn "Verifier SSH_PORT avant de deployer : un mauvais port = lockout garanti."
        fi
    fi
fi

# Detection de la session SSH courante : est-elle couverte par ADMIN_NETS ?
CURRENT_SSH_IP=""
if [[ -n "${SSH_CLIENT:-}" ]]; then
    CURRENT_SSH_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
elif [[ -n "${SSH_CONNECTION:-}" ]]; then
    CURRENT_SSH_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
fi

if [[ -n "$CURRENT_SSH_IP" ]]; then
    if [[ "$CURRENT_SSH_IP" == *:* ]]; then
        ok "Session SSH detectee en IPv6 depuis $CURRENT_SSH_IP"
        if [[ "$ADMIN_NETS6" == "{ fc00::/7, fe80::/10 }" ]]; then
            warn "ADMIN_NETS6 est reste sur les valeurs par defaut (adresses locales)."
            warn "En mode SSH strict, votre IPv6 publique ne sera pas whitelistee."
        fi
    else
        ok "Session SSH detectee en IPv4 depuis $CURRENT_SSH_IP"
    fi
else
    warn "Session SSH non detectee (console locale, ou sudo -i qui vide l'environnement)."
fi

echo ""

# -----------------------------------------------------------------------------
# 3. Valeurs numeriques
# -----------------------------------------------------------------------------
echo "--- Seuils et limites ---"

require_int NFT_SYN_RATE        1 1000000  && ok "NFT_SYN_RATE = $NFT_SYN_RATE/s par IP"
require_int NFT_SYN_BURST       1 1000000  && ok "NFT_SYN_BURST = $NFT_SYN_BURST"
require_int NFT_HTTP_SYN_RATE   1 1000000
require_int NFT_HTTP_SYN_BURST  1 1000000
require_int CONNTRACK_MAX       1024 16777216 && ok "CONNTRACK_MAX = $CONNTRACK_MAX"
require_int CONNTRACK_BUCKETS   256  4194304
require_int SOMAXCONN           128  1048576
require_int TCP_MAX_SYN_BACKLOG 128  1048576
require_int NGINX_REQ_PER_SEC   1    100000
require_int NGINX_BURST         1    100000
require_int NGINX_MAX_CONN_PER_IP 1  100000
require_int NGINX_UPSTREAM_PORT 1    65535
require_int F2B_SSH_MAXRETRY    1    1000
require_int F2B_SSH_FINDTIME    1    86400
require_int F2B_SSH_BANTIME     1    31536000
require_int F2B_HTTP_MAXRETRY   1    1000000
require_int F2B_HTTP_FINDTIME   1    86400
require_int F2B_HTTP_BANTIME    1    31536000

# Le rate HTTP est global, pas par IP : une valeur basse jette des visiteurs.
if [[ "${NFT_HTTP_SYN_RATE:-0}" =~ ^[0-9]+$ ]] && (( NFT_HTTP_SYN_RATE < 100 )); then
    warn "NFT_HTTP_SYN_RATE = ${NFT_HTTP_SYN_RATE}/s est un plafond GLOBAL (toutes IP confondues)."
    warn "Sur un site frequente, cela coupe des visiteurs legitimes : 500-2000 est plus realiste."
else
    ok "NFT_HTTP_SYN_RATE = ${NFT_HTTP_SYN_RATE:-?}/s (global)"
fi

# Un burst inferieur au rate n'a pas de sens
if [[ "${NFT_SYN_RATE:-}" =~ ^[0-9]+$ ]] && [[ "${NFT_SYN_BURST:-}" =~ ^[0-9]+$ ]]; then
    (( NFT_SYN_BURST < NFT_SYN_RATE )) && warn "NFT_SYN_BURST ($NFT_SYN_BURST) < NFT_SYN_RATE ($NFT_SYN_RATE) : burst sans effet utile."
fi

# conntrack_buckets doit rester proportionnel a conntrack_max (~1/4)
if [[ "${CONNTRACK_MAX:-}" =~ ^[0-9]+$ ]] && [[ "${CONNTRACK_BUCKETS:-}" =~ ^[0-9]+$ ]]; then
    if (( CONNTRACK_BUCKETS * 16 < CONNTRACK_MAX )); then
        warn "CONNTRACK_BUCKETS ($CONNTRACK_BUCKETS) tres faible face a CONNTRACK_MAX ($CONNTRACK_MAX) : collisions de hash."
    fi
fi

echo ""

# -----------------------------------------------------------------------------
# 4. Booleens et options avancees
# -----------------------------------------------------------------------------
echo "--- Options ---"

require_bool XDP_ENABLED   && ok "XDP_ENABLED = $XDP_ENABLED"
require_bool SYNPROXY_ENABLED && ok "SYNPROXY_ENABLED = $SYNPROXY_ENABLED"
require_bool F2B_USE_FLUXGATE_SETS && ok "F2B_USE_FLUXGATE_SETS = $F2B_USE_FLUXGATE_SETS"

if [[ "${SYNPROXY_ENABLED:-false}" == "true" ]]; then
    warn "SYNPROXY active : a valider hors production avant tout usage reel."
    require_int SYNPROXY_MSS    536 9000
    require_int SYNPROXY_WSCALE 0   14
    # Prerequis noyau
    if [[ -f /proc/sys/net/netfilter/nf_conntrack_tcp_loose ]]; then
        LOOSE=$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_loose 2>/dev/null || echo 1)
        if [[ "$LOOSE" != "0" ]]; then
            warn "nf_conntrack_tcp_loose = $LOOSE (doit passer a 0 : applique par le deploiement sysctl)."
        fi
    fi
fi

# Empreinte et checksum CRS
if [[ -n "${CRS_SHA256:-}" ]] && [[ ! "${CRS_SHA256}" =~ ^[a-f0-9]{64}$ ]]; then
    err "CRS_SHA256 n'est pas un sha256 valide (64 caracteres hexadecimaux minuscules)."
fi
if [[ -n "${CRS_GPG_FINGERPRINT:-}" ]] && [[ ! "${CRS_GPG_FINGERPRINT}" =~ ^[A-F0-9]{40}$ ]]; then
    err "CRS_GPG_FINGERPRINT n'est pas une empreinte valide (40 caracteres hexadecimaux majuscules)."
fi
[[ -n "${CRS_VERSION:-}" ]] && ok "OWASP CRS cible : v${CRS_VERSION}"

echo ""

# -----------------------------------------------------------------------------
# Resume
# -----------------------------------------------------------------------------
echo -e "${CYAN}=============================================${NC}"
if (( ERRORS > 0 )); then
    echo -e "  Resultat : ${RED}${ERRORS} erreur(s)${NC}, ${WARNINGS} avertissement(s)"
    echo -e "${CYAN}=============================================${NC}"
    echo ""
    echo "  Corriger $CONFIG_FILE avant de relancer le deploiement."
    echo ""
    exit 1
fi

if (( WARNINGS > 0 )); then
    echo -e "  Resultat : ${GREEN}configuration exploitable${NC}, ${YELLOW}${WARNINGS} avertissement(s)${NC}"
else
    echo -e "  Resultat : ${GREEN}configuration valide${NC}"
fi
echo -e "${CYAN}=============================================${NC}"
echo ""
exit 0
