#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Validation de config.env
# =============================================================================
# Verifie que config.env est complet et coherent AVANT de toucher au serveur.
# Appele automatiquement par deploy.sh, utilisable seul :
#
#   bash scripts/check-config.sh [config.env]
#
# Codes de sortie :
#   0 = configuration exploitable (des avertissements sont possibles)
#   1 = erreur bloquante, le deploiement doit etre annule
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${1:-${FLUXGATE_CONFIG:-${SCRIPT_DIR}/config.env}}"

# shellcheck source=lib/defaults.sh
source "${SCRIPT_DIR}/lib/defaults.sh"

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

# require_enum <NOM> <valeur1> <valeur2>... : valeur parmi une liste fermee
require_enum() {
    local name="$1" val="${!1:-}" v
    shift
    for v in "$@"; do
        [[ "$val" == "$v" ]] && return 0
    done
    err "$name = '$val' : valeurs acceptees : $*."
    return 1
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

# Comme require_nft_set, mais une valeur vide est acceptee
optional_nft_set() {
    [[ -z "${!1:-}" ]] && return 0
    require_nft_set "$1"
}

# require_port_list <NOM> : liste de ports separes par espaces ou virgules
require_port_list() {
    local name="$1" p
    for p in ${!name//,/ }; do
        if [[ ! "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
            err "$name : '$p' n'est pas un port valide (1-65535)."
            return 1
        fi
    done
    return 0
}

# -----------------------------------------------------------------------------
# 0. Droits du fichier et cles absentes
# -----------------------------------------------------------------------------
# config.env est source en root par tous les scripts : un fichier modifiable
# par un autre utilisateur lui donnerait un acces root.
if ! fluxgate_check_config_perms "$CONFIG_FILE"; then
    err "Droits de $CONFIG_FILE refuses (voir ci-dessus)."
    exit 1
fi

# Les cles absentes prennent leur valeur par defaut (lib/defaults.sh) : on
# le signale sans bloquer, sinon toute mise a jour d'un serveur deja
# deploye serait impossible.
MISSING_KEYS=()
for k in $(printf '%s\n' "${!FLUXGATE_DEFAULTS[@]}" | sort); do
    grep -qE "^[[:space:]]*(export[[:space:]]+)?${k}=" "$CONFIG_FILE" || MISSING_KEYS+=("$k")
done

# shellcheck source=/dev/null
source "$CONFIG_FILE"
fluxgate_apply_defaults

LEGACY_CONFIG=false
if [[ ${#MISSING_KEYS[@]} -gt 0 ]]; then
    LEGACY_CONFIG=true
    echo "--- Version de la configuration ---"
    warn "${#MISSING_KEYS[@]} cle(s) absente(s) de votre config.env : valeurs par defaut utilisees."
    echo "         Manquantes : ${MISSING_KEYS[*]}"
    echo ""
    echo "         Pour les ajouter en conservant vos reglages actuels :"
    echo "             bash ${SCRIPT_DIR}/migrate-config.sh"
    echo ""
fi

# -----------------------------------------------------------------------------
# 1. Variables obligatoires
# -----------------------------------------------------------------------------
echo "--- Variables obligatoires ---"

# IFACE n'a pas de valeur par defaut sure : il reste strictement obligatoire.
for v in IFACE SSH_PORT HTTP_PORT HTTPS_PORT ADMIN_NETS ADMIN_NETS6; do
    require_set "$v" && reject_placeholder "$v"
done

require_int SSH_PORT   1 65535 && ok "SSH_PORT = $SSH_PORT"
require_int HTTP_PORT  1 65535 && ok "HTTP_PORT = $HTTP_PORT"
require_int HTTPS_PORT 1 65535 && ok "HTTPS_PORT = $HTTPS_PORT"

require_nft_set ADMIN_NETS  && ok "ADMIN_NETS = $ADMIN_NETS"
require_nft_set ADMIN_NETS6 && ok "ADMIN_NETS6 = $ADMIN_NETS6"
optional_nft_set ALLOWLIST4 && [[ -n "$ALLOWLIST4" ]] && ok "ALLOWLIST4 = $ALLOWLIST4"
optional_nft_set ALLOWLIST6 && [[ -n "$ALLOWLIST6" ]] && ok "ALLOWLIST6 = $ALLOWLIST6"

if require_port_list EXTRA_TCP_PORTS && [[ -n "$EXTRA_TCP_PORTS" ]]; then
    ok "Ports TCP supplementaires : $EXTRA_TCP_PORTS"
    for p in ${EXTRA_TCP_PORTS//,/ }; do
        [[ "$p" == "$SSH_PORT" ]] && warn "EXTRA_TCP_PORTS contient le port SSH : il serait ouvert sans limite de debit."
    done
fi
if require_port_list EXTRA_UDP_PORTS && [[ -n "$EXTRA_UDP_PORTS" ]]; then
    ok "Ports UDP supplementaires : $EXTRA_UDP_PORTS"
fi

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
        if [[ "$SSH_MODE" == "strict" ]] && [[ "$ADMIN_NETS6" == "{ fc00::/7, fe80::/10 }" ]]; then
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
require_int NFT_SSH_RATE        1 10000    && ok "NFT_SSH_RATE = $NFT_SSH_RATE/min par IP"
require_int NFT_SSH_BURST       1 10000
require_int NFT_HTTP_CONN_LIMIT 0 1000000
require_int CONNTRACK_MAX       1024 16777216 && ok "CONNTRACK_MAX = $CONNTRACK_MAX"
require_int CONNTRACK_BUCKETS   256  4194304
require_int SOMAXCONN           128  1048576
require_int TCP_MAX_SYN_BACKLOG 128  1048576
require_int NGINX_REQ_PER_SEC   1    100000
require_int NGINX_BURST         1    100000
require_int NGINX_LOGIN_BURST   1    100000
require_int NGINX_MAX_CONN_PER_IP 1  100000
require_int NGINX_UPSTREAM_PORT 1    65535
require_int F2B_SSH_MAXRETRY    1    1000
require_int F2B_SSH_FINDTIME    1    86400
require_int F2B_SSH_BANTIME     1    31536000
require_int F2B_HTTP_MAXRETRY   1    1000000
require_int F2B_HTTP_FINDTIME   1    86400
require_int F2B_HTTP_BANTIME    1    31536000
require_int CROWDSEC_LAPI_PORT  1    65535
require_int SHIELD_SYN_RATE     1    1000000
require_int SHIELD_SYN_BURST    1    1000000
require_int SHIELD_CONN_LIMIT   1    1000000
require_int XDP_BLOCK_THRESHOLD 10   10000000
require_int XDP_BLOCK_TIMEOUT   0    31536000
require_int XDP_SAMPLE_INTERVAL 1    3600

# Toutes les limites nftables sont par IP (par /64 en IPv6). Trop basses,
# elles genent les visiteurs qui partagent une IP (NAT d'entreprise, CGNAT).
if [[ "$NFT_HTTP_SYN_RATE" =~ ^[0-9]+$ ]] && (( NFT_HTTP_SYN_RATE < 10 )); then
    warn "NFT_HTTP_SYN_RATE = ${NFT_HTTP_SYN_RATE}/s par IP : trop bas pour des clients derriere un NAT ou CGNAT."
else
    ok "NFT_HTTP_SYN_RATE = ${NFT_HTTP_SYN_RATE}/s par IP"
fi
if [[ "$NFT_HTTP_CONN_LIMIT" == "0" ]]; then
    warn "NFT_HTTP_CONN_LIMIT = 0 : pas de limite de connexions simultanees par IP."
elif [[ "$NFT_HTTP_CONN_LIMIT" =~ ^[0-9]+$ ]] && (( NFT_HTTP_CONN_LIMIT < 32 )); then
    warn "NFT_HTTP_CONN_LIMIT = ${NFT_HTTP_CONN_LIMIT} : un navigateur ouvre jusqu'a 6 connexions par hote, un NAT en cumule beaucoup."
fi

# Un burst inferieur au rate n'a pas de sens
if [[ "$NFT_SYN_RATE" =~ ^[0-9]+$ ]] && [[ "$NFT_SYN_BURST" =~ ^[0-9]+$ ]]; then
    (( NFT_SYN_BURST < NFT_SYN_RATE )) && warn "NFT_SYN_BURST ($NFT_SYN_BURST) < NFT_SYN_RATE ($NFT_SYN_RATE) : burst sans effet utile."
fi

# Le bouclier doit etre plus strict que le regime normal
if [[ "$SHIELD_SYN_RATE" =~ ^[0-9]+$ ]] && [[ "$NFT_HTTP_SYN_RATE" =~ ^[0-9]+$ ]] \
   && (( SHIELD_SYN_RATE >= NFT_HTTP_SYN_RATE )); then
    warn "SHIELD_SYN_RATE ($SHIELD_SYN_RATE) >= NFT_HTTP_SYN_RATE ($NFT_HTTP_SYN_RATE) : le bouclier ne resserre rien."
fi
if [[ "$SHIELD_CONN_LIMIT" =~ ^[0-9]+$ ]] && [[ "$NFT_HTTP_CONN_LIMIT" =~ ^[0-9]+$ ]] \
   && (( NFT_HTTP_CONN_LIMIT > 0 && SHIELD_CONN_LIMIT >= NFT_HTTP_CONN_LIMIT )); then
    warn "SHIELD_CONN_LIMIT ($SHIELD_CONN_LIMIT) >= NFT_HTTP_CONN_LIMIT ($NFT_HTTP_CONN_LIMIT) : le bouclier ne resserre rien."
fi
if [[ ! "$SHIELD_DURATION" =~ ^[0-9]+[smhd]?$ ]]; then
    err "SHIELD_DURATION = '$SHIELD_DURATION' : attendu un nombre suivi de s, m, h ou d (ex : 30m)."
fi

# conntrack_buckets doit rester proportionnel a conntrack_max (~1/4)
if [[ "$CONNTRACK_MAX" =~ ^[0-9]+$ ]] && [[ "$CONNTRACK_BUCKETS" =~ ^[0-9]+$ ]]; then
    if (( CONNTRACK_BUCKETS * 16 < CONNTRACK_MAX )); then
        warn "CONNTRACK_BUCKETS ($CONNTRACK_BUCKETS) tres faible face a CONNTRACK_MAX ($CONNTRACK_MAX) : collisions de hash."
    fi
fi

# XDP : un seuil bas bannit les NAT/CGNAT qui ouvrent beaucoup de connexions
if [[ "$XDP_AUTOBLOCK" == "true" ]] && [[ "$XDP_BLOCK_THRESHOLD" =~ ^[0-9]+$ ]] && (( XDP_BLOCK_THRESHOLD < 300 )); then
    warn "XDP_BLOCK_THRESHOLD = $XDP_BLOCK_THRESHOLD : risque de bannir des clients legitimes derriere un NAT."
fi

echo ""

# -----------------------------------------------------------------------------
# 4. Ports internes : pas de collision
# -----------------------------------------------------------------------------
echo "--- Ports internes ---"

# Le port de l'API locale CrowdSec (8080 en amont) entrait en conflit avec
# l'application derriere NGINX : l'un des deux ne demarrait pas.
if [[ "$CROWDSEC_LAPI_PORT" =~ ^[0-9]+$ ]]; then
    conflict=""
    for v in SSH_PORT HTTP_PORT HTTPS_PORT NGINX_UPSTREAM_PORT SVC_LISTEN_PORT \
             PROMETHEUS_PORT NODE_EXPORTER_PORT GRAFANA_PORT; do
        [[ "${!v:-}" == "$CROWDSEC_LAPI_PORT" ]] && conflict+=" $v"
    done
    for p in ${EXTRA_TCP_PORTS//,/ }; do
        [[ "$p" == "$CROWDSEC_LAPI_PORT" ]] && conflict+=" EXTRA_TCP_PORTS"
    done
    if [[ -n "$conflict" ]]; then
        err "CROWDSEC_LAPI_PORT ($CROWDSEC_LAPI_PORT) deja utilise par :${conflict}."
    else
        ok "CROWDSEC_LAPI_PORT = $CROWDSEC_LAPI_PORT (pas de conflit)"
    fi
fi

echo ""

# -----------------------------------------------------------------------------
# 5. Booleens et options avancees
# -----------------------------------------------------------------------------
echo "--- Options ---"

require_bool XDP_ENABLED           && ok "XDP_ENABLED = $XDP_ENABLED"
require_bool XDP_AUTOBLOCK         && ok "XDP_AUTOBLOCK = $XDP_AUTOBLOCK"
require_bool SYNPROXY_ENABLED      && ok "SYNPROXY_ENABLED = $SYNPROXY_ENABLED"
require_bool F2B_USE_FLUXGATE_SETS && ok "F2B_USE_FLUXGATE_SETS = $F2B_USE_FLUXGATE_SETS"
require_bool HSTS_PRELOAD          && ok "HSTS_PRELOAD = $HSTS_PRELOAD"
require_bool FLUXGATE_EXPORTER_ENABLED && ok "FLUXGATE_EXPORTER_ENABLED = $FLUXGATE_EXPORTER_ENABLED"

require_enum SSH_MODE open strict           && ok "SSH_MODE = $SSH_MODE"
require_enum NFT_FORWARD_POLICY auto drop accept && ok "NFT_FORWARD_POLICY = $NFT_FORWARD_POLICY"
require_enum CDN_MODE off cloudflare        && ok "CDN_MODE = $CDN_MODE"
require_enum TC_QDISC auto cake tbf         && ok "TC_QDISC = $TC_QDISC"

if [[ "$XDP_AUTOBLOCK" == "true" ]] && [[ "$XDP_ENABLED" != "true" ]]; then
    warn "XDP_AUTOBLOCK=true sans XDP_ENABLED=true : l'auto-blocage ne sera pas lance."
fi
if [[ "$HSTS_PRELOAD" == "true" ]]; then
    warn "HSTS_PRELOAD=true : engagement long, tous les sous-domaines doivent servir du HTTPS."
fi
if [[ "$CDN_MODE" != "off" ]]; then
    warn "CDN_MODE=$CDN_MODE : HTTP/HTTPS ne seront accessibles QUE depuis le CDN."
fi

case "$SVC_CPU_QUOTA" in
    auto|none) ok "SVC_CPU_QUOTA = $SVC_CPU_QUOTA" ;;
    *)
        if [[ "$SVC_CPU_QUOTA" =~ ^[0-9]+%$ ]] && (( ${SVC_CPU_QUOTA%\%} > 0 )); then
            ok "SVC_CPU_QUOTA = $SVC_CPU_QUOTA (pourcentage d'un coeur)"
            ncpu=$(nproc 2>/dev/null || echo 1)
            if (( ${SVC_CPU_QUOTA%\%} < 100 && ncpu > 1 )); then
                warn "SVC_CPU_QUOTA = $SVC_CPU_QUOTA : moins d'un coeur sur une machine de $ncpu coeurs (auto = $(( ncpu * 80 ))%)."
            fi
        else
            err "SVC_CPU_QUOTA = '$SVC_CPU_QUOTA' : attendu auto, none ou un pourcentage (ex : 150%)."
        fi
        ;;
esac

if [[ ! "$TC_RATE" =~ ^[0-9]+(bit|kbit|mbit|gbit|tbit|bps|kbps|mbps|gbps)$ ]]; then
    err "TC_RATE = '$TC_RATE' : attendu un debit tc (ex : 500mbit, 1gbit)."
fi

# Methodes HTTP : injectees dans une regle du CRS, le format est strict
if [[ ! "$ALLOWED_METHODS" =~ ^[A-Z]+(\ [A-Z]+)*$ ]]; then
    err "ALLOWED_METHODS = '$ALLOWED_METHODS' : methodes en majuscules separees par un espace (ex : GET HEAD POST)."
elif [[ " $ALLOWED_METHODS " != *" GET "* ]]; then
    err "ALLOWED_METHODS ne contient pas GET : le site serait inaccessible."
else
    ok "ALLOWED_METHODS = $ALLOWED_METHODS"
    [[ " $ALLOWED_METHODS " == *" TRACE "* ]] && warn "ALLOWED_METHODS contient TRACE (Cross-Site Tracing)."
fi

if [[ -n "$REPUTATION_LISTS" ]]; then
    for l in ${REPUTATION_LISTS//,/ }; do
        case "$l" in
            spamhaus-drop|spamhaus-drop6|firehol-level1|https://*) ;;
            *) err "REPUTATION_LISTS : '$l' inconnue (spamhaus-drop, spamhaus-drop6, firehol-level1 ou URL https://)." ;;
        esac
    done
    ok "Listes de reputation : $REPUTATION_LISTS"
fi

if [[ -n "$NGINX_CERT_NAME" ]] && [[ ! "$NGINX_CERT_NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
    err "NGINX_CERT_NAME = '$NGINX_CERT_NAME' : nom de dossier attendu (ex : exemple.fr)."
fi

if [[ "$SYNPROXY_ENABLED" == "true" ]]; then
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
if [[ -n "$CRS_SHA256" ]] && [[ ! "$CRS_SHA256" =~ ^[a-f0-9]{64}$ ]]; then
    err "CRS_SHA256 n'est pas un sha256 valide (64 caracteres hexadecimaux minuscules)."
fi
if [[ -n "$CRS_GPG_FINGERPRINT" ]] && [[ ! "$CRS_GPG_FINGERPRINT" =~ ^[A-F0-9]{40}$ ]]; then
    err "CRS_GPG_FINGERPRINT n'est pas une empreinte valide (40 caracteres hexadecimaux majuscules)."
fi
[[ -n "$CRS_VERSION" ]] && ok "OWASP CRS cible : v${CRS_VERSION}"

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

if [[ "$LEGACY_CONFIG" == "true" ]]; then
    echo ""
    echo -e "  ${YELLOW}Rappel${NC} : des cles manquent dans config.env."
    echo "  Le deploiement fonctionnera avec les valeurs par defaut, mais"
    echo "  completer le fichier rend les reglages visibles et modifiables :"
    echo "      bash ${SCRIPT_DIR}/migrate-config.sh"
fi
echo ""
exit 0
