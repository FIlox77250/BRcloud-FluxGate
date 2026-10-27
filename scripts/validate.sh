#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Script de Validation Post-Deploiement
# =============================================================================
# Verifie que tous les composants de la stack anti-DDoS sont fonctionnels.
# Execution : sudo bash scripts/validate.sh [--no-active]
#   --no-active : sans les tests actifs (requetes HTTP reelles sur NGINX :
#                 injection SQL -> 403 attendu, rafale -> 429 attendu)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${FLUXGATE_CONFIG:-${SCRIPT_DIR}/config.env}"

# shellcheck source=lib/defaults.sh
source "${SCRIPT_DIR}/lib/defaults.sh"
if [[ -f "$CONFIG_FILE" ]]; then
    fluxgate_load_config "$CONFIG_FILE" || exit 1
else
    fluxgate_apply_defaults
fi

ACTIVE_TESTS=true
case "${1:-}" in
    --no-active) ACTIVE_TESTS=false ;;
    -h|--help) echo "Usage: $0 [--no-active]"; exit 0 ;;
esac

IFACE="${IFACE:-eth0}"
PASS=0
FAIL=0
WARN=0

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

check_pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; PASS=$((PASS+1)); }
check_fail() { echo -e "  ${RED}[FAIL]${NC} $*"; FAIL=$((FAIL+1)); }
check_warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; WARN=$((WARN+1)); }
check_info() { echo -e "  ${CYAN}[INFO]${NC} $*"; }

echo ""
echo "============================================="
echo "  BRCloud FluxGate - Validation"
echo "============================================="
echo ""

# =============================================================================
# 1. Sysctl
# =============================================================================
echo "--- Kernel Tuning (sysctl) ---"

val=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "N/A")
[[ "$val" == "1" ]] && check_pass "SYN cookies actifs" || check_fail "SYN cookies inactifs ($val)"

val=$(sysctl -n net.core.somaxconn 2>/dev/null || echo "N/A")
[[ "$val" -ge 1024 ]] 2>/dev/null && check_pass "somaxconn = $val" || check_warn "somaxconn faible ($val)"

val=$(sysctl -n net.ipv4.tcp_max_syn_backlog 2>/dev/null || echo "N/A")
[[ "$val" -ge 4096 ]] 2>/dev/null && check_pass "tcp_max_syn_backlog = $val" || check_warn "tcp_max_syn_backlog faible ($val)"

val=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo "N/A")
[[ "$val" == "1" ]] && check_pass "Reverse path filtering actif" || check_warn "rp_filter = $val"

val=$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo "N/A")
[[ "$val" == "1" ]] && check_pass "ICMP broadcast ignore actif" || check_warn "icmp_echo_ignore_broadcasts = $val"

# --- Controle de congestion ---
val=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
case "$val" in
    bbr)   check_pass "Controle de congestion : bbr" ;;
    cubic) check_warn "Controle de congestion : cubic (bbr indisponible ou non applique)" ;;
    *)     check_warn "Controle de congestion : $val" ;;
esac

val=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
[[ "$val" == "fq" ]] && check_pass "Qdisc par defaut : fq" || check_warn "Qdisc par defaut : $val (fq recommande avec bbr)"

# --- Prerequis SYNPROXY ---
val=$(sysctl -n net.netfilter.nf_conntrack_tcp_loose 2>/dev/null || echo "N/A")
if [[ "$val" == "0" ]]; then
    check_pass "nf_conntrack_tcp_loose = 0 (prerequis SYNPROXY satisfait)"
elif [[ "$val" == "N/A" ]]; then
    check_warn "nf_conntrack non charge : impossible de verifier tcp_loose"
else
    check_warn "nf_conntrack_tcp_loose = $val (doit valoir 0 si SYNPROXY est utilise)"
fi

echo ""

# =============================================================================
# 2. nftables
# =============================================================================
echo "--- Pare-feu nftables (table inet fluxgate) ---"

if command -v nft &>/dev/null; then
    if nft list table inet fluxgate &>/dev/null; then
        check_pass "Table inet fluxgate chargee"
        FG_RULES=$(nft list table inet fluxgate 2>/dev/null)

        for s in blocklist4 blocklist6 blocklist6net allowlist4 allowlist6; do
            grep -q "set ${s} " <<<"$FG_RULES" && check_pass "Set ${s} present" || check_warn "Set ${s} absent"
        done
        grep -q "policy drop" <<<"$FG_RULES" && check_pass "Politique input drop" || check_fail "Chaine input sans politique drop"
        grep -q "ct state invalid" <<<"$FG_RULES" && check_pass "Regle drop invalid presente" || check_warn "Regle drop invalid absente"
        grep -q "limit rate" <<<"$FG_RULES" && check_pass "Rate limiting par IP present" || check_warn "Pas de rate limiting nftables"
        grep -q "ct count" <<<"$FG_RULES" && check_pass "Limite de connexions simultanees (ct count)" || check_warn "Pas de limite ct count"

        if ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
            check_info "IPv6 globale detectee sur cette machine"
            grep -q "ip6 saddr" <<<"$FG_RULES" && \
                check_pass "Regles IPv6 presentes" || \
                check_fail "IPv6 active mais aucune regle ip6 saddr : trafic IPv6 non filtre"
        fi

        # SYNPROXY : les deux moities doivent etre presentes ou aucune.
        HAS_SYNPROXY_PRE=$(grep -c "notrack" <<<"$FG_RULES" || true)
        HAS_SYNPROXY_IN=$(grep -c "synproxy" <<<"$FG_RULES" || true)
        if [[ "$HAS_SYNPROXY_IN" -gt 0 ]] && [[ "$HAS_SYNPROXY_PRE" -gt 0 ]]; then
            check_pass "SYNPROXY actif (prerouting notrack + regle input)"
        elif [[ "$HAS_SYNPROXY_IN" -gt 0 ]] || [[ "$HAS_SYNPROXY_PRE" -gt 0 ]]; then
            check_fail "SYNPROXY incomplet : notrack=$HAS_SYNPROXY_PRE, synproxy=$HAS_SYNPROXY_IN (le trafic web sera casse)"
        else
            check_info "SYNPROXY non active"
        fi

        # Une regle qui ACCEPTE le port SSH, pas seulement qui le mentionne
        if nft -n list chain inet fluxgate input 2>/dev/null | grep -qE "tcp dport ${SSH_PORT} .*accept"; then
            check_pass "Regle d'acceptation SSH pour le port ${SSH_PORT}"
        else
            check_fail "Aucune regle n'accepte le port SSH ${SSH_PORT} !"
        fi

        # Les sets doivent etre modifiables : c'est ce qu'utilisent fail2ban,
        # CrowdSec et nft-manage.sh. Adresse de documentation, ban de 5 s.
        if nft add element inet fluxgate blocklist4 "{ 192.0.2.254 timeout 5s }" 2>/dev/null \
           && nft get element inet fluxgate blocklist4 "{ 192.0.2.254 }" &>/dev/null; then
            nft delete element inet fluxgate blocklist4 "{ 192.0.2.254 }" 2>/dev/null || true
            check_pass "Blocklist modifiable (ajout/retrait d'un ban de test)"
        else
            check_fail "Impossible d'ajouter un ban dans blocklist4"
        fi

        if nft list table inet fluxgate_emergency &>/dev/null; then
            check_warn "Mode urgence ACTIF (nft-manage.sh restore)"
        fi
        if [[ -n "$(nft list chain inet fluxgate shield 2>/dev/null | grep -E 'drop|reject')" ]]; then
            check_warn "Bouclier ACTIF (nft-manage.sh shield off)"
        fi
    else
        check_fail "Table inet fluxgate absente : pare-feu FluxGate non charge"
    fi

    if [[ -f /etc/nftables.conf ]]; then
        if nft -c -f /etc/nftables.conf 2>/dev/null; then
            check_pass "/etc/nftables.conf valide (rechargeable au boot)"
        else
            check_fail "/etc/nftables.conf invalide : le prochain boot echouera"
        fi
    fi

    # Les regles doivent survivre au reboot
    if systemctl is-enabled nftables &>/dev/null; then
        check_pass "Service nftables active au demarrage"
    else
        check_fail "nftables non active au boot : les regles seront perdues au reboot"
    fi
    if systemctl is-enabled fluxgate-state.service &>/dev/null; then
        check_pass "Bans persistants (fluxgate-state.service)"
    else
        check_warn "fluxgate-state.service inactif : les bans sont perdus au reboot"
    fi
else
    check_warn "nft non disponible"
fi

echo ""

# =============================================================================
# 3. Conntrack
# =============================================================================
echo "--- Conntrack ---"

if [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    count=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
    max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
    pct=$((count * 100 / max))
    check_info "Conntrack: $count / $max ($pct%)"
    [[ $pct -lt 80 ]] && check_pass "Conntrack sous 80%" || check_warn "Conntrack a $pct% !"
else
    check_info "Conntrack non charge (peut etre normal si stateless)"
fi

echo ""

# =============================================================================
# 4. Services
# =============================================================================
echo "--- Services ---"

for svc in nftables nginx apache2 httpd fail2ban crowdsec; do
    if systemctl is-active "$svc" &>/dev/null; then
        check_pass "$svc actif"
    elif systemctl is-enabled "$svc" &>/dev/null; then
        check_warn "$svc active mais pas en cours d'execution"
    else
        check_info "$svc non installe ou desactive"
    fi
done

echo ""

# =============================================================================
# 5. NGINX
# =============================================================================
echo "--- NGINX ---"

if command -v nginx &>/dev/null; then
    nginx -t 2>/dev/null && check_pass "Config NGINX valide" || check_fail "Config NGINX invalide"

    if grep -rq "limit_req_zone" /etc/nginx/ 2>/dev/null; then
        check_pass "Rate limiting NGINX configure"
    else
        check_warn "Pas de limit_req_zone dans la config NGINX"
    fi

    if grep -rq "limit_conn_zone" /etc/nginx/ 2>/dev/null; then
        check_pass "Conn limiting NGINX configure"
    else
        check_warn "Pas de limit_conn_zone dans la config NGINX"
    fi
fi

echo ""

# =============================================================================
# 6. fail2ban
# =============================================================================
echo "--- fail2ban ---"

if command -v fail2ban-client &>/dev/null; then
    jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g' || echo "")
    if [[ -n "$jails" ]]; then
        check_pass "fail2ban jails actives :$jails"
    else
        check_warn "Aucune jail fail2ban active"
    fi

    # Action FluxGate : les bans doivent atterrir dans blocklist4/6
    if grep -rq "banaction = fluxgate-nft" /etc/fail2ban/jail.d/ 2>/dev/null; then
        if [[ -f /etc/fail2ban/action.d/fluxgate-nft.conf ]]; then
            check_pass "fail2ban banni dans les sets FluxGate (blocklist4/6)"
        else
            check_fail "Jails configurees sur fluxgate-nft mais action.d/fluxgate-nft.conf absent : les bans echoueront"
        fi
    else
        check_info "fail2ban utilise l'action nftables standard (table f2b dediee)"
    fi
fi

echo ""

# =============================================================================
# 6b. WAF / OWASP CRS
# =============================================================================
echo "--- WAF ModSecurity / OWASP CRS ---"

if [[ -d /etc/modsecurity/crs/rules ]]; then
    nb_rules=$(find /etc/modsecurity/crs/rules -name "*.conf" 2>/dev/null | wc -l)
    if [[ "$nb_rules" -gt 0 ]]; then
        check_pass "OWASP CRS present ($nb_rules fichiers de regles)"
    else
        check_fail "Repertoire CRS present mais vide : WAF sans regles"
    fi

    # Version reellement installee vs version attendue
    if [[ -f /etc/modsecurity/crs/crs-setup.conf.example ]] || [[ -f /etc/modsecurity/crs/crs-setup.conf ]]; then
        installed_ver=$(grep -rhoP 'version[/ ]OWASP_CRS/\K[0-9]+\.[0-9]+\.[0-9]+' /etc/modsecurity/crs/rules/*.conf 2>/dev/null | head -1)
        if [[ -n "$installed_ver" ]]; then
            if [[ -n "${CRS_VERSION:-}" ]] && [[ "$installed_ver" != "${CRS_VERSION}" ]]; then
                check_warn "CRS installe en v${installed_ver}, config.env attend v${CRS_VERSION}"
            else
                check_pass "OWASP CRS v${installed_ver}"
            fi
        fi
    fi

    if [[ ! -f /etc/modsecurity/unicode.mapping ]]; then
        if grep -q "^[[:space:]]*SecUnicodeMapFile" /etc/modsecurity/modsecurity.conf 2>/dev/null; then
            check_fail "SecUnicodeMapFile actif mais unicode.mapping absent : NGINX refusera de demarrer"
        else
            check_info "unicode.mapping absent, SecUnicodeMapFile desactive (coherent)"
        fi
    else
        check_pass "unicode.mapping present"
    fi
else
    check_info "OWASP CRS non installe"
fi

echo ""

# =============================================================================
# 7. XDP
# =============================================================================
echo "--- XDP ---"

if ip link show dev "$IFACE" 2>/dev/null | grep -qi "xdp"; then
    check_pass "XDP attache sur $IFACE"
else
    check_info "XDP non attache sur $IFACE"
fi

echo ""

# =============================================================================
# 7b. Tests actifs (requetes reelles sur NGINX local)
# =============================================================================
# Verifie le comportement, pas seulement la presence des regles : une
# injection SQL doit etre bloquee (403), une rafale doit etre limitee (429).
# Les requetes partent de 127.0.0.1 : elles testent NGINX et le WAF, pas
# nftables (la boucle locale y est toujours acceptee).
echo "--- Tests actifs (HTTP local) ---"

http_code() { curl -s -o /dev/null -m 5 -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

if [[ "$ACTIVE_TESTS" != "true" ]]; then
    check_info "Tests actifs ignores (--no-active)"
elif ! command -v curl &>/dev/null; then
    check_warn "curl absent : tests actifs impossibles"
elif ! command -v nginx &>/dev/null || ! { systemctl is-active nginx &>/dev/null || pgrep -x nginx &>/dev/null; }; then
    check_info "NGINX inactif : tests actifs ignores"
else
    BASE="http://127.0.0.1:${HTTP_PORT}"

    code=$(http_code "${BASE}/health")
    case "$code" in
        200) check_pass "NGINX repond sur ${BASE} (/health = 200)" ;;
        000) check_fail "Aucune reponse de ${BASE}" ;;
        *)   check_warn "/health renvoie ${code}" ;;
    esac

    if grep -qE '^[[:space:]]*modsecurity[[:space:]]+on;' /etc/nginx/nginx.conf 2>/dev/null; then
        code=$(http_code "${BASE}/?id=1%27%20OR%20%271%27%3D%271")
        [[ "$code" == "403" ]] && check_pass "WAF : injection SQL bloquee (403)" \
                               || check_fail "WAF : injection SQL non bloquee (code ${code})"
        code=$(http_code "${BASE}/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        [[ "$code" == "403" ]] && check_pass "WAF : XSS bloque (403)" \
                               || check_fail "WAF : XSS non bloque (code ${code})"
    else
        check_info "ModSecurity inactif : tests WAF ignores"
    fi

    code=$(http_code -X TRACE "${BASE}/")
    [[ "$code" == "403" || "$code" == "405" ]] && check_pass "Methode TRACE refusee (${code})" \
                                               || check_warn "Methode TRACE acceptee (code ${code})"

    # Rafale : nettement plus que burst + debit, envoyee en parallele.
    n=$(( NGINX_BURST + NGINX_REQ_PER_SEC * 2 + 40 ))
    codes=$(seq "$n" | xargs -P 32 -I{} curl -s -o /dev/null -m 5 -w '%{http_code}\n' "${BASE}/?fluxgate-burst={}" 2>/dev/null | sort | uniq -c || true)
    if grep -qE '[[:space:]]429$' <<<"$codes"; then
        check_pass "Rate limiting : rafale de ${n} requetes limitee ($(awk '$2 == 429 {print $1}' <<<"$codes") x 429)"
    else
        check_fail "Rate limiting : aucun 429 sur une rafale de ${n} requetes ($(tr -s ' \n' ' ' <<<"$codes"))"
    fi
fi

echo ""

# =============================================================================
# 8. Ports en ecoute
# =============================================================================
echo "--- Ports en ecoute ---"

ss -lntu 2>/dev/null | grep -E "LISTEN|UNCONN" | while read -r line; do
    check_info "$line"
done

echo ""

# =============================================================================
# 9. Ressources systeme
# =============================================================================
echo "--- Ressources systeme ---"

check_info "Memoire : $(free -h 2>/dev/null | grep Mem | awk '{print $3 "/" $2 " utilise"}')"
check_info "CPU cores : $(nproc 2>/dev/null || echo 'N/A')"
check_info "FD ouverts : $(cat /proc/sys/fs/file-nr 2>/dev/null | awk '{print $1 " / " $3}')"
check_info "Load average : $(cat /proc/loadavg 2>/dev/null | awk '{print $1, $2, $3}')"

echo ""

# =============================================================================
# Resume
# =============================================================================
echo "============================================="
echo -e "  Resultats : ${GREEN}$PASS PASS${NC}  ${RED}$FAIL FAIL${NC}  ${YELLOW}$WARN WARN${NC}"
echo "============================================="
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}Des verifications ont echoue. Corriger avant mise en production.${NC}"
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo -e "${YELLOW}Avertissements detectes. Verifier la pertinence.${NC}"
    exit 0
else
    echo -e "${GREEN}Toutes les verifications sont passees.${NC}"
    exit 0
fi
