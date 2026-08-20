#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Script de Validation Post-Deploiement
# =============================================================================
# Verifie que tous les composants de la stack anti-DDoS sont fonctionnels.
# Execution : sudo bash scripts/validate.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.env"

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

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
echo "--- Pare-feu nftables ---"

if command -v nft &>/dev/null; then
    # Le ruleset est releve UNE fois dans une variable, puis inspecte via des
    # here-strings.
    #
    # Ne jamais faire 'nft list ruleset | grep -q ...' ici : grep -q sort des
    # la premiere correspondance, nft se prend un SIGPIPE en continuant a
    # ecrire, et 'set -o pipefail' transforme ca en echec de la condition. Sur
    # un gros ruleset (CrowdSec, des milliers de lignes) le test echouait donc
    # *parce que* la regle avait ete trouvee tot. Effet de bord agreable :
    # une seule invocation au lieu d'une dizaine.
    NFT_RULESET=$(nft list ruleset 2>/dev/null || true)

    if grep -q "chain input" <<< "$NFT_RULESET"; then
        check_pass "nftables actif avec chain input"

        grep -q "blocklist4" <<< "$NFT_RULESET" && \
            check_pass "Set blocklist4 present" || check_warn "Set blocklist4 absent"

        grep -q "ct state invalid" <<< "$NFT_RULESET" && \
            check_pass "Regle drop invalid presente" || check_warn "Regle drop invalid absente"

        grep -q "limit rate" <<< "$NFT_RULESET" && \
            check_pass "Rate limiting present" || check_warn "Pas de rate limiting nftables"

        # Parite IPv6 : un pare-feu qui ne filtre qu'en IPv4 laisse une porte
        # ouverte des que la machine a une adresse IPv6 routable.
        grep -q "blocklist6" <<< "$NFT_RULESET" && \
            check_pass "Set blocklist6 present (parite IPv6)" || check_warn "Set blocklist6 absent"

        if ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
            check_info "IPv6 globale detectee sur cette machine"
            grep -q "ip6 saddr" <<< "$NFT_RULESET" && \
                check_pass "Regles IPv6 presentes dans le ruleset" || \
                check_fail "IPv6 active mais aucune regle ip6 saddr : trafic IPv6 non filtre"
        fi

        # SYNPROXY : les deux moities doivent etre presentes ou aucune.
        HAS_SYNPROXY_PRE=$(grep -c "notrack" <<< "$NFT_RULESET" || true)
        HAS_SYNPROXY_IN=$(grep -c "synproxy" <<< "$NFT_RULESET" || true)
        if [[ "$HAS_SYNPROXY_IN" -gt 0 ]] && [[ "$HAS_SYNPROXY_PRE" -gt 0 ]]; then
            check_pass "SYNPROXY actif (prerouting notrack + regle input)"
        elif [[ "$HAS_SYNPROXY_IN" -gt 0 ]] || [[ "$HAS_SYNPROXY_PRE" -gt 0 ]]; then
            check_fail "SYNPROXY incomplet : notrack=$HAS_SYNPROXY_PRE, synproxy=$HAS_SYNPROXY_IN (le trafic web sera casse)"
        else
            check_info "SYNPROXY non active"
        fi

        # Un ruleset sans regle SSH d'aucune sorte = lockout au prochain reboot
        if grep -q "dport ${SSH_PORT:-22}" <<< "$NFT_RULESET"; then
            check_pass "Regle SSH presente pour le port ${SSH_PORT:-22}"
        else
            check_fail "Aucune regle nftables pour le port SSH ${SSH_PORT:-22} !"
        fi
    else
        check_fail "nftables sans regles input"
    fi

    # Les regles doivent survivre au reboot
    if systemctl is-enabled nftables &>/dev/null; then
        check_pass "Service nftables active au demarrage"
    else
        check_fail "nftables non active au boot : les regles seront perdues au reboot"
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
        # Sans '| head -1' : voir la note SIGPIPE de la section nftables.
        crs_matches=$(grep -rhoE 'OWASP_CRS/[0-9]+\.[0-9]+\.[0-9]+' /etc/modsecurity/crs/rules/ 2>/dev/null || true)
        installed_ver=$(sed -n '1s|.*/||p' <<< "$crs_matches")
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
