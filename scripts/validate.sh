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

echo ""

# =============================================================================
# 2. nftables
# =============================================================================
echo "--- Pare-feu nftables ---"

if command -v nft &>/dev/null; then
    if nft list ruleset 2>/dev/null | grep -q "chain input"; then
        check_pass "nftables actif avec chain input"

        nft list ruleset 2>/dev/null | grep -q "blocklist4" && \
            check_pass "Set blocklist4 present" || check_warn "Set blocklist4 absent"

        nft list ruleset 2>/dev/null | grep -q "ct state invalid" && \
            check_pass "Regle drop invalid presente" || check_warn "Regle drop invalid absente"

        nft list ruleset 2>/dev/null | grep -q "limit rate" && \
            check_pass "Rate limiting present" || check_warn "Pas de rate limiting nftables"
    else
        check_fail "nftables sans regles input"
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
