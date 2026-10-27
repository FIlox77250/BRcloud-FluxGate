#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Status Dashboard (CLI)
# =============================================================================
# Affiche un resume rapide de l'etat de la protection anti-DDoS.
# Execution : sudo bash scripts/status.sh
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

IFACE="${IFACE:-eth0}"
# --- Couleurs ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Parse arguments ---
WATCH_MODE=false
INTERVAL=2

while [[ $# -gt 0 ]]; do
    case "$1" in
        -w|--watch) WATCH_MODE=true; shift ;;
        -n|--interval) INTERVAL="${2:-2}"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [-w|--watch] [-n|--interval <seconds>]"
            exit 0
            ;;
        *) shift ;;
    esac
done

# set_size <set> : nombre d'elements d'un set de inet fluxgate. L'ancien
# "grep -c ... || echo 0" affichait "0 0" (grep -c imprime deja 0 en
# echouant) et ne comptait pas les bans sans timeout.
set_size() {
    nft list set inet fluxgate "$1" 2>/dev/null \
        | awk '/elements = \{/ {f = 1} f {print} f && /\}/ {exit}' \
        | tr -d '\n' \
        | sed -n 's/.*elements = {\(.*\)}.*/\1/p' \
        | awk -F, '{print NF} END {if (NR == 0) print 0}'
}

print_status() {
    echo ""
    echo -e "${BOLD}╔═══════════════════════════════════════════════╗"
    echo "║   BRCloud FluxGate - Status Dashboard         ║"
    echo -e "║   $(date '+%Y-%m-%d %H:%M:%S')                        ║"
    echo -e "╚═══════════════════════════════════════════════╝${NC}"
    echo ""

# --- Systeme ---
echo -e "${CYAN}=== Systeme ===${NC}"
echo "  Hostname : $(hostname)"
echo "  Uptime   : $(uptime -p 2>/dev/null || uptime)"
echo "  Load     : $(cat /proc/loadavg 2>/dev/null | awk '{print $1, $2, $3}')"
echo "  Memory   : $(free -h 2>/dev/null | grep Mem | awk '{printf "%s / %s (%s libre)", $3, $2, $7}')"
echo "  FD       : $(cat /proc/sys/fs/file-nr 2>/dev/null | awk '{printf "%s ouverts / %s max", $1, $3}')"
echo ""

# --- Reseau ---
echo -e "${CYAN}=== Reseau ($IFACE) ===${NC}"
if ip link show dev "$IFACE" &>/dev/null; then
    RX_BYTES=$(cat "/sys/class/net/$IFACE/statistics/rx_bytes" 2>/dev/null || echo 0)
    TX_BYTES=$(cat "/sys/class/net/$IFACE/statistics/tx_bytes" 2>/dev/null || echo 0)
    RX_DROPS=$(cat "/sys/class/net/$IFACE/statistics/rx_dropped" 2>/dev/null || echo 0)
    RX_ERRORS=$(cat "/sys/class/net/$IFACE/statistics/rx_errors" 2>/dev/null || echo 0)
    echo "  RX total  : $((RX_BYTES / 1048576)) MB"
    echo "  TX total  : $((TX_BYTES / 1048576)) MB"
    echo "  RX drops  : $RX_DROPS"
    echo "  RX errors : $RX_ERRORS"
fi
echo ""

# --- XDP ---
echo -e "${CYAN}=== XDP ===${NC}"
if ip link show dev "$IFACE" 2>/dev/null | grep -qi "xdp"; then
    echo -e "  Status : ${GREEN}ACTIF${NC}"
else
    echo -e "  Status : ${YELLOW}INACTIF${NC}"
fi
echo ""

# --- Conntrack ---
echo -e "${CYAN}=== Conntrack ===${NC}"
if [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]]; then
    COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
    MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
    PCT=$((COUNT * 100 / MAX))
    if [[ $PCT -lt 50 ]]; then
        COLOR=$GREEN
    elif [[ $PCT -lt 80 ]]; then
        COLOR=$YELLOW
    else
        COLOR=$RED
    fi
    echo -e "  Entries : ${COLOR}$COUNT / $MAX ($PCT%)${NC}"
else
    echo "  Conntrack non charge"
fi
echo ""

# --- nftables ---
echo -e "${CYAN}=== nftables (table inet fluxgate) ===${NC}"
if ! command -v nft &>/dev/null; then
    echo "  nft non disponible"
elif ! nft list table inet fluxgate &>/dev/null; then
    echo -e "  Table : ${RED}ABSENTE${NC} (pare-feu FluxGate non charge)"
else
    echo -e "  Table : ${GREEN}chargee${NC}"
    # Somme des compteurs des regles "drop" et "reject" de la chaine input
    DROP_COUNT=$(nft list chain inet fluxgate input 2>/dev/null \
        | awk '/counter packets/ && /drop|reject/ {for (i = 1; i < NF; i++) if ($i == "packets") s += $(i+1)} END {print s + 0}')
    echo "  Paquets rejetes (regles avec compteur) : $DROP_COUNT"
    echo "  Bans IPv4 : $(set_size blocklist4)   IPv6 : $(set_size blocklist6)   IPv6 /64 : $(set_size blocklist6net)"
    echo "  Reputation : $(set_size reputation4) reseau(x) v4, $(set_size reputation6) v6"
    if nft list chain inet fluxgate shield 2>/dev/null | grep -q 'Shield'; then
        echo -e "  Bouclier : ${YELLOW}ACTIF${NC}"
    else
        echo "  Bouclier : inactif"
    fi
fi
if command -v nft &>/dev/null && nft list table inet fluxgate_emergency &>/dev/null; then
    echo -e "  ${RED}MODE URGENCE ACTIF${NC} (nft-manage.sh restore pour en sortir)"
fi
echo ""

# --- Services ---
echo -e "${CYAN}=== Services ===${NC}"
for svc in nftables fluxgate-state nginx apache2 fail2ban crowdsec crowdsec-firewall-bouncer fluxgate-xdp; do
    if systemctl is-active "$svc" &>/dev/null; then
        echo -e "  $svc : ${GREEN}actif${NC}"
    elif systemctl is-enabled "$svc" &>/dev/null; then
        echo -e "  $svc : ${YELLOW}enabled mais arrete${NC}"
    else
        echo -e "  $svc : ${RED}inactif${NC}"
    fi
done
echo ""

# --- fail2ban ---
echo -e "${CYAN}=== fail2ban ===${NC}"
if command -v fail2ban-client &>/dev/null && systemctl is-active fail2ban &>/dev/null; then
    TOTAL_BANNED=$(fail2ban-client status 2>/dev/null | grep "Jail list" || echo "N/A")
    echo "  $TOTAL_BANNED"

    # Lister les jails avec le nombre de bans
    for jail in $(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*:\s*//;s/,/ /g'); do
        BANNED=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
        echo "  Jail $jail : $BANNED IP(s) bannies"
    done
else
    echo "  fail2ban inactif"
fi
echo ""

# --- TCP sockets ---
echo -e "${CYAN}=== Sockets TCP ===${NC}"
if command -v ss &>/dev/null; then
    echo "  ESTABLISHED : $(ss -t state established 2>/dev/null | tail -n +2 | wc -l)"
    echo "  SYN_RECV    : $(ss -t state syn-recv 2>/dev/null | tail -n +2 | wc -l)"
    echo "  TIME_WAIT   : $(ss -t state time-wait 2>/dev/null | tail -n +2 | wc -l)"
    echo "  CLOSE_WAIT  : $(ss -t state close-wait 2>/dev/null | tail -n +2 | wc -l)"
    echo "  LISTEN      : $(ss -t state listening 2>/dev/null | tail -n +2 | wc -l)"
fi
    echo -e "${BOLD}--- Fin du status ---${NC}"
    echo ""
}

# --- Execution ---
if [[ "$WATCH_MODE" == "true" ]]; then
    # Masquer le curseur de maniere elegante
    tput civis 2>/dev/null || true
    trap 'tput cnorm 2>/dev/null || true; exit 0' INT TERM EXIT
    
    while true; do
        clear
        print_status
        sleep "$INTERVAL"
    done
else
    print_status
fi
