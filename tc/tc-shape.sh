#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Traffic Shaping (tc / Token Bucket Filter)
# =============================================================================
# Controle du trafic sortant pour :
#   - Plafonner le debit sortant (eviter amplification sortante)
#   - Proteger la bande passante pour les services critiques
#   - Limiter l'impact sur les voisins (hebergement partage)
#
# Pre-requis : iproute2 (tc)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/../scripts/config.env"

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

IFACE="${IFACE:-eth0}"
TC_RATE="${TC_RATE:-1gbit}"
TC_BURST="${TC_BURST:-32kbit}"
TC_LATENCY="${TC_LATENCY:-50ms}"

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  apply       Appliquer le shaping sortant (TBF)
  remove      Supprimer le shaping
  status      Afficher les qdiscs/stats actuelles
  monitor     Surveiller les stats en continu (Ctrl+C pour arreter)

Options:
  -i <iface>   Interface (defaut: $IFACE)
  -r <rate>    Debit max (defaut: $TC_RATE)
  -b <burst>   Burst (defaut: $TC_BURST)
  -l <latency> Latence max dans la file (defaut: $TC_LATENCY)

Exemples:
  $0 apply
  $0 apply -r 500mbit -b 64kbit
  $0 status
  $0 remove
EOF
}

log_info()  { echo "[INFO]  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_error() { echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }

check_root() {
    [[ $EUID -eq 0 ]] || { log_error "Root requis."; exit 1; }
}

CMD="${1:-help}"
shift || true

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i) IFACE="$2"; shift 2 ;;
        -r) TC_RATE="$2"; shift 2 ;;
        -b) TC_BURST="$2"; shift 2 ;;
        -l) TC_LATENCY="$2"; shift 2 ;;
        *)  break ;;
    esac
done

case "$CMD" in
    apply)
        check_root
        log_info "Application du shaping TBF sur $IFACE (rate=$TC_RATE burst=$TC_BURST latency=$TC_LATENCY)..."

        # Supprimer l'ancien qdisc s'il existe
        tc qdisc del dev "$IFACE" root 2>/dev/null || true

        # Appliquer le Token Bucket Filter
        tc qdisc replace dev "$IFACE" root tbf \
            rate "$TC_RATE" \
            burst "$TC_BURST" \
            latency "$TC_LATENCY"

        log_info "Shaping applique."
        tc -s qdisc show dev "$IFACE"
        ;;

    remove)
        check_root
        log_info "Suppression du shaping sur $IFACE..."
        tc qdisc del dev "$IFACE" root 2>/dev/null || log_info "Aucun qdisc a supprimer."
        log_info "Shaping supprime."
        ;;

    status)
        log_info "Qdiscs sur $IFACE :"
        tc -s qdisc show dev "$IFACE"
        echo ""
        log_info "Classes sur $IFACE :"
        tc -s class show dev "$IFACE" 2>/dev/null || echo "(aucune)"
        ;;

    monitor)
        log_info "Monitoring tc sur $IFACE (Ctrl+C pour arreter)..."
        while true; do
            clear
            echo "=== TC Stats - $IFACE - $(date) ==="
            tc -s qdisc show dev "$IFACE"
            echo ""
            echo "=== Interface Stats ==="
            ip -s link show dev "$IFACE" 2>/dev/null | grep -A3 "RX\|TX"
            sleep 2
        done
        ;;

    help|--help|-h)
        usage
        ;;

    *)
        log_error "Commande inconnue: $CMD"
        usage
        exit 1
        ;;
esac
