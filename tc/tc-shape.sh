#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Traffic Shaping sortant (tc)
# =============================================================================
# Controle du trafic sortant pour :
#   - Plafonner le debit sortant (eviter amplification sortante)
#   - Proteger la bande passante pour les services critiques
#   - Limiter l'impact sur les voisins (hebergement partage)
#
# Qdisc (TC_QDISC dans config.env) :
#   cake  (defaut si disponible) : plafond global + equite entre flux, sans
#         reglage de burst.
#   tbf   : plafond global seul. Le burst est calcule depuis le debit : un
#         TBF doit pouvoir emettre au moins debit/HZ octets par tick
#         d'horloge. L'ancien burst fixe de 32kbit (4 Ko) limitait un lien
#         1gbit a quelques dizaines de Mbit/s.
#
# Note : "fq maxrate" plafonne chaque flux, pas le total : il ne remplace
# pas un plafond global et n'est donc pas propose ici.
#
# Pre-requis : iproute2 (tc), module sch_cake pour cake
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${FLUXGATE_CONFIG:-${SCRIPT_DIR}/../scripts/config.env}"

# shellcheck source=../scripts/lib/defaults.sh
source "${SCRIPT_DIR}/../scripts/lib/defaults.sh"
if [[ -f "$CONFIG_FILE" ]]; then
    fluxgate_load_config "$CONFIG_FILE" || exit 1
else
    fluxgate_apply_defaults
fi

IFACE="${IFACE:-$(ip route show default 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')}"
IFACE="${IFACE:-eth0}"
TC_QDISC="${TC_QDISC:-auto}"
TC_BURST="${TC_BURST:-auto}"

# rate_to_bps <debit tc> : 1gbit, 500mbit, 100kbit, 1000000 -> bits/s
rate_to_bps() {
    local r="${1,,}" n unit
    n="${r%%[a-z]*}"
    unit="${r#"$n"}"
    case "$unit" in
        ""|bit)   echo "$n" ;;
        kbit)     echo $(( n * 1000 )) ;;
        mbit)     echo $(( n * 1000000 )) ;;
        gbit)     echo $(( n * 1000000000 )) ;;
        tbit)     echo $(( n * 1000000000000 )) ;;
        *)        return 1 ;;
    esac
}

# auto_burst <debit> : max(debit/250 octets, 10 x 1514 octets). 250 est la
# frequence d'horloge (HZ) la plus courante ; une valeur plus haute ne fait
# que garder de la marge.
auto_burst() {
    local bps bytes
    bps=$(rate_to_bps "$1") || { echo 64kb; return 0; }
    bytes=$(( bps / 8 / 250 ))
    (( bytes < 15140 )) && bytes=15140
    echo "${bytes}b"
}

resolve_qdisc() {
    case "$TC_QDISC" in
        cake|tbf) echo "$TC_QDISC" ;;
        *)
            if modprobe -n sch_cake &>/dev/null || [[ -d /sys/module/sch_cake ]]; then
                echo cake
            else
                echo tbf
            fi
            ;;
    esac
}

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  apply       Appliquer le shaping sortant (cake, ou TBF)
  remove      Supprimer le shaping
  status      Afficher les qdiscs/stats actuelles
  monitor     Surveiller les stats en continu (Ctrl+C pour arreter)

Options:
  -i <iface>   Interface (defaut: $IFACE)
  -r <rate>    Debit max (defaut: $TC_RATE)
  -b <burst>   Burst TBF (defaut: $TC_BURST, calcule depuis le debit)
  -l <latency> Latence max dans la file TBF (defaut: $TC_LATENCY)
  -q <qdisc>   cake ou tbf (defaut: $TC_QDISC, cake si disponible)

Exemples:
  $0 apply
  $0 apply -r 500mbit -q tbf
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
        -q) TC_QDISC="$2"; shift 2 ;;
        *)  break ;;
    esac
done

case "$CMD" in
    apply)
        check_root
        QDISC=$(resolve_qdisc)
        if [[ "$QDISC" == "cake" ]]; then
            log_info "Application de cake sur $IFACE (bandwidth=$TC_RATE)..."
            tc qdisc replace dev "$IFACE" root cake bandwidth "$TC_RATE"
        else
            [[ "$TC_BURST" == "auto" ]] && TC_BURST=$(auto_burst "$TC_RATE")
            log_info "Application de TBF sur $IFACE (rate=$TC_RATE burst=$TC_BURST latency=$TC_LATENCY)..."
            tc qdisc replace dev "$IFACE" root tbf \
                rate "$TC_RATE" \
                burst "$TC_BURST" \
                latency "$TC_LATENCY"
        fi

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
