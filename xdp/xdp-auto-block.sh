#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - XDP Auto-Block (detection par seuil connexions conntrack)
# =============================================================================
# Script de surveillance qui detecte les IP depassant un seuil de connexions
# conntrack et les bloque automatiquement via xdp-filter.
#
# A executer en daemon (systemd timer ou cron).
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/../scripts/config.env"

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

IFACE="${IFACE:-eth0}"
CONN_THRESHOLD="${XDP_CONN_THRESHOLD:-10000}"  # connexions conntrack par IP avant blocage
SAMPLE_INTERVAL="${XDP_SAMPLE_INTERVAL:-5}"    # secondes entre mesures
BLOCK_TIMEOUT="${XDP_BLOCK_TIMEOUT:-10m}"      # duree du ban XDP
LOG_FILE="/var/log/fluxgate/xdp-auto-block.log"

mkdir -p "$(dirname "$LOG_FILE")"

log_info()  { echo "[INFO]  $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }
log_warn()  { echo "[WARN]  $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE" >&2; }

# Verifier pre-requis
for cmd in xdp-filter conntrack; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Commande requise non trouvee: $cmd" >&2
        exit 1
    fi
done

log_info "Demarrage xdp-auto-block (seuil: ${CONN_THRESHOLD} conn/IP, intervalle: ${SAMPLE_INTERVAL}s)"

# Boucle de surveillance basee sur conntrack (compteurs)
while true; do
    # Capturer les IP sources avec le plus de connexions/paquets
    # conntrack -L donne les entrees de suivi d'etat
    HIGH_RATE_IPS=$(conntrack -L 2>/dev/null \
        | grep -oP 'src=\K[0-9a-fA-F.:]+' \
        | sort | uniq -c | sort -rn \
        | awk -v threshold="$CONN_THRESHOLD" '$1 > threshold {print $2}' \
        | head -20)

    if [[ -n "$HIGH_RATE_IPS" ]]; then
        while IFS= read -r ip; do
            log_warn "IP $ip depasse le seuil ($CONN_THRESHOLD conn). Blocage XDP..."
            xdp-filter ip "$ip" -m src 2>/dev/null \
                && log_info "IP $ip bloquee via XDP." \
                || log_warn "Echec blocage XDP pour $ip (deja bloquee?)."
        done <<< "$HIGH_RATE_IPS"
    fi

    sleep "$SAMPLE_INTERVAL"
done
