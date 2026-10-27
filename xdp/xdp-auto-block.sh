#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - XDP Auto-Block (detection par seuil connexions conntrack)
# =============================================================================
# Script de surveillance qui detecte les IP depassant un seuil d'entrees
# conntrack et les bloque via xdp-manage.sh (ban avec echeance).
#
# - Une entree conntrack contient deux "src=" (sens original et reponse) :
#   seul le premier, l'initiateur du flux, est compte. L'ancien comptage
#   prenait aussi le second, c'est-a-dire l'IP du serveur lui-meme, qui
#   finissait bannie de sa propre interface.
# - Les IP locales, ADMIN_NETS(6) et ALLOWLIST4/6 ne sont jamais bannies.
# - Les bans expirent apres XDP_BLOCK_TIMEOUT secondes (xdp-manage.sh expire).
#
# Lance par fluxgate-xdp-autoblock.service.
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

IFACE="${IFACE:-eth0}"
CONN_THRESHOLD="${XDP_BLOCK_THRESHOLD}"        # entrees conntrack par IP avant blocage
SAMPLE_INTERVAL="${XDP_SAMPLE_INTERVAL:-5}"    # secondes entre mesures
BLOCK_TIMEOUT="${XDP_BLOCK_TIMEOUT}"           # duree du ban XDP (secondes)
MANAGE="${SCRIPT_DIR}/xdp-manage.sh"
BANS_FILE="${FLUXGATE_STATE_DIR:-/var/lib/fluxgate}/xdp-bans"

log_info()  { echo "[INFO]  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_warn()  { echo "[WARN]  $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }

# Verifier pre-requis
for cmd in xdp-filter conntrack python3; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Commande requise non trouvee: $cmd" >&2
        exit 1
    fi
done

# Reseaux jamais bannis : adresses de la machine + ADMIN_NETS + ALLOWLIST.
# Les variables nftables ont la forme "{ a, b }" : on retire la ponctuation.
build_whitelist() {
    {
        echo "${ADMIN_NETS:-} ${ADMIN_NETS6:-} ${ALLOWLIST4:-} ${ALLOWLIST6:-}" | tr -d '{},' | tr -s ' ' '\n'
        ip -o addr show 2>/dev/null | awk '{split($4, a, "/"); print a[1]}'
        echo 127.0.0.0/8
        echo ::1
    } | grep -v '^$' | sort -u
}

# filter_candidates <fichier whitelist> : lit "IP" sur stdin, n'ecrit que
# celles hors whitelist (comparaison CIDR exacte, v4 et v6).
filter_candidates() {
    python3 -c '
import ipaddress, sys
nets = []
for line in open(sys.argv[1]):
    try:
        nets.append(ipaddress.ip_network(line.strip(), strict=False))
    except ValueError:
        pass
for line in sys.stdin:
    try:
        ip = ipaddress.ip_address(line.strip())
    except ValueError:
        continue
    if not any(ip.version == n.version and ip in n for n in nets):
        print(ip)
' "$1"
}

WHITELIST=$(mktemp /tmp/fluxgate-xdp-wl.XXXXXX)
trap 'rm -f "$WHITELIST"' EXIT
build_whitelist > "$WHITELIST"

"$MANAGE" -i "$IFACE" load

log_info "Demarrage xdp-auto-block (seuil: ${CONN_THRESHOLD} conn/IP, intervalle: ${SAMPLE_INTERVAL}s, ban: ${BLOCK_TIMEOUT}s)"
log_info "$(wc -l < "$WHITELIST") reseau(x) en liste blanche."

while true; do
    "$MANAGE" -i "$IFACE" expire || true

    # Premier src= de chaque entree = initiateur du flux
    HIGH_RATE_IPS=$(conntrack -L 2>/dev/null \
        | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^src=/) {print substr($i, 5); break}}' \
        | sort | uniq -c \
        | awk -v threshold="$CONN_THRESHOLD" '$1 > threshold {print $2}' \
        | filter_candidates "$WHITELIST" \
        | head -20)

    if [[ -n "$HIGH_RATE_IPS" ]]; then
        while IFS= read -r ip; do
            if [[ -f "$BANS_FILE" ]] && awk -v ip="$ip" '$1 == ip {f = 1} END {exit !f}' "$BANS_FILE"; then
                continue
            fi
            log_warn "IP $ip depasse le seuil ($CONN_THRESHOLD conn). Blocage XDP ${BLOCK_TIMEOUT}s..."
            "$MANAGE" -i "$IFACE" block-ip "$ip" "$BLOCK_TIMEOUT" \
                || log_warn "Echec blocage XDP pour $ip."
        done <<< "$HIGH_RATE_IPS"
    fi

    sleep "$SAMPLE_INTERVAL"
done
