#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - XDP/eBPF Filter Management
# =============================================================================
# Gestion de xdp-filter pour drop tres tot (avant pile noyau).
# Capacite : dizaines de millions de pps par coeur CPU.
#
# xdp-filter n'a pas de notion de duree : les bans avec timeout sont notes
# dans ${STATE_DIR}/xdp-bans (IP, echeance epoch) et retires par 'expire'
# (appele en boucle par xdp-auto-block.sh). Le meme fichier sert a
# reconstituer les bans apres un reboot ('restore', fluxgate-xdp.service).
#
# Pre-requis : xdp-tools (xdp-filter) installe, driver NIC compatible XDP.
# Fallback : mode "skb" (generic) si le driver ne supporte pas XDP natif.
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
STATE_DIR="${FLUXGATE_STATE_DIR:-/var/lib/fluxgate}"
BANS_FILE="${STATE_DIR}/xdp-bans"

usage() {
    cat <<EOF
Usage: $0 [-i <iface>] <command> [options]

Commands:
  load                      Attacher xdp-filter sur l'interface
  unload                    Detacher xdp-filter (rollback)
  restore                   Attacher puis rejouer les bans non expires (boot)
  block-ip <IP> [duree]     Bloquer une IP source (defaut: ${XDP_BLOCK_TIMEOUT}s ;
                            duree en s, ou suffixe m/h/d ; 0 = permanent)
  unblock-ip <IP>           Debloquer une IP source
  expire                    Retirer les bans arrives a echeance
  block-port <PORT> [proto] Bloquer un port destination (tcp|udp, defaut: tcp)
  unblock-port <PORT> [proto]
                            Debloquer un port
  list                      Lister les regles actives et les echeances
  status                    Statut XDP sur l'interface
  stats                     Statistiques de drop

Options:
  -i <iface>   Interface (defaut: $IFACE)

Exemples:
  $0 load
  $0 block-ip 203.0.113.50 30m
  $0 block-port 53 udp
  $0 list
  $0 unload
EOF
}

log_info()  { echo "[INFO]  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_warn()  { echo "[WARN]  $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }
log_error() { echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Ce script doit etre execute en root (sudo)."
        exit 1
    fi
}

check_xdp_filter() {
    if ! command -v xdp-filter &>/dev/null; then
        log_error "xdp-filter non trouve. Installer xdp-tools."
        log_info "  Debian/Ubuntu : apt install xdp-tools"
        log_info "  RHEL/Fedora   : dnf install xdp-tools"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Les versions precedentes remplacaient /usr/sbin/xdp-loader par un script
# (l'original renomme en .real). Modifier un binaire du systeme casse la
# mise a jour du paquet et s'execute en root a chaque appel. On remet
# l'original en place s'il est retrouve.
# -----------------------------------------------------------------------------
remove_legacy_loader_wrapper() {
    local p
    for p in /usr/sbin/xdp-loader /usr/bin/xdp-loader /sbin/xdp-loader /bin/xdp-loader; do
        if [[ -f "${p}.real" ]] && grep -q 'Wrapper de compatibilite cree par FluxGate' "$p" 2>/dev/null; then
            mv -f "${p}.real" "$p"
            log_info "Wrapper FluxGate retire : $p restaure."
        fi
    done
}

# duration_to_seconds <duree> : 600, 30m, 2h, 1d -> secondes
duration_to_seconds() {
    local d="$1"
    case "$d" in
        *[!0-9smhd]*|"") return 1 ;;
        *d) echo $(( ${d%d} * 86400 )) ;;
        *h) echo $(( ${d%h} * 3600 )) ;;
        *m) echo $(( ${d%m} * 60 )) ;;
        *s) echo "${d%s}" ;;
        *)  echo "$d" ;;
    esac
}

# record_ban <ip> <echeance epoch|0>
record_ban() {
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    touch "$BANS_FILE"
    chmod 600 "$BANS_FILE"
    forget_ban "$1"
    echo "$1 $2" >> "$BANS_FILE"
}

forget_ban() {
    [[ -f "$BANS_FILE" ]] || return 0
    local tmp
    tmp=$(mktemp "${STATE_DIR}/.xdp-bans.XXXXXX")
    awk -v ip="$1" '$1 != ip' "$BANS_FILE" > "$tmp"
    mv -f "$tmp" "$BANS_FILE"
    chmod 600 "$BANS_FILE"
}

xdp_load() {
    remove_legacy_loader_wrapper
    if ip link show dev "$IFACE" 2>/dev/null | grep -q 'prog/xdp'; then
        log_info "Un programme XDP est deja attache a $IFACE."
        return 0
    fi
    log_info "Attachement xdp-filter sur $IFACE..."
    if xdp-filter load "$IFACE" 2>/dev/null; then
        log_info "xdp-filter attache (mode natif)."
    else
        log_warn "Mode natif refuse par le driver : tentative en mode skb (generic)..."
        xdp-filter load -m skb "$IFACE"
        log_info "xdp-filter attache en mode skb."
    fi
}

xdp_expire() {
    [[ -s "$BANS_FILE" ]] || return 0
    local now ip until n=0
    now=$(date +%s)
    while read -r ip until; do
        [[ -n "$ip" ]] || continue
        if [[ "$until" != "0" ]] && (( until <= now )); then
            xdp-filter ip -r "$ip" -m src 2>/dev/null || true
            forget_ban "$ip"
            n=$((n + 1))
        fi
    done < <(cat "$BANS_FILE")
    (( n == 0 )) || log_info "${n} ban(s) XDP arrive(s) a echeance retire(s)."
}

# --- Parse interface option ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i) IFACE="$2"; shift 2 ;;
        *)  break ;;
    esac
done

CMD="${1:-help}"
shift || true

case "$CMD" in
    help|--help|-h)
        usage
        exit 0
        ;;
esac

check_xdp_filter

case "$CMD" in
    load)
        check_root
        xdp_load
        ;;

    unload)
        check_root
        log_info "Detachement xdp-filter de $IFACE..."
        xdp-filter unload "$IFACE" || log_warn "Rien a detacher ou erreur."
        remove_legacy_loader_wrapper
        log_info "XDP detache."
        ;;

    restore)
        check_root
        xdp_load
        xdp_expire
        if [[ -s "$BANS_FILE" ]]; then
            n=0
            while read -r ip until; do
                [[ -n "$ip" ]] || continue
                xdp-filter ip "$ip" -m src 2>/dev/null && n=$((n + 1)) || true
            done < "$BANS_FILE"
            log_info "${n} ban(s) XDP restaure(s)."
        fi
        ;;

    block-ip)
        check_root
        IP="${1:?IP requise}"
        DURATION="${2:-${XDP_BLOCK_TIMEOUT}}"
        if ! SECS=$(duration_to_seconds "$DURATION"); then
            log_error "Duree invalide : $DURATION (exemples : 600, 30m, 2h, 1d)"
            exit 1
        fi
        log_info "Blocage IP source $IP..."
        xdp-filter ip "$IP" -m src
        if (( SECS > 0 )); then
            record_ban "$IP" $(( $(date +%s) + SECS ))
            log_info "IP $IP bloquee pour ${SECS}s."
        else
            record_ban "$IP" 0
            log_info "IP $IP bloquee sans echeance."
        fi
        ;;

    unblock-ip)
        check_root
        IP="${1:?IP requise}"
        log_info "Deblocage IP source $IP..."
        xdp-filter ip -r "$IP" -m src
        forget_ban "$IP"
        log_info "IP $IP debloquee."
        ;;

    expire)
        check_root
        xdp_expire
        ;;

    block-port)
        check_root
        PORT="${1:?Port requis}"
        PROTO="${2:-tcp}"
        log_info "Blocage port $PROTO/$PORT..."
        xdp-filter port "$PORT" -p "$PROTO" -m dst
        log_info "Port $PROTO/$PORT bloque."
        ;;

    unblock-port)
        check_root
        PORT="${1:?Port requis}"
        PROTO="${2:-tcp}"
        log_info "Deblocage port $PROTO/$PORT..."
        xdp-filter port -r "$PORT" -p "$PROTO" -m dst
        log_info "Port $PROTO/$PORT debloque."
        ;;

    list)
        log_info "Regles xdp-filter actives :"
        xdp-filter status 2>/dev/null || log_warn "Aucune regle ou xdp-filter non charge."
        if [[ -s "$BANS_FILE" ]]; then
            echo ""
            log_info "Echeances (${BANS_FILE}) :"
            while read -r ip until; do
                if [[ "$until" == "0" ]]; then
                    printf '  %-40s permanent\n' "$ip"
                else
                    printf '  %-40s %s\n' "$ip" "$(date -d "@$until" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$until")"
                fi
            done < "$BANS_FILE"
        fi
        ;;

    status)
        log_info "Statut XDP sur $IFACE :"
        ip link show dev "$IFACE" | grep -i xdp || log_info "Pas de programme XDP attache."
        ;;

    stats)
        log_info "Statistiques XDP sur $IFACE :"
        if command -v bpftool &>/dev/null; then
            bpftool prog show 2>/dev/null | head -30
        else
            log_warn "bpftool non disponible pour les stats detaillees."
        fi
        # Compteurs interface
        ip -s link show dev "$IFACE" | grep -A2 "RX\|TX"
        ;;

    *)
        log_error "Commande inconnue: $CMD"
        usage
        exit 1
        ;;
esac
