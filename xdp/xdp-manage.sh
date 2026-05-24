#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - XDP/eBPF Filter Management
# =============================================================================
# Gestion de xdp-filter pour drop tres tot (avant pile noyau).
# Capacite : dizaines de millions de pps par coeur CPU.
#
# Pre-requis : xdp-tools (xdp-filter) installe, driver NIC compatible XDP.
# Fallback : mode "generic" si le driver ne supporte pas XDP natif.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/../scripts/config.env"

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

IFACE="${IFACE:-eth0}"

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  load                      Attacher xdp-filter sur l'interface
  unload                    Detacher xdp-filter (rollback)
  block-ip <IP> [timeout]   Bloquer une IP source (defaut: timeout 1h)
  unblock-ip <IP>           Debloquer une IP source
  block-port <PORT> [proto] Bloquer un port destination (tcp|udp, defaut: tcp)
  unblock-port <PORT>       Debloquer un port
  list                      Lister les regles actives
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

install_xdp_loader_wrapper() {
    # Eviter de tourner en boucle
    [[ -n "${FLUXGATE_WRAPPER_INSTALLED:-}" ]] && return 0
    export FLUXGATE_WRAPPER_INSTALLED=1

    local loader_path=""
    for p in /usr/sbin/xdp-loader /usr/bin/xdp-loader /sbin/xdp-loader /bin/xdp-loader; do
        if [[ -f "$p" ]] && [[ ! -L "$p" ]] && [[ ! "$p" == *".real" ]]; then
            loader_path="$p"
            break
        fi
    done

    if [[ -n "$loader_path" ]]; then
        # Verifier si le loader a deja ete sauvegarde/patche
        if [[ ! -f "${loader_path}.real" ]]; then
            log_info "Application du correctif de compatibilite xdp-loader a : $loader_path"
            mv "$loader_path" "${loader_path}.real"
            
            # Creer le wrapper
            cat << 'EOF' > "$loader_path"
#!/usr/bin/env bash
# Wrapper de compatibilite cree par FluxGate pour resoudre le bug '--dev' de xdp-tools
REAL_LOADER="${BASH_SOURCE[0]}.real"
if [[ ! -f "$REAL_LOADER" ]]; then
    REAL_LOADER="/usr/sbin/xdp-loader.real"
fi

ARGS=()
DEV=""
MODE=""
POLICY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev|-d)
            DEV="$2"
            shift 2
            ;;
        -m|--mode)
            MODE="$2"
            shift 2
            ;;
        -p|--policy)
            POLICY="$2"
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

if [[ "${ARGS[0]:-}" == "load" ]] && [[ -n "$DEV" ]]; then
    FINAL_ARGS=("load")
    if [[ -n "$MODE" ]]; then
        FINAL_ARGS+=("-m" "$MODE")
    fi
    if [[ -n "$POLICY" ]]; then
        FINAL_ARGS+=("-p" "$POLICY")
    fi
    FINAL_ARGS+=("$DEV")
    for arg in "${ARGS[@]:1}"; do
        FINAL_ARGS+=("$arg")
    done
    exec "$REAL_LOADER" "${FINAL_ARGS[@]}"
else
    exec "$REAL_LOADER" "$@"
fi
EOF
            chmod +x "$loader_path"
            log_info "Wrapper de compatibilite xdp-loader installe avec succes."
        fi
    fi
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

check_xdp_filter

case "$CMD" in
    load)
        check_root
        install_xdp_loader_wrapper
        log_info "Attachement xdp-filter sur $IFACE..."
        if xdp-filter load "$IFACE" 2>/dev/null; then
            log_info "xdp-filter attache (mode natif si supporte, sinon generic)."
        else
            log_warn "Tentative en mode skb (generic fallback)..."
            xdp-filter load -m skb "$IFACE"
            log_info "xdp-filter attache en mode generic/skb."
        fi
        ;;

    unload)
        check_root
        install_xdp_loader_wrapper
        log_info "Detachement xdp-filter de $IFACE..."
        xdp-filter unload "$IFACE" || log_warn "Rien a detacher ou erreur."
        log_info "XDP detache."
        ;;

    block-ip)
        check_root
        IP="${1:?IP requise}"
        log_info "Blocage IP source $IP..."
        xdp-filter ip "$IP" -m src
        log_info "IP $IP bloquee."
        ;;

    unblock-ip)
        check_root
        IP="${1:?IP requise}"
        log_info "Deblocage IP source $IP..."
        xdp-filter ip -r "$IP"
        log_info "IP $IP debloquee."
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
        xdp-filter port -r "$PORT" -p "$PROTO"
        log_info "Port $PROTO/$PORT debloque."
        ;;

    list)
        log_info "Regles xdp-filter actives :"
        xdp-filter status 2>/dev/null || log_warn "Aucune regle ou xdp-filter non charge."
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

    help|--help|-h)
        usage
        ;;

    *)
        log_error "Commande inconnue: $CMD"
        usage
        exit 1
        ;;
esac
