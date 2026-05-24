#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - nftables Management Helper
# =============================================================================
# Commandes utilitaires pour gerer les sets et regles nftables.
# =============================================================================

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  apply               Appliquer la configuration nftables
  show                Afficher les regles actives
  block <IP> [ttl]    Ajouter une IP a la blocklist (defaut: 1h)
  unblock <IP>        Retirer une IP de la blocklist
  list-blocked        Lister les IPs bloquees
  flush-blocked       Vider les blocklists
  counters            Afficher les compteurs de drop
  conntrack-stats     Statistiques conntrack
  emergency-drop-all  Mode urgence : drop tout sauf SSH admin

Exemples:
  $0 block 203.0.113.50 2h
  $0 counters
  $0 emergency-drop-all
EOF
}

log_info()  { echo "[INFO]  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_error() { echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }

check_root() {
    [[ $EUID -eq 0 ]] || { log_error "Root requis."; exit 1; }
}

CONF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONF_DIR}/../scripts/config.env"

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

SSH_PORT="${SSH_PORT:-22}"

case "${1:-help}" in
    apply)
        check_root
        log_info "Application de la configuration nftables..."
        nft -f "$CONF_DIR/nftables.conf"
        log_info "Configuration appliquee."
        nft list ruleset | head -5
        ;;

    show)
        nft list ruleset
        ;;

    block)
        check_root
        IP="${2:?IP requise}"
        TTL="${3:-1h}"
        # Detecter IPv4 vs IPv6
        if [[ "$IP" == *:* ]]; then
            nft add element inet filter blocklist6 "{ $IP timeout $TTL }"
        else
            nft add element inet filter blocklist4 "{ $IP timeout $TTL }"
        fi
        log_info "IP $IP bloquee (TTL: $TTL)."
        ;;

    unblock)
        check_root
        IP="${2:?IP requise}"
        if [[ "$IP" == *:* ]]; then
            nft delete element inet filter blocklist6 "{ $IP }"
        else
            nft delete element inet filter blocklist4 "{ $IP }"
        fi
        log_info "IP $IP debloquee."
        ;;

    list-blocked)
        log_info "Blocklist IPv4 :"
        nft list set inet filter blocklist4 2>/dev/null || echo "(vide ou inexistant)"
        log_info "Blocklist IPv6 :"
        nft list set inet filter blocklist6 2>/dev/null || echo "(vide ou inexistant)"
        ;;

    flush-blocked)
        check_root
        nft flush set inet filter blocklist4
        nft flush set inet filter blocklist6
        log_info "Blocklists videes."
        ;;

    counters)
        nft list chain inet filter input 2>/dev/null | grep -E "counter|comment"
        ;;

    conntrack-stats)
        log_info "Conntrack stats :"
        echo "  Entries : $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo N/A)"
        echo "  Max     : $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo N/A)"
        echo "  Buckets : $(cat /proc/sys/net/netfilter/nf_conntrack_buckets 2>/dev/null || echo N/A)"
        if command -v conntrack &>/dev/null; then
            conntrack -S 2>/dev/null || true
        fi
        ;;

    emergency-drop-all)
        check_root
        log_info "MODE URGENCE : drop tout sauf SSH admin (port $SSH_PORT) !"
        nft flush ruleset
        nft -f - <<EMERGENCY
table inet emergency {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        tcp dport $SSH_PORT accept comment "SSH urgence"
        counter drop
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EMERGENCY
        log_info "Mode urgence actif. Seul SSH (port $SSH_PORT) est ouvert."
        ;;

    help|--help|-h)
        usage
        ;;

    *)
        log_error "Commande inconnue: $1"
        usage
        exit 1
        ;;
esac
