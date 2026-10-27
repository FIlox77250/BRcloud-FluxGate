#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - nftables Management Helper
# =============================================================================
# Commandes utilitaires pour gerer les sets et regles de la table
# "inet fluxgate". Aucune commande ne touche au reste du ruleset (Docker,
# CrowdSec, libvirt...) : plus de 'flush ruleset'.
#
# Niveaux de protection :
#   normal      ruleset de /etc/nftables.conf
#   shield      seuils resserres (SYN, connexions simultanees) pour les IP
#               hors ADMIN_NETS, le site reste joignable. Duree limitee,
#               retour automatique.
#   emergency   drop de toute nouvelle connexion entrante sauf SSH admin :
#               le site est coupe. Avec --for, retour automatique.
# =============================================================================

set -euo pipefail

CONF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="${CONF_DIR}/$(basename "${BASH_SOURCE[0]}")"
CONFIG_FILE="${FLUXGATE_CONFIG:-${CONF_DIR}/../scripts/config.env}"

# shellcheck source=../scripts/lib/defaults.sh
source "${CONF_DIR}/../scripts/lib/defaults.sh"
if [[ -f "$CONFIG_FILE" ]]; then
    fluxgate_load_config "$CONFIG_FILE" || exit 1
else
    fluxgate_apply_defaults
fi

TABLE="inet fluxgate"
EMERG_TABLE="inet fluxgate_emergency"
NFT_CONF="${FLUXGATE_NFT_CONF:-/etc/nftables.conf}"
STATE_SCRIPT="${CONF_DIR}/fluxgate-state.sh"
RUN_DIR="/run/fluxgate"
SHIELD_MARK="${RUN_DIR}/shield"

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  apply                     Recharger ${NFT_CONF} (bans et bouclier conserves)
  show                      Afficher la table ${TABLE}
  block <IP|IPv6/64> [ttl]  Bannir une IP, ou un /64 IPv6 entier (defaut: 1h)
  unblock <IP|IPv6/64>      Retirer un ban
  list-blocked              Lister les bans
  flush-blocked             Vider les blocklists
  counters                  Afficher les compteurs de drop
  conntrack-stats           Statistiques conntrack
  shield on [--for <duree>] Resserrer les seuils (defaut: ${SHIELD_DURATION})
  shield off                Revenir aux seuils normaux
  shield status             Etat du bouclier
  emergency-drop-all [--for <duree>]
                            Mode urgence : drop tout sauf SSH admin
  restore                   Quitter le mode urgence

Durees : 30s, 15m, 2h, 1d.

Exemples:
  $0 block 203.0.113.50 2h
  $0 block 2001:db8:1:2::/64 1d
  $0 shield on --for 30m
  $0 emergency-drop-all --for 15m
  $0 restore
EOF
}

log_info()  { echo "[INFO]  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_warn()  { echo "[WARN]  $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }
log_error() { echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }

check_root() {
    [[ $EUID -eq 0 ]] || { log_error "Root requis."; exit 1; }
}

require_table() {
    if ! nft list table $TABLE &>/dev/null; then
        log_error "Table ${TABLE} absente : lancer d'abord '$0 apply' ou deploy.sh."
        exit 1
    fi
}

valid_duration() {
    [[ "$1" =~ ^[0-9]+[smhd]?$ ]]
}

# -----------------------------------------------------------------------------
# schedule <nom> <duree> <commande...> : execution differee, survit a la
# fermeture de la session SSH. systemd-run de preference, sinon at.
# -----------------------------------------------------------------------------
schedule() {
    local name="$1" delay="$2"
    shift 2
    local unit="fluxgate-${name}"
    systemctl stop "${unit}.timer" &>/dev/null || true
    if command -v systemd-run &>/dev/null && systemd-run --quiet --collect \
        --unit="$unit" --on-active="$delay" --timer-property=AccuracySec=1s "$@" 2>/dev/null; then
        log_info "Retour automatique dans ${delay} (timer systemd ${unit})."
        return 0
    fi
    if command -v at &>/dev/null; then
        local minutes secs
        case "$delay" in
            *d) minutes=$(( ${delay%d} * 1440 )) ;;
            *h) minutes=$(( ${delay%h} * 60 )) ;;
            *m) minutes="${delay%m}" ;;
            *)  secs="${delay%s}"; minutes=$(( (secs + 59) / 60 )) ;;
        esac
        (( minutes < 1 )) && minutes=1
        printf '%q ' "$@" | at "now + ${minutes} minutes" 2>/dev/null
        log_info "Retour automatique dans ${minutes} min (job at)."
        return 0
    fi
    log_warn "Ni systemd-run ni at : PAS de retour automatique."
    return 1
}

cancel_schedule() {
    # Le timer seulement : quand c'est lui qui a lance cette commande, arreter
    # le .service tuerait la commande en cours.
    systemctl stop "fluxgate-${1}.timer" &>/dev/null || true
}

# -----------------------------------------------------------------------------
# normalize_ban <cible> : imprime "<set> <element>" ou echoue
# -----------------------------------------------------------------------------
normalize_ban() {
    local target="$1" addr plen
    addr="${target%/*}"
    plen=""
    [[ "$target" == */* ]] && plen="${target##*/}"

    if [[ "$addr" == *:* ]]; then
        case "$plen" in
            ""|128) echo "blocklist6 $addr" ;;
            64)
                # Element = adresse de reseau : la regle compare la source
                # masquee a /64 au contenu du set.
                python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1] + "/64", strict=False).network_address)' "$addr" \
                    | sed 's/^/blocklist6net /'
                ;;
            *) log_error "IPv6 : seuls /128 et /64 sont acceptes."; return 1 ;;
        esac
    else
        case "$plen" in
            ""|32) echo "blocklist4 $addr" ;;
            *) log_error "IPv4 : seule une adresse (/32) est acceptee."; return 1 ;;
        esac
    fi
}

# -----------------------------------------------------------------------------
# Bouclier
# -----------------------------------------------------------------------------
# Les regles vivent dans la chaine "shield" (appelee par input apres les
# blocklists) et dans des sets crees a la volee : 'shield off' supprime le
# tout sans recharger la table, donc sans perdre les bans.
shield_rules() {
    local ports="{ ${HTTP_PORT}, ${HTTPS_PORT} }"
    cat <<EOF
flush chain ${TABLE} shield
add set ${TABLE} shield_syn4 { type ipv4_addr; size 65535; flags dynamic, timeout; timeout 60s; }
add set ${TABLE} shield_syn6 { type ipv6_addr; size 65535; flags dynamic, timeout; timeout 60s; }
add set ${TABLE} shield_conn4 { type ipv4_addr; size 65535; flags dynamic; }
add set ${TABLE} shield_conn6 { type ipv6_addr; size 65535; flags dynamic; }
add rule ${TABLE} shield ct state established,related return
add rule ${TABLE} shield ip saddr @admin4 return
add rule ${TABLE} shield ip6 saddr @admin6 return
add rule ${TABLE} shield tcp dport ${ports} ct state new add @shield_conn4 { ip saddr ct count over ${SHIELD_CONN_LIMIT} } counter reject with tcp reset comment "Shield connlimit IPv4"
add rule ${TABLE} shield tcp dport ${ports} ct state new add @shield_conn6 { ip6 saddr and ffff:ffff:ffff:ffff:: ct count over ${SHIELD_CONN_LIMIT} } counter reject with tcp reset comment "Shield connlimit IPv6"
add rule ${TABLE} shield tcp flags syn ct state new update @shield_syn4 { ip saddr limit rate over ${SHIELD_SYN_RATE}/second burst ${SHIELD_SYN_BURST} packets } counter drop comment "Shield SYN IPv4"
add rule ${TABLE} shield tcp flags syn ct state new update @shield_syn6 { ip6 saddr and ffff:ffff:ffff:ffff:: limit rate over ${SHIELD_SYN_RATE}/second burst ${SHIELD_SYN_BURST} packets } counter drop comment "Shield SYN IPv6"
EOF
}

shield_on() {
    require_table
    shield_off_rules
    shield_rules | nft -f -
    mkdir -p "$RUN_DIR"
    echo "$1" > "$SHIELD_MARK"
    log_info "Bouclier actif : ${SHIELD_SYN_RATE} SYN/s et ${SHIELD_CONN_LIMIT} connexions par IP (ou /64)."
}

shield_off_rules() {
    nft flush chain $TABLE shield 2>/dev/null || true
    local s
    for s in shield_syn4 shield_syn6 shield_conn4 shield_conn6; do
        nft delete set $TABLE "$s" 2>/dev/null || true
    done
}

# -----------------------------------------------------------------------------
# Mode urgence : table separee, priorite plus haute que inet fluxgate.
# Un drop y est definitif ; un accept laisse ensuite inet fluxgate decider.
# -----------------------------------------------------------------------------
emergency_ruleset() {
    local session_ip v4="" v6=""
    session_ip=$(echo "${SSH_CLIENT:-${SSH_CONNECTION:-}}" | awk '{print $1}')

    if [[ -n "${ADMIN_NETS:-}" ]]; then
        v4="tcp dport ${SSH_PORT} ip saddr ${ADMIN_NETS} accept comment \"SSH urgence IPv4\""
    fi
    if [[ -n "${ADMIN_NETS6:-}" ]]; then
        v6="tcp dport ${SSH_PORT} ip6 saddr ${ADMIN_NETS6} accept comment \"SSH urgence IPv6\""
    fi
    if [[ -z "$v4" && -z "$v6" ]]; then
        log_warn "ADMIN_NETS et ADMIN_NETS6 vides : SSH laisse ouvert a tous pour eviter le lockout."
        v4="tcp dport ${SSH_PORT} accept comment \"SSH urgence (non restreint)\""
    fi

    cat <<EOF
table ${EMERG_TABLE}
delete table ${EMERG_TABLE}
table ${EMERG_TABLE} {
    chain input {
        type filter hook input priority filter - 10; policy drop;
        iif "lo" accept
        ct state invalid drop
        ct state established,related accept
        ${v4}
        ${v6}
EOF
    # La session qui lance la commande reste joignable, meme hors ADMIN_NETS.
    if [[ -n "$session_ip" ]]; then
        if [[ "$session_ip" == *:* ]]; then
            echo "        tcp dport ${SSH_PORT} ip6 saddr ${session_ip} accept comment \"SSH session courante\""
        else
            echo "        tcp dport ${SSH_PORT} ip saddr ${session_ip} accept comment \"SSH session courante\""
        fi
    fi
    cat <<EOF
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } ip6 hoplimit 255 accept
        counter drop
    }
}
EOF
}

parse_for() {
    FOR_DURATION=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --for) FOR_DURATION="${2:?duree requise apres --for}"; shift 2 ;;
            *) log_error "Option inconnue : $1"; exit 1 ;;
        esac
    done
    if [[ -n "$FOR_DURATION" ]] && ! valid_duration "$FOR_DURATION"; then
        log_error "Duree invalide : $FOR_DURATION (exemples : 30s, 15m, 2h)"
        exit 1
    fi
}

case "${1:-help}" in
    apply)
        check_root
        if [[ ! -f "$NFT_CONF" ]]; then
            log_error "${NFT_CONF} introuvable : le fichier du depot est un modele, lancer deploy.sh."
            exit 1
        fi
        log_info "Verification de ${NFT_CONF}..."
        nft -c -f "$NFT_CONF"
        # Recharger la table la vide : bans sauvegardes avant, rejoues apres.
        if nft list table $TABLE &>/dev/null; then
            bash "$STATE_SCRIPT" save
        fi
        nft -f "$NFT_CONF"
        bash "$STATE_SCRIPT" restore || true
        if [[ -f "$SHIELD_MARK" ]]; then
            shield_rules | nft -f -
            log_info "Bouclier reapplique."
        fi
        log_info "Configuration appliquee."
        ;;

    show)
        nft list table $TABLE
        ;;

    block)
        check_root
        require_table
        TARGET="${2:?IP requise}"
        TTL="${3:-1h}"
        valid_duration "$TTL" || { log_error "TTL invalide : $TTL"; exit 1; }
        read -r SET ELEM < <(normalize_ban "$TARGET") || exit 1
        [[ -n "${ELEM:-}" ]] || exit 1
        nft add element $TABLE "$SET" "{ $ELEM timeout $TTL }"
        log_info "$TARGET bloque (set ${SET}, TTL: $TTL)."
        ;;

    unblock)
        check_root
        require_table
        TARGET="${2:?IP requise}"
        read -r SET ELEM < <(normalize_ban "$TARGET") || exit 1
        [[ -n "${ELEM:-}" ]] || exit 1
        nft delete element $TABLE "$SET" "{ $ELEM }"
        log_info "$TARGET debloque."
        ;;

    list-blocked)
        for s in blocklist4 blocklist6 blocklist6net; do
            log_info "Set ${s} :"
            nft list set $TABLE "$s" 2>/dev/null | sed -n '/elements/,/}/p' || true
        done
        ;;

    flush-blocked)
        check_root
        for s in blocklist4 blocklist6 blocklist6net; do
            nft flush set $TABLE "$s" 2>/dev/null || true
        done
        log_info "Blocklists videes."
        ;;

    counters)
        nft list chain $TABLE input 2>/dev/null | grep -E "counter|comment"
        nft list chain $TABLE shield 2>/dev/null | grep -E "counter" || true
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

    shield)
        case "${2:-status}" in
            on)
                check_root
                shift 2
                parse_for "$@"
                DURATION="${FOR_DURATION:-$SHIELD_DURATION}"
                shield_on "$DURATION"
                if [[ "$DURATION" != "0" ]]; then
                    cancel_schedule shield-off
                    schedule shield-off "$DURATION" "$SELF" shield off || true
                else
                    log_warn "Bouclier sans echeance : '$0 shield off' pour revenir."
                fi
                ;;
            off)
                check_root
                cancel_schedule shield-off
                shield_off_rules
                rm -f "$SHIELD_MARK"
                log_info "Bouclier desactive : seuils normaux."
                ;;
            status)
                if [[ -f "$SHIELD_MARK" ]] && nft list chain $TABLE shield 2>/dev/null | grep -q 'Shield'; then
                    echo "shield: on (duree demandee : $(cat "$SHIELD_MARK"))"
                    nft list chain $TABLE shield | grep counter
                else
                    echo "shield: off"
                fi
                ;;
            *) log_error "Usage : $0 shield on [--for <duree>] | off | status"; exit 1 ;;
        esac
        ;;

    emergency-drop-all)
        check_root
        shift
        parse_for "$@"
        log_info "MODE URGENCE : drop de toute nouvelle connexion sauf SSH admin (port $SSH_PORT) !"
        emergency_ruleset | nft -f -
        log_info "Mode urgence actif (table ${EMERG_TABLE}). Le reste du ruleset est intact."
        if [[ -n "$FOR_DURATION" ]]; then
            cancel_schedule emergency-restore
            schedule emergency-restore "$FOR_DURATION" "$SELF" restore || true
        else
            log_info "Revenir a l'etat normal : $0 restore"
        fi
        ;;

    restore)
        check_root
        cancel_schedule emergency-restore
        if nft list table $EMERG_TABLE &>/dev/null; then
            nft delete table $EMERG_TABLE
            log_info "Mode urgence termine."
        else
            log_info "Mode urgence non actif."
        fi
        # Ancien mode urgence (FluxGate <= 2.0) : table "inet emergency"
        # installee apres un 'flush ruleset'. Seul un apply reconstruit tout.
        if nft list table inet emergency &>/dev/null; then
            log_warn "Ancienne table 'inet emergency' detectee : suppression puis rechargement de ${NFT_CONF}."
            nft delete table inet emergency
            "$SELF" apply
        fi
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
