#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Persistance de l'etat dynamique du pare-feu
# =============================================================================
# Les blocklists sont des sets dynamiques : un reboot, ou un rechargement de
# /etc/nftables.conf (qui recree la table inet fluxgate), les vide. Sans ce
# script, tous les attaquants bannis etaient relaches d'un coup.
#
# Usage :
#   fluxgate-state.sh save      # blocklists -> /var/lib/fluxgate/bans.nft
#   fluxgate-state.sh restore   # bans sauvegardes + listes de reputation/CDN
#
# Appele par fluxgate-state.service (restore au boot, save a l'arret), par
# deploy.sh et par nft-manage.sh apply autour de chaque rechargement.
# =============================================================================

set -uo pipefail

STATE_DIR="${FLUXGATE_STATE_DIR:-/var/lib/fluxgate}"
BANS_FILE="${STATE_DIR}/bans.nft"
TABLE="inet fluxgate"
LISTS_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fluxgate-lists.sh"

# -----------------------------------------------------------------------------
# dump_set <table> <set>
# Ecrit "ip timeout <reste>" pour chaque element. Le temps restant est
# conserve (a la seconde pres) : un ban de 24h ne redevient pas un ban d'1h.
# -----------------------------------------------------------------------------
dump_set() {
    local table="$1" set="$2"
    # shellcheck disable=SC2086
    nft list set $table "$set" 2>/dev/null \
        | awk '/elements = \{/{f=1} f{print} f && /\}/{exit}' \
        | tr -d '\n\t' \
        | sed 's/.*elements = {//; s/}.*//' \
        | tr ',' '\n' \
        | awk '{
            ip=$1; rem="";
            for (i=2; i<=NF; i++) if ($i == "expires") rem=$(i+1);
            sub(/[0-9]+ms$/, "", rem);
            if (ip == "") next;
            if (rem == "") print ip; else print ip " timeout " rem;
          }'
}

save() {
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    local tmp n=0 table set elems
    tmp=$(mktemp "${STATE_DIR}/bans.XXXXXX")

    # Table dediee, ou table "inet filter" d'une installation anterieure
    # (FluxGate <= 2.0) si c'est elle qui porte encore les blocklists.
    table="$TABLE"
    if ! nft list set inet fluxgate blocklist4 &>/dev/null \
       && nft list set inet filter blocklist4 &>/dev/null; then
        table="inet filter"
    fi

    for set in blocklist4 blocklist6 blocklist6net; do
        nft list set $table "$set" &>/dev/null || continue
        elems=$(dump_set "$table" "$set" | paste -sd, - | sed 's/,/, /g')
        if [[ -n "$elems" ]]; then
            echo "add element ${TABLE} ${set} { ${elems} }" >> "$tmp"
            n=$((n + $(tr -cd ',' <<<"$elems" | wc -c) + 1))
        fi
    done

    mv -f "$tmp" "$BANS_FILE"
    chmod 600 "$BANS_FILE"
    echo "[fluxgate-state] ${n} ban(s) sauvegarde(s) dans ${BANS_FILE}"
}

restore() {
    if ! nft list table inet fluxgate &>/dev/null; then
        echo "[fluxgate-state] table inet fluxgate absente : rien a restaurer" >&2
        return 1
    fi

    if [[ -s "$BANS_FILE" ]]; then
        # Une ligne invalide (element deja expire, format change) ne doit pas
        # empecher le reste : on rejoue ligne par ligne en cas d'echec global.
        if ! nft -f "$BANS_FILE" 2>/dev/null; then
            while IFS= read -r line; do
                nft "$line" 2>/dev/null || true
            done < "$BANS_FILE"
        fi
        echo "[fluxgate-state] bans restaures depuis ${BANS_FILE}"
    fi

    if [[ -x "$LISTS_SCRIPT" ]] || [[ -f "$LISTS_SCRIPT" ]]; then
        bash "$LISTS_SCRIPT" load || true
    fi
}

case "${1:-}" in
    save)    save ;;
    restore) restore ;;
    *)
        echo "Usage: $0 {save|restore}" >&2
        exit 1
        ;;
esac
