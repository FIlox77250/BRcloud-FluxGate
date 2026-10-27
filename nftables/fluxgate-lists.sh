#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Listes de reputation et plages CDN
# =============================================================================
# Remplit les sets d'intervalles de la table inet fluxgate :
#   reputation4/6 : reseaux notoirement hostiles (Spamhaus DROP, FireHOL
#                   level1...), jetes avant toute autre regle
#   cdn4/6        : plages du CDN place devant le serveur (mode CDN_MODE),
#                   seules autorisees a joindre HTTP/HTTPS
#
# Usage :
#   fluxgate-lists.sh update   # telecharge, valide, stocke, puis charge
#   fluxgate-lists.sh load     # recharge les sets depuis le cache local
#
# update est lance chaque jour par fluxgate-lists.timer. load est appele au
# boot (fluxgate-state.sh restore) et apres chaque rechargement du pare-feu.
#
# Un telechargement rate ou suspect (liste vide, trop petite) ne vide JAMAIS
# un set : on garde la derniere version valide. C'est vital en mode CDN, ou
# un set cdn4 vide couperait tout le trafic web.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${FLUXGATE_STATE_DIR:-/var/lib/fluxgate}"
LIST_DIR="${STATE_DIR}/lists"
CONFIG_FILE="${FLUXGATE_CONFIG:-${SCRIPT_DIR}/../scripts/config.env}"

# Meme chargement que les autres scripts : verification des droits de
# config.env et valeurs par defaut communes.
# shellcheck source=../scripts/lib/defaults.sh
source "${SCRIPT_DIR}/../scripts/lib/defaults.sh"
if [[ -f "$CONFIG_FILE" ]]; then
    fluxgate_load_config "$CONFIG_FILE" || exit 1
else
    fluxgate_apply_defaults
fi

REPUTATION_LISTS="${REPUTATION_LISTS:-}"
CDN_MODE="${CDN_MODE:-off}"

# Listes connues : nom court -> URL. REPUTATION_LISTS accepte ces noms ou
# directement des URL https://.
declare -A KNOWN_LISTS=(
    [spamhaus-drop]="https://www.spamhaus.org/drop/drop_v4.json"
    [spamhaus-drop6]="https://www.spamhaus.org/drop/drop_v6.json"
    [firehol-level1]="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
)

declare -A CDN_SOURCES=(
    [cloudflare4]="https://www.cloudflare.com/ips-v4"
    [cloudflare6]="https://www.cloudflare.com/ips-v6"
)

log() { echo "[fluxgate-lists] $*"; }

# -----------------------------------------------------------------------------
# extract_cidrs <fichier> <4|6>
# Extrait les reseaux d'un fichier texte, netset ou JSON Spamhaus. Seuls les
# motifs strictement IPv4/IPv6 (+ prefixe) passent : un fichier pirate ou
# corrompu ne peut pas injecter de syntaxe nftables.
#
# Les reseaux prives et reserves sont ecartes : FireHOL level1 inclut les
# bogons (10/8, 192.168/16...). Les charger dans reputation4 jetterait le
# LAN d'administration et provoquerait un lockout.
# -----------------------------------------------------------------------------
extract_cidrs() {
    local file="$1" fam="$2"
    # Commentaires "#" (netset) et ";" (anciens formats Spamhaus) retires :
    # ils contiennent des dates et des adresses qui ne sont pas des entrees.
    if [[ "$fam" == "4" ]]; then
        sed 's/[#;].*//' "$file" \
            | grep -oE '(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' \
            | sed -E 's/^[^0-9]//' \
            | awk -F'[./]' '
                $1>255 || $2>255 || $3>255 || $4>255 { next }
                NF==5 && ($5>32 || $5<8)             { next }
                $1==0 || $1==10 || $1==127 || $1>=224 { next }
                $1==100 && $2>=64 && $2<=127          { next }
                $1==169 && $2==254                    { next }
                $1==172 && $2>=16 && $2<=31           { next }
                $1==192 && $2==168                    { next }
                { print }' \
            | sort -u
    else
        # Une adresse IPv6 contient "::" ou exactement 7 ":" : cela ecarte
        # les heures (10:12:30) presentes dans les en-tetes des listes.
        sed 's/[#;].*//' "$file" \
            | grep -oE '[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}(/[0-9]{1,3})?' \
            | awk '{ a=$0; sub(/\/.*/, "", a); c=gsub(/:/, ":", a) }
                   index(a, "::") || c == 7 { print }' \
            | grep -viE '^(::|f[c-f])' \
            | sort -u
    fi
}

# -----------------------------------------------------------------------------
# fetch <url> <destination>
# -----------------------------------------------------------------------------
fetch() {
    local url="$1" dest="$2"
    if [[ "$url" != https://* ]]; then
        log "URL refusee (https obligatoire) : $url"
        return 1
    fi
    curl -fsSL --proto '=https' --max-time 60 --retry 2 -o "$dest" "$url"
}

# -----------------------------------------------------------------------------
# store <nom> <fam> <fichier_brut> <minimum>
# Valide puis remplace atomiquement ${LIST_DIR}/<nom>.<fam>. En dessous de
# <minimum> entrees, la nouvelle version est rejetee.
# -----------------------------------------------------------------------------
store() {
    local name="$1" fam="$2" raw="$3" min="$4" tmp count
    tmp=$(mktemp "${LIST_DIR}/.${name}.XXXXXX")
    extract_cidrs "$raw" "$fam" > "$tmp"
    count=$(wc -l < "$tmp")
    if (( count < min )); then
        log "${name} (IPv${fam}) : ${count} entree(s) seulement, version precedente conservee."
        rm -f "$tmp"
        return 1
    fi
    mv -f "$tmp" "${LIST_DIR}/${name}.v${fam}"
    log "${name} (IPv${fam}) : ${count} reseau(x)"
}

update() {
    mkdir -p "$LIST_DIR"
    chmod 700 "$STATE_DIR" "$LIST_DIR"
    command -v curl &>/dev/null || { log "curl absent"; return 1; }

    local raw entry url name
    raw=$(mktemp)
    trap 'rm -f "$raw"' RETURN

    # Les listes retirees de config.env ne doivent plus etre chargees
    find "$LIST_DIR" -maxdepth 1 -name 'rep-*' -delete

    for entry in ${REPUTATION_LISTS//,/ }; do
        if [[ "$entry" == https://* ]]; then
            url="$entry"
            name="rep-$(printf '%s' "$entry" | md5sum | cut -c1-8)"
        elif [[ -n "${KNOWN_LISTS[$entry]:-}" ]]; then
            url="${KNOWN_LISTS[$entry]}"
            name="rep-${entry}"
        else
            log "liste inconnue ignoree : $entry (connues : ${!KNOWN_LISTS[*]})"
            continue
        fi
        if fetch "$url" "$raw"; then
            store "$name" 4 "$raw" 1 || true
            store "$name" 6 "$raw" 1 || true
        else
            log "telechargement echoue : $url"
        fi
    done

    case "$CDN_MODE" in
        off|"") rm -f "${LIST_DIR}"/cdn.v4 "${LIST_DIR}"/cdn.v6 ;;
        cloudflare)
            # Cloudflare publie ~15 plages v4 et ~7 v6 : en dessous, la
            # reponse est anormale et on garde l'ancienne liste.
            fetch "${CDN_SOURCES[cloudflare4]}" "$raw" && store cdn 4 "$raw" 10 || true
            fetch "${CDN_SOURCES[cloudflare6]}" "$raw" && store cdn 6 "$raw" 5  || true
            ;;
        *)
            log "CDN_MODE inconnu : ${CDN_MODE} (valeurs : off, cloudflare)"
            ;;
    esac

    local rc=0
    load || rc=$?
    nginx_realip
    return "$rc"
}

# -----------------------------------------------------------------------------
# fill_set <set> <fichier...> : remplace le contenu d'un set en une transaction
# -----------------------------------------------------------------------------
fill_set() {
    local set="$1"; shift
    local tmp files=() f
    for f in "$@"; do [[ -s "$f" ]] && files+=("$f"); done
    tmp=$(mktemp)
    {
        echo "flush set inet fluxgate ${set}"
        if (( ${#files[@]} > 0 )); then
            # Paquets de 2000 elements : une seule ligne geante ralentit nft
            sort -u "${files[@]}" | awk -v s="$set" '
                { buf = buf (n ? ", " : "") $0; n++ }
                n == 2000 { print "add element inet fluxgate " s " { " buf " }"; buf=""; n=0 }
                END { if (n) print "add element inet fluxgate " s " { " buf " }" }'
        fi
    } > "$tmp"
    if nft -f "$tmp"; then
        log "set ${set} : $(sort -u "${files[@]}" /dev/null | wc -l) reseau(x)"
    else
        log "ERREUR au chargement du set ${set} (contenu precedent conserve)"
    fi
    rm -f "$tmp"
}

load() {
    if ! nft list table inet fluxgate &>/dev/null; then
        log "table inet fluxgate absente : chargement impossible"
        return 1
    fi
    shopt -s nullglob
    fill_set reputation4 "${LIST_DIR}"/rep-*.v4
    fill_set reputation6 "${LIST_DIR}"/rep-*.v6

    if [[ "$CDN_MODE" != "off" ]] && [[ -n "$CDN_MODE" ]]; then
        if [[ ! -s "${LIST_DIR}/cdn.v4" ]]; then
            log "ATTENTION : CDN_MODE=${CDN_MODE} mais aucune plage CDN en cache."
            log "Le trafic HTTP(S) serait integralement rejete : lancer 'fluxgate-lists.sh update'."
            return 1
        fi
        fill_set cdn4 "${LIST_DIR}/cdn.v4"
        fill_set cdn6 "${LIST_DIR}/cdn.v6"
    fi
}

# -----------------------------------------------------------------------------
# nginx_realip : vraie IP client derriere le CDN
# -----------------------------------------------------------------------------
# En mode CDN, toutes les connexions viennent des plages du CDN : sans
# real_ip, les limites NGINX par client et fail2ban viseraient le CDN lui-meme
# (blocage de tous les visiteurs a la fois). Les plages sont celles du cache,
# donc tenues a jour par le meme timer que les sets nftables.
nginx_realip() {
    local conf="${NGINX_REALIP_CONF:-/etc/nginx/conf.d/fluxgate-realip.conf}"
    local tmp prev=""
    command -v nginx &>/dev/null || return 0
    [[ -d "$(dirname "$conf")" ]] || return 0

    if [[ "$CDN_MODE" == "off" ]] || [[ -z "$CDN_MODE" ]]; then
        if [[ -f "$conf" ]]; then
            rm -f "$conf"
            nginx -t &>/dev/null && systemctl reload nginx 2>/dev/null || true
            log "real_ip NGINX retire (CDN_MODE=off)"
        fi
        return 0
    fi
    [[ -s "${LIST_DIR}/cdn.v4" ]] || return 0

    tmp=$(mktemp)
    {
        echo "# Genere par fluxgate-lists.sh (CDN_MODE=${CDN_MODE}) : ne pas modifier."
        cat "${LIST_DIR}/cdn.v4" "${LIST_DIR}/cdn.v6" 2>/dev/null \
            | sed 's/^/set_real_ip_from /; s/$/;/'
        case "$CDN_MODE" in
            cloudflare) echo "real_ip_header CF-Connecting-IP;" ;;
        esac
    } > "$tmp"
    if [[ -f "$conf" ]] && cmp -s "$tmp" "$conf"; then
        rm -f "$tmp"
        return 0
    fi
    [[ -f "$conf" ]] && prev=$(mktemp) && cp -f "$conf" "$prev"
    install -m 644 "$tmp" "$conf"
    rm -f "$tmp"
    if nginx -t &>/dev/null; then
        systemctl reload nginx 2>/dev/null || true
        log "real_ip NGINX mis a jour ($(grep -c '^set_real_ip_from' "$conf") plages)"
    else
        log "ERREUR : nginx -t refuse ${conf}, version precedente restauree"
        if [[ -n "$prev" ]]; then cp -f "$prev" "$conf"; else rm -f "$conf"; fi
    fi
    [[ -n "$prev" ]] && rm -f "$prev"
    return 0
}

case "${1:-}" in
    update) update ;;
    load)   load ;;
    *)
        echo "Usage: $0 {update|load}" >&2
        exit 1
        ;;
esac
