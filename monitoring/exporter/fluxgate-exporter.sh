#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Exporteur de metriques (textfile collector)
# =============================================================================
# Ecrit les metriques FluxGate au format Prometheus dans le repertoire du
# textfile collector de node_exporter. Lance chaque minute par
# fluxgate-exporter.timer ; aucun port supplementaire n'est ouvert.
#
#   fluxgate-exporter.sh            # ecrit ${TEXTFILE_DIR}/fluxgate.prom
#   fluxgate-exporter.sh --stdout   # affiche sans rien ecrire
#
# node_exporter doit etre lance avec :
#   --collector.textfile.directory=/var/lib/prometheus/node-exporter
# (valeur par defaut du paquet Debian/Ubuntu prometheus-node-exporter)
#
# Metriques :
#   fluxgate_nft_table_loaded               table inet fluxgate presente
#   fluxgate_nft_rule_packets_total{chain,rule}
#   fluxgate_nft_rule_bytes_total{chain,rule}
#                                           compteurs des regles commentees
#   fluxgate_banned_ips{set}                bans actifs (blocklist4/6/6net)
#   fluxgate_reputation_entries{set}        reseaux des listes de reputation
#   fluxgate_shield_active                  bouclier actif
#   fluxgate_emergency_active               mode urgence actif
#   fluxgate_xdp_banned_ips                 bans XDP actifs
#   fluxgate_fail2ban_banned{jail}          bans fail2ban par jail
#   fluxgate_crowdsec_decisions             decisions CrowdSec actives
#   fluxgate_nginx_429_total                reponses 429 (rate limiting NGINX)
#   fluxgate_waf_blocked_total              requetes bloquees par ModSecurity
#   fluxgate_exporter_last_run_timestamp_seconds
#
# Les deux derniers compteurs sont calcules en lisant les journaux depuis la
# position memorisee au passage precedent (rotation detectee par l'inode) :
# ils sont monotones et s'utilisent avec rate()/increase().
# =============================================================================

set -uo pipefail

TEXTFILE_DIR="${FLUXGATE_TEXTFILE_DIR:-/var/lib/prometheus/node-exporter}"
STATE_DIR="${FLUXGATE_STATE_DIR:-/var/lib/fluxgate}"
OFFSETS_FILE="${STATE_DIR}/exporter-offsets"
ACCESS_LOG="${FLUXGATE_ACCESS_LOG:-/var/log/nginx/access.log}"
ERROR_LOG="${FLUXGATE_ERROR_LOG:-/var/log/nginx/error.log}"

STDOUT=false
[[ "${1:-}" == "--stdout" ]] && STDOUT=true

# set_size <set> : nombre d'elements d'un set de la table inet fluxgate
set_size() {
    nft list set inet fluxgate "$1" 2>/dev/null \
        | awk '/elements = \{/ {f = 1} f {print} f && /\}/ {exit}' \
        | tr -d '\n' \
        | sed -n 's/.*elements = {\(.*\)}.*/\1/p' \
        | awk -F, '{print NF} END {if (NR == 0) print 0}'
}

# rule_counters : compteurs des regles portant un commentaire, par chaine.
# Les regles de meme commentaire dans une chaine sont additionnees.
rule_counters() {
    nft list table inet fluxgate 2>/dev/null | awk '
        $1 == "chain" { chain = $2; next }
        /counter packets [0-9]+ bytes [0-9]+/ && /comment "/ {
            match($0, /counter packets [0-9]+ bytes [0-9]+/)
            split(substr($0, RSTART, RLENGTH), c, " ")
            match($0, /comment "[^"]*"/)
            rule = substr($0, RSTART + 9, RLENGTH - 10)
            gsub(/\\/, "\\\\", rule)
            key = chain "\t" rule
            pk[key] += c[3]; by[key] += c[5]
            if (!(key in seen)) { seen[key] = 1; order[n++] = key }
        }
        END {
            print "# HELP fluxgate_nft_rule_packets_total Paquets vus par les regles nftables FluxGate."
            print "# TYPE fluxgate_nft_rule_packets_total counter"
            for (i = 0; i < n; i++) {
                split(order[i], k, "\t")
                printf "fluxgate_nft_rule_packets_total{chain=\"%s\",rule=\"%s\"} %d\n", k[1], k[2], pk[order[i]]
            }
            print "# HELP fluxgate_nft_rule_bytes_total Octets vus par les regles nftables FluxGate."
            print "# TYPE fluxgate_nft_rule_bytes_total counter"
            for (i = 0; i < n; i++) {
                split(order[i], k, "\t")
                printf "fluxgate_nft_rule_bytes_total{chain=\"%s\",rule=\"%s\"} %d\n", k[1], k[2], by[order[i]]
            }
        }'
}

# log_counter <nom> <journal> <programme awk> : total cumule des lignes
# comptees par le programme awk, en ne lisant que ce qui a ete ajoute au
# journal depuis le passage precedent. Etat : "<nom> <inode> <offset> <total>".
log_counter() {
    local name="$1" file="$2" prog="$3"
    local ino size old_ino=0 off=0 total=0 new
    if [[ -f "$OFFSETS_FILE" ]]; then
        read -r old_ino off total < <(awk -v n="$name" '$1 == n {print $2, $3, $4}' "$OFFSETS_FILE") || true
    fi
    old_ino="${old_ino:-0}"; off="${off:-0}"; total="${total:-0}"
    if [[ -r "$file" ]]; then
        ino=$(stat -c %i "$file")
        size=$(stat -c %s "$file")
        # Rotation ou troncature : on repart du debut du nouveau fichier
        if [[ "$ino" != "$old_ino" ]] || (( size < off )); then
            off=0
        fi
        new=$(tail -c +"$((off + 1))" "$file" | head -c "$((size - off))" | awk "$prog")
        total=$(( total + ${new:-0} ))
        off="$size"
    else
        ino="$old_ino"
    fi
    if [[ "$STDOUT" != "true" ]]; then
        local tmp
        tmp=$(mktemp "${STATE_DIR}/.exporter-offsets.XXXXXX")
        { [[ -f "$OFFSETS_FILE" ]] && awk -v n="$name" '$1 != n' "$OFFSETS_FILE"
          echo "$name $ino $off $total"; } > "$tmp"
        mv -f "$tmp" "$OFFSETS_FILE"
    fi
    echo "$total"
}

collect() {
    local loaded=0 shield=0 emergency=0 s xdp=0

    if nft list table inet fluxgate &>/dev/null; then
        loaded=1
    fi
    echo "# HELP fluxgate_nft_table_loaded Table nftables inet fluxgate chargee."
    echo "# TYPE fluxgate_nft_table_loaded gauge"
    echo "fluxgate_nft_table_loaded ${loaded}"

    if (( loaded )); then
        rule_counters

        echo "# HELP fluxgate_banned_ips Adresses ou reseaux bannis dans les sets FluxGate."
        echo "# TYPE fluxgate_banned_ips gauge"
        for s in blocklist4 blocklist6 blocklist6net; do
            echo "fluxgate_banned_ips{set=\"${s}\"} $(set_size "$s")"
        done

        echo "# HELP fluxgate_reputation_entries Reseaux charges depuis les listes de reputation."
        echo "# TYPE fluxgate_reputation_entries gauge"
        for s in reputation4 reputation6; do
            echo "fluxgate_reputation_entries{set=\"${s}\"} $(set_size "$s")"
        done

        if nft list chain inet fluxgate shield 2>/dev/null | grep -qE '(drop|reject)'; then
            shield=1
        fi
    fi
    nft list table inet fluxgate_emergency &>/dev/null && emergency=1

    echo "# HELP fluxgate_shield_active Bouclier (seuils resserres) actif."
    echo "# TYPE fluxgate_shield_active gauge"
    echo "fluxgate_shield_active ${shield}"
    echo "# HELP fluxgate_emergency_active Mode urgence (drop de tout sauf SSH admin) actif."
    echo "# TYPE fluxgate_emergency_active gauge"
    echo "fluxgate_emergency_active ${emergency}"

    if [[ -s "${STATE_DIR}/xdp-bans" ]]; then
        xdp=$(awk -v now="$(date +%s)" '$2 == 0 || $2 > now' "${STATE_DIR}/xdp-bans" | wc -l)
    fi
    echo "# HELP fluxgate_xdp_banned_ips Adresses bannies au niveau XDP."
    echo "# TYPE fluxgate_xdp_banned_ips gauge"
    echo "fluxgate_xdp_banned_ips ${xdp}"

    if command -v fail2ban-client &>/dev/null && fail2ban-client ping &>/dev/null; then
        echo "# HELP fluxgate_fail2ban_banned Adresses actuellement bannies par jail fail2ban."
        echo "# TYPE fluxgate_fail2ban_banned gauge"
        local jails j n
        jails=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' ')
        for j in $jails; do
            n=$(fail2ban-client status "$j" 2>/dev/null | awk -F: '/Currently banned/ {gsub(/[[:space:]]/, "", $2); print $2}')
            echo "fluxgate_fail2ban_banned{jail=\"${j}\"} ${n:-0}"
        done
    fi

    if command -v cscli &>/dev/null; then
        local d
        if d=$(cscli decisions list -o raw 2>/dev/null); then
            echo "# HELP fluxgate_crowdsec_decisions Decisions CrowdSec actives."
            echo "# TYPE fluxgate_crowdsec_decisions gauge"
            echo "fluxgate_crowdsec_decisions $(printf '%s\n' "$d" | awk 'NR > 1 && NF' | wc -l)"
        fi
    fi

    # Format combined : le code HTTP est le 9e champ
    echo "# HELP fluxgate_nginx_429_total Reponses 429 servies par NGINX (rate limiting)."
    echo "# TYPE fluxgate_nginx_429_total counter"
    echo "fluxgate_nginx_429_total $(log_counter nginx429 "$ACCESS_LOG" '$9 == 429 {n++} END {print n + 0}')"

    echo "# HELP fluxgate_waf_blocked_total Requetes refusees par ModSecurity."
    echo "# TYPE fluxgate_waf_blocked_total counter"
    echo "fluxgate_waf_blocked_total $(log_counter waf "$ERROR_LOG" '/ModSecurity: Access denied/ {n++} END {print n + 0}')"

    echo "# HELP fluxgate_exporter_last_run_timestamp_seconds Date du dernier passage de l'exporteur."
    echo "# TYPE fluxgate_exporter_last_run_timestamp_seconds gauge"
    echo "fluxgate_exporter_last_run_timestamp_seconds $(date +%s)"
}

if [[ "$STDOUT" == "true" ]]; then
    collect
    exit 0
fi

mkdir -p "$TEXTFILE_DIR" "$STATE_DIR"
chmod 700 "$STATE_DIR"
# Ecriture atomique : node_exporter ne doit jamais lire un fichier partiel
TMP=$(mktemp "${TEXTFILE_DIR}/.fluxgate.prom.XXXXXX")
trap 'rm -f "$TMP"' EXIT
collect > "$TMP"
chmod 644 "$TMP"
mv -f "$TMP" "${TEXTFILE_DIR}/fluxgate.prom"
