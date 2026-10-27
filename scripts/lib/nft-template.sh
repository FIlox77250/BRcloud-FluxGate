#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Application de config.env dans nftables.conf
# =============================================================================
# Fournit render_nftables_conf(), utilisee par deploy.sh et par les tests.
#
# Pourquoi cette fonction est isolee ici :
#   Les valeurs sont injectees par sed, avec pour ancre le nom d'un "define"
#   ou d'un set. Si quelqu'un reformule une regle dans nftables.conf, l'ancre
#   ne matche plus et la substitution echoue EN SILENCE : le pare-feu part
#   avec les valeurs par defaut sans que rien ne le signale. C'etait le
#   defaut de fond de la v1 (la moitie de config.env ne servait a rien).
#
#   En centralisant ici, tests/test-templating.sh peut verifier apres chaque
#   modification que chaque valeur atterrit bien ou on l'attend.
#
# Variables lues (toutes optionnelles, valeur par defaut sinon) :
#   SSH_PORT HTTP_PORT HTTPS_PORT
#   ADMIN_NETS ADMIN_NETS6
#   NFT_SYN_RATE NFT_SYN_BURST NFT_HTTP_SYN_RATE NFT_HTTP_SYN_BURST
#   NFT_SSH_RATE NFT_SSH_BURST NFT_HTTP_CONN_LIMIT
#   NFT_FORWARD_POLICY (drop|accept ; "auto" est resolu par deploy.sh)
#   EXTRA_TCP_PORTS EXTRA_UDP_PORTS ALLOWLIST4 ALLOWLIST6
#   CDN_MODE (off|cloudflare)
#   SYNPROXY_ENABLED SYNPROXY_MSS SYNPROXY_WSCALE
#   SSH_MODE (open|strict)
# =============================================================================

if ! declare -F log_info >/dev/null 2>&1; then
    log_info()  { echo "[INFO]  $*"; }
    log_warn()  { echo "[WARN]  $*" >&2; }
    log_error() { echo "[ERROR] $*" >&2; }
fi

# -----------------------------------------------------------------------------
# _nft_require_match <fichier> <motif> <description>
# Verifie qu'une ancre existe AVANT de tenter la substitution. Une ancre
# absente est une erreur de maintenance, pas un cas normal a ignorer.
# -----------------------------------------------------------------------------
_nft_require_match() {
    local file="$1" pattern="$2" desc="$3"
    if ! grep -qE "$pattern" "$file"; then
        log_error "Ancre introuvable dans $(basename "$file") : $desc"
        log_error "  motif attendu : $pattern"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# _nft_list <valeur>
# Transforme "25, 587 1000-2000" en "25, 587, 1000-2000" : config.env accepte
# virgules et espaces comme separateurs, nft n'accepte que les virgules.
# -----------------------------------------------------------------------------
_nft_list() {
    local raw="${1//,/ }" out="" item
    for item in $raw; do
        out+="${out:+, }${item}"
    done
    printf '%s' "$out"
}

# -----------------------------------------------------------------------------
# _nft_toggle_block <fichier> <MARQUEUR> <on|off> <indentation>
# Decommente (on) ou commente (off) les lignes situees entre
# "# --- <MARQUEUR> BEGIN ---" et "# --- <MARQUEUR> END ---", marqueurs exclus.
# -----------------------------------------------------------------------------
_nft_toggle_block() {
    local file="$1" marker="$2" state="$3" ind="$4"
    local range="/^${ind}# --- ${marker} BEGIN ---\$/,/^${ind}# --- ${marker} END ---\$/"
    if [[ "$state" == "on" ]]; then
        sed -i "${range}{/BEGIN ---\$/!{/END ---\$/!s/^${ind}# /${ind}/}}" "$file"
    else
        sed -i "${range}{/BEGIN ---\$/!{/END ---\$/!{/^${ind}# /!s/^${ind}/${ind}# /}}}" "$file"
    fi
}

# -----------------------------------------------------------------------------
# render_nftables_conf <fichier>
# Applique la configuration en place. Retourne 1 si une ancre a disparu.
# -----------------------------------------------------------------------------
render_nftables_conf() {
    local conf="$1"
    local rc=0

    [[ -f "$conf" ]] || { log_error "Fichier introuvable : $conf"; return 1; }

    local ssh_port="${SSH_PORT:-22}"
    local http_port="${HTTP_PORT:-80}"
    local https_port="${HTTPS_PORT:-443}"
    local admin_nets="${ADMIN_NETS:-{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/24 \}}"
    local admin_nets6="${ADMIN_NETS6:-{ fc00::/7, fe80::/10 \}}"
    local syn_rate="${NFT_SYN_RATE:-100}"
    local syn_burst="${NFT_SYN_BURST:-150}"
    local http_rate="${NFT_HTTP_SYN_RATE:-50}"
    local http_burst="${NFT_HTTP_SYN_BURST:-100}"
    local ssh_rate="${NFT_SSH_RATE:-5}"
    local ssh_burst="${NFT_SSH_BURST:-10}"
    local conn_limit="${NFT_HTTP_CONN_LIMIT:-256}"
    local forward_policy="${NFT_FORWARD_POLICY:-drop}"
    local cdn_mode="${CDN_MODE:-off}"
    local synproxy="${SYNPROXY_ENABLED:-false}"
    local synproxy_mss="${SYNPROXY_MSS:-1460}"
    local synproxy_wscale="${SYNPROXY_WSCALE:-7}"
    local ssh_mode="${SSH_MODE:-strict}"
    local extra_tcp extra_udp allow4 allow6
    extra_tcp=$(_nft_list "${EXTRA_TCP_PORTS:-}")
    extra_udp=$(_nft_list "${EXTRA_UDP_PORTS:-}")
    allow4=$(_nft_list "${ALLOWLIST4:-}")
    allow6=$(_nft_list "${ALLOWLIST6:-}")

    # "auto" se decide sur la machine cible (deploy.sh). Ici, faute
    # d'information, on retombe sur la valeur la plus stricte.
    [[ "$forward_policy" == "auto" ]] && forward_policy="drop"

    # --- Ports ---
    _nft_require_match "$conf" '^define SSH_PORT' "define SSH_PORT" || rc=1
    sed -i "s/^define SSH_PORT   = .*/define SSH_PORT   = ${ssh_port}/"   "$conf"
    sed -i "s/^define HTTP_PORT  = .*/define HTTP_PORT  = ${http_port}/"  "$conf"
    sed -i "s/^define HTTPS_PORT = .*/define HTTPS_PORT = ${https_port}/" "$conf"

    # --- Reseaux d'administration (les deux familles) ---
    _nft_require_match "$conf" '^define ADMIN_NETS  =' "define ADMIN_NETS" || rc=1
    _nft_require_match "$conf" '^define ADMIN_NETS6 =' "define ADMIN_NETS6" || rc=1
    sed -i "s|^define ADMIN_NETS  = .*|define ADMIN_NETS  = ${admin_nets}|"   "$conf"
    sed -i "s|^define ADMIN_NETS6 = .*|define ADMIN_NETS6 = ${admin_nets6}|"  "$conf"

    # --- Rate limiting SYN per-IP (tous ports) ---
    # Ancre = le nom du set dynamique. Le commentaire de la regle est sur la
    # ligne de continuation, il ne peut donc pas servir d'ancre.
    _nft_require_match "$conf" '@syn_flood4 \{ ip saddr limit rate over' "rate limit per-IP IPv4" || rc=1
    _nft_require_match "$conf" '@syn_flood6 \{ ip6 saddr .* limit rate over' "rate limit per-IP IPv6" || rc=1
    sed -i "/@syn_flood[46]/s|limit rate over [0-9]\+/second burst [0-9]\+ packets|limit rate over ${syn_rate}/second burst ${syn_burst} packets|" "$conf"

    # --- Rate limiting SSH par IP ---
    _nft_require_match "$conf" '@ssh_meter4 \{ ip saddr limit rate [0-9]+/minute' "rate limit SSH IPv4" || rc=1
    _nft_require_match "$conf" '@ssh_meter6 \{ ip6 saddr .* limit rate [0-9]+/minute' "rate limit SSH IPv6" || rc=1
    sed -i "/@ssh_meter[46]/s|limit rate [0-9]\+/minute burst [0-9]\+ packets|limit rate ${ssh_rate}/minute burst ${ssh_burst} packets|" "$conf"

    # --- Rate limiting HTTP(S) par IP ---
    # L'ancienne limite etait globale : 50 SYN/s pour tous les visiteurs
    # reunis, qu'un seul attaquant suffisait a epuiser. Ancre = nom du set.
    _nft_require_match "$conf" '@http_meter4 \{ ip saddr limit rate over' "rate limit HTTP(S) IPv4" || rc=1
    _nft_require_match "$conf" '@http_meter6 \{ ip6 saddr .* limit rate over' "rate limit HTTP(S) IPv6" || rc=1
    sed -i "/@http_meter[46]/s|limit rate over [0-9]\+/second burst [0-9]\+ packets|limit rate over ${http_rate}/second burst ${http_burst} packets|" "$conf"

    # --- Connexions simultanees par IP (0 = desactive) ---
    _nft_require_match "$conf" '# --- CONNLIMIT BEGIN ---' "bloc CONNLIMIT" || rc=1
    _nft_require_match "$conf" '@http_conn4 \{ ip saddr ct count over' "connlimit IPv4" || rc=1
    if [[ "$conn_limit" == "0" ]]; then
        _nft_toggle_block "$conf" "CONNLIMIT" off "        "
    else
        sed -i "/@http_conn[46]/s|ct count over [0-9]\+|ct count over ${conn_limit}|" "$conf"
    fi

    # --- Politique forward ---
    _nft_require_match "$conf" 'policy [a-z]+; # @FORWARD_POLICY@' "politique forward" || rc=1
    sed -i "s|policy [a-z]\+; # @FORWARD_POLICY@|policy ${forward_policy}; # @FORWARD_POLICY@|" "$conf"

    # --- Ports supplementaires ---
    _nft_require_match "$conf" '# @EXTRA_TCP_PORTS@' "ports TCP supplementaires" || rc=1
    _nft_require_match "$conf" '# @EXTRA_UDP_PORTS@' "ports UDP supplementaires" || rc=1
    if [[ -n "$extra_tcp" ]]; then
        sed -i "s|^\([[:space:]]*\)# @EXTRA_TCP_PORTS@|\1tcp dport { ${extra_tcp} } ct state new accept comment \"EXTRA_TCP_PORTS\"|" "$conf"
    fi
    if [[ -n "$extra_udp" ]]; then
        sed -i "s|^\([[:space:]]*\)# @EXTRA_UDP_PORTS@|\1udp dport { ${extra_udp} } accept comment \"EXTRA_UDP_PORTS\"|" "$conf"
    fi

    # --- Allowlist ---
    _nft_require_match "$conf" '# @ALLOWLIST4@' "allowlist IPv4" || rc=1
    _nft_require_match "$conf" '# @ALLOWLIST6@' "allowlist IPv6" || rc=1
    if [[ -n "$allow4" ]]; then
        sed -i "s|^\([[:space:]]*\)# @ALLOWLIST4@|\1elements = { ${allow4} }|" "$conf"
    fi
    if [[ -n "$allow6" ]]; then
        sed -i "s|^\([[:space:]]*\)# @ALLOWLIST6@|\1elements = { ${allow6} }|" "$conf"
    fi

    # --- Mode CDN : HTTP(S) reserve aux plages du CDN ---
    if [[ "$cdn_mode" != "off" ]]; then
        _nft_require_match "$conf" '# --- CDN BEGIN ---' "bloc CDN" || rc=1
        _nft_toggle_block "$conf" "CDN" on "        "
    fi

    # --- Mode SSH ---
    # open   : SSH accessible a tous, limite par IP (lignes admin inutiles)
    # strict : SSH reserve a ADMIN_NETS. Les lignes "ouvertes" doivent alors
    #          etre neutralisees, sinon elles acceptent n'importe qui (a
    #          5/min) et le mode strict ne restreint rien.
    if [[ "$ssh_mode" == "open" ]]; then
        sed -i 's|^\([[:space:]]*\)tcp dport \$SSH_PORT ip  saddr \$ADMIN_NETS |\1# tcp dport $SSH_PORT ip  saddr $ADMIN_NETS |' "$conf"
        sed -i 's|^\([[:space:]]*\)tcp dport \$SSH_PORT ip6 saddr \$ADMIN_NETS6 |\1# tcp dport $SSH_PORT ip6 saddr $ADMIN_NETS6 |' "$conf"
    else
        sed -i 's|^\([[:space:]]*\)tcp dport \$SSH_PORT ct state new update @ssh_meter|\1# tcp dport $SSH_PORT ct state new update @ssh_meter|' "$conf"
    fi

    # --- SYNPROXY ---
    if [[ "$synproxy" == "true" ]]; then
        _nft_require_match "$conf" '# --- SYNPROXY PRE BEGIN ---' "bloc SYNPROXY prerouting" || rc=1
        _nft_require_match "$conf" '# --- SYNPROXY IN BEGIN ---'  "bloc SYNPROXY input" || rc=1
        # Decommenter les deux blocs, marqueurs exclus
        _nft_toggle_block "$conf" "SYNPROXY PRE" on "    "
        _nft_toggle_block "$conf" "SYNPROXY IN"  on "        "
        sed -i "s/synproxy mss [0-9]\+ wscale [0-9]\+/synproxy mss ${synproxy_mss} wscale ${synproxy_wscale}/" "$conf"
    fi

    if [[ $rc -ne 0 ]]; then
        log_error "Une ou plusieurs ancres de substitution ont disparu de $conf."
        log_error "Des valeurs de config.env n'ont donc PAS ete appliquees."
        return 1
    fi

    return 0
}
