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
    local synproxy="${SYNPROXY_ENABLED:-false}"
    local synproxy_mss="${SYNPROXY_MSS:-1460}"
    local synproxy_wscale="${SYNPROXY_WSCALE:-7}"
    local ssh_mode="${SSH_MODE:-strict}"

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

    # --- Rate limiting per-IP ---
    # Ancre = le nom du set dynamique. Le commentaire de la regle est sur la
    # ligne de continuation, il ne peut donc pas servir d'ancre.
    _nft_require_match "$conf" '@syn_flood4 \{ ip saddr limit rate over' "rate limit per-IP IPv4" || rc=1
    _nft_require_match "$conf" '@syn_flood6 \{ ip6 saddr limit rate over' "rate limit per-IP IPv6" || rc=1
    sed -i "/@syn_flood[46]/s|limit rate over [0-9]\+/second burst [0-9]\+ packets|limit rate over ${syn_rate}/second burst ${syn_burst} packets|" "$conf"

    # --- Rate limiting global HTTP(S) ---
    # Ancre = ligne COMMENCANT par "limit rate" : les limites ICMP sont
    # precedees d'une accolade fermante sur la meme ligne, elles sont donc
    # exclues par cette ancre.
    _nft_require_match "$conf" '^[[:space:]]+limit rate [0-9]+/second burst [0-9]+ packets accept' "rate limit HTTP(S) global" || rc=1
    sed -i "s|^\([[:space:]]*\)limit rate [0-9]\+/second burst [0-9]\+ packets accept|\1limit rate ${http_rate}/second burst ${http_burst} packets accept|" "$conf"

    # --- Mode SSH ---
    if [[ "$ssh_mode" == "open" ]]; then
        sed -i 's|^\([[:space:]]*\)tcp dport \$SSH_PORT ip  saddr \$ADMIN_NETS |\1# tcp dport $SSH_PORT ip  saddr $ADMIN_NETS |' "$conf"
        sed -i 's|^\([[:space:]]*\)tcp dport \$SSH_PORT ip6 saddr \$ADMIN_NETS6 |\1# tcp dport $SSH_PORT ip6 saddr $ADMIN_NETS6 |' "$conf"
    fi

    # --- SYNPROXY ---
    if [[ "$synproxy" == "true" ]]; then
        _nft_require_match "$conf" '# --- SYNPROXY PRE BEGIN ---' "bloc SYNPROXY prerouting" || rc=1
        _nft_require_match "$conf" '# --- SYNPROXY IN BEGIN ---'  "bloc SYNPROXY input" || rc=1
        # Decommenter les deux blocs, marqueurs exclus
        sed -i '/^    # --- SYNPROXY PRE BEGIN ---$/,/^    # --- SYNPROXY PRE END ---$/{/BEGIN ---$/!{/END ---$/!s/^    # /    /}}' "$conf"
        sed -i '/^        # --- SYNPROXY IN BEGIN ---$/,/^        # --- SYNPROXY IN END ---$/{/BEGIN ---$/!{/END ---$/!s/^        # /        /}}' "$conf"
        sed -i "s/synproxy mss [0-9]\+ wscale [0-9]\+/synproxy mss ${synproxy_mss} wscale ${synproxy_wscale}/" "$conf"
    fi

    if [[ $rc -ne 0 ]]; then
        log_error "Une ou plusieurs ancres de substitution ont disparu de $conf."
        log_error "Des valeurs de config.env n'ont donc PAS ete appliquees."
        return 1
    fi

    return 0
}
