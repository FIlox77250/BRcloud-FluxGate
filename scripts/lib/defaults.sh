#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Valeurs par defaut et chargement de config.env
# =============================================================================
# Source UNIQUE des valeurs par defaut. Elles etaient auparavant recopiees
# dans deploy.sh, check-config.sh, nft-template.sh et les scripts annexes :
# chaque nouvelle cle devait etre ajoutee a quatre endroits, et un oubli
# faisait diverger silencieusement ce que check-config validait de ce que
# deploy.sh appliquait.
#
# Fournit :
#   FLUXGATE_DEFAULTS        tableau associatif cle -> valeur par defaut
#   fg_get <CLE>             valeur de la variable, ou son defaut
#   fluxgate_apply_defaults  affecte le defaut a chaque cle vide ou absente
#   fluxgate_load_config <fichier>
#                            verifie proprietaire/droits puis source le
#                            fichier et applique les defauts
# =============================================================================

declare -gA FLUXGATE_DEFAULTS=(
    # Reseau
    [SSH_PORT]=22
    [HTTP_PORT]=80
    [HTTPS_PORT]=443
    [ADMIN_NETS]="{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/24 }"
    [ADMIN_NETS6]="{ fc00::/7, fe80::/10 }"
    [EXTRA_TCP_PORTS]=""
    [EXTRA_UDP_PORTS]=""
    [ALLOWLIST4]=""
    [ALLOWLIST6]=""
    [SSH_MODE]=open

    # nftables
    [NFT_SYN_RATE]=100
    [NFT_SYN_BURST]=150
    [NFT_HTTP_SYN_RATE]=50
    [NFT_HTTP_SYN_BURST]=100
    [NFT_SSH_RATE]=5
    [NFT_SSH_BURST]=10
    [NFT_HTTP_CONN_LIMIT]=256
    [NFT_FORWARD_POLICY]=auto
    [SYNPROXY_ENABLED]=false
    [SYNPROXY_MSS]=1460
    [SYNPROXY_WSCALE]=7
    [REPUTATION_LISTS]=""
    [CDN_MODE]=off
    [SHIELD_SYN_RATE]=10
    [SHIELD_SYN_BURST]=20
    [SHIELD_CONN_LIMIT]=32
    [SHIELD_DURATION]=30m

    # Noyau
    [CONNTRACK_MAX]=262144
    [CONNTRACK_BUCKETS]=65536
    [SOMAXCONN]=4096
    [TCP_MAX_SYN_BACKLOG]=8192
    [TCP_CONGESTION_CONTROL]=bbr
    [DEFAULT_QDISC]=fq

    # NGINX
    [NGINX_REQ_PER_SEC]=30
    [NGINX_BURST]=50
    [NGINX_LOGIN_BURST]=5
    [NGINX_MAX_CONN_PER_IP]=50
    [NGINX_UPSTREAM_PORT]=8080
    [NGINX_CERT_NAME]=""
    [HSTS_PRELOAD]=false
    [ALLOWED_METHODS]="GET HEAD POST OPTIONS"

    # Apache
    [APACHE_HEADER_TIMEOUT_MIN]=10
    [APACHE_HEADER_TIMEOUT_MAX]=40
    [APACHE_HEADER_MIN_RATE]=500
    [APACHE_BODY_TIMEOUT_MIN]=10
    [APACHE_BODY_TIMEOUT_MAX]=60
    [APACHE_BODY_MIN_RATE]=500
    [APACHE_MAX_REQUEST_WORKERS]=256

    # fail2ban / CrowdSec
    [F2B_SSH_MAXRETRY]=5
    [F2B_SSH_FINDTIME]=600
    [F2B_SSH_BANTIME]=3600
    [F2B_HTTP_MAXRETRY]=100
    [F2B_HTTP_FINDTIME]=60
    [F2B_HTTP_BANTIME]=600
    [F2B_USE_FLUXGATE_SETS]=true
    [CROWDSEC_LAPI_PORT]=8081

    # systemd
    [SVC_NAME]=nginx
    [SVC_CPU_QUOTA]=auto
    [SVC_MEMORY_MAX]=2G
    [SVC_MEMORY_HIGH]=1800M
    [SVC_LIMIT_NOFILE]=65536
    [SVC_MAX_CONN_PER_SOURCE]=50
    [SVC_BACKLOG]=4096
    [SVC_LISTEN_PORT]=8080

    # tc / XDP
    [TC_RATE]=1gbit
    [TC_LATENCY]=50ms
    [TC_QDISC]=auto
    [XDP_ENABLED]=false
    [XDP_BLOCK_THRESHOLD]=1000
    [XDP_BLOCK_TIMEOUT]=3600
    [XDP_SAMPLE_INTERVAL]=5
    [XDP_AUTOBLOCK]=false

    # WAF / OWASP CRS
    [CRS_VERSION]=4.29.0
    [CRS_SHA256]=1aa1c5c8fc29e532d35293bcea36bf72de61db8f6ed4716a0f91ab14552b7fed
    [CRS_GPG_FINGERPRINT]=36006F0E0BA167832158821138EEACA1AB8A6E72

    # Monitoring
    [PROMETHEUS_PORT]=9090
    [NODE_EXPORTER_PORT]=9100
    [GRAFANA_PORT]=3000
    [FLUXGATE_EXPORTER_ENABLED]=true
)

# -----------------------------------------------------------------------------
# fg_get <CLE> : valeur courante si non vide, sinon defaut
# -----------------------------------------------------------------------------
fg_get() {
    local key="$1"
    local val="${!key:-}"
    if [[ -n "$val" ]]; then
        printf '%s' "$val"
    else
        printf '%s' "${FLUXGATE_DEFAULTS[$key]:-}"
    fi
}

# -----------------------------------------------------------------------------
# fluxgate_apply_defaults : complete les cles absentes d'un ancien config.env
# -----------------------------------------------------------------------------
fluxgate_apply_defaults() {
    local key
    for key in "${!FLUXGATE_DEFAULTS[@]}"; do
        if [[ -z "${!key:-}" ]]; then
            printf -v "$key" '%s' "${FLUXGATE_DEFAULTS[$key]}"
        fi
    done
}

# -----------------------------------------------------------------------------
# fluxgate_check_config_perms <fichier>
# config.env est source en root : quiconque peut l'ecrire execute du code en
# root. On exige donc qu'il appartienne a root et ne soit modifiable par
# personne d'autre. Le controle n'a de sens qu'en root (en CI ou pour un
# check-config.sh lance en utilisateur, le fichier n'appartient pas a root).
# -----------------------------------------------------------------------------
fluxgate_check_config_perms() {
    local file="$1" owner mode
    [[ $EUID -eq 0 ]] || return 0
    owner=$(stat -c '%u' "$file" 2>/dev/null) || return 1
    mode=$(stat -c '%a' "$file" 2>/dev/null) || return 1
    if [[ "$owner" != "0" ]]; then
        echo "config.env doit appartenir a root (proprietaire actuel : uid $owner) : $file" >&2
        echo "  Corriger : chown root:root '$file' && chmod 600 '$file'" >&2
        return 1
    fi
    # Ecriture groupe ou autres : refus. Lecture : on resserre en 600, le
    # fichier peut contenir des cles (bouncer, API).
    if (( (8#$mode & 8#022) != 0 )); then
        echo "config.env est modifiable par d'autres que root (mode $mode) : $file" >&2
        echo "  Corriger : chmod 600 '$file'" >&2
        return 1
    fi
    if [[ "$mode" != "600" ]] && [[ "$mode" != "400" ]]; then
        chmod 600 "$file" 2>/dev/null || true
    fi
    return 0
}

# -----------------------------------------------------------------------------
# fluxgate_load_config <fichier>
# -----------------------------------------------------------------------------
fluxgate_load_config() {
    local file="$1"
    [[ -f "$file" ]] || { echo "config.env introuvable : $file" >&2; return 1; }
    fluxgate_check_config_perms "$file" || return 1
    # shellcheck source=/dev/null
    source "$file"
    fluxgate_apply_defaults
}
