#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Script de Deploiement Principal
# =============================================================================
# Deploie l'ensemble de la stack anti-DDoS sur le serveur.
# Execution : sudo bash scripts/deploy.sh [--dry-run] [--diff] [--yes]
#
#   --dry-run  rend le pare-feu et le sysctl dans un repertoire temporaire,
#              verifie la syntaxe nftables, puis s'arrete sans rien modifier
#   --diff     comme --dry-run, et affiche les differences avec les fichiers
#              actuellement installes
#   --yes      aucune question : les valeurs de config.env font foi. L'acces
#              SSH est alors verifie automatiquement avant d'annuler le
#              rollback (voir confirm_firewall_access)
#
# IMPORTANT : Executer UNIQUEMENT sur des systemes que vous administrez.
# Lire et adapter config.env AVANT le deploiement.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${SCRIPT_DIR}/config.env"
INSTALL_DIR="/opt/fluxgate"
STATE_DIR="/var/lib/fluxgate"
LOG_FILE="/var/log/fluxgate/deploy.log"

DRY_RUN=false
SHOW_DIFF=false
ASSUME_YES=false
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --diff)    DRY_RUN=true; SHOW_DIFF=true ;;
        --yes|-y)  ASSUME_YES=true ;;
        -h|--help)
            sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Option inconnue : $arg (voir --help)" >&2
            exit 1
            ;;
    esac
done

# En --dry-run, rien ne doit etre ecrit hors d'un repertoire temporaire, pas
# meme le journal.
if [[ "$DRY_RUN" == "true" ]]; then
    LOG_FILE="/dev/null"
fi

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE" >&2; }

# --- Fonction de sauvegarde de securite ---
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup
        backup="${file}.bak-$(date +%s)"
        cp "$file" "$backup"
        log_info "Sauvegarde de securite creee : $backup"
    fi
}

# --- Etat d'origine, pour rollback.sh ---
# Copie la version d'un fichier systeme AVANT la premiere modification par
# FluxGate (ou note son absence). Les deploiements suivants ne l'ecrasent
# pas : rollback.sh restaure ainsi l'etat d'avant FluxGate, pas celui du
# deploiement precedent.
save_original() {
    local file="$1" dest="${STATE_DIR}/orig${1}"
    [[ -e "$dest" || -e "${dest}.absent" ]] && return 0
    mkdir -p "$(dirname "$dest")"
    chmod 700 "$STATE_DIR"
    if [[ -f "$file" ]]; then
        cp -p "$file" "$dest"
    else
        touch "${dest}.absent"
    fi
}

# --- Verifications ---
if [[ $EUID -ne 0 ]]; then
    log_error "Ce script doit etre execute en root (sudo)."
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    log_error "Fichier config.env introuvable."
    log_info "Copier config.env.example vers config.env et l'adapter :"
    log_info "  cp ${SCRIPT_DIR}/config.env.example ${CONFIG_FILE}"
    exit 1
fi

# Valeurs par defaut communes (lib/defaults.sh) : une seule source pour
# deploy.sh, check-config.sh et les scripts annexes.
# shellcheck source=lib/defaults.sh
if ! source "${SCRIPT_DIR}/lib/defaults.sh"; then
    echo "lib/defaults.sh introuvable." >&2
    exit 1
fi

# config.env est source en root : un fichier modifiable par un autre compte
# equivaut a lui donner root. Verifie avant toute lecture.
if ! fluxgate_check_config_perms "$CONFIG_FILE"; then
    exit 1
fi

if [[ "$DRY_RUN" != "true" ]]; then
    mkdir -p /var/log/fluxgate "$INSTALL_DIR"
fi

# --- Validation de la configuration avant de toucher au systeme ---
# check-config.sh refuse les placeholders, les ports incoherents et les
# valeurs hors bornes : mieux vaut echouer ici qu'a mi-parcours.
if [[ -x "${SCRIPT_DIR}/check-config.sh" ]] || [[ -f "${SCRIPT_DIR}/check-config.sh" ]]; then
    if ! bash "${SCRIPT_DIR}/check-config.sh" "$CONFIG_FILE"; then
        log_error "Configuration invalide. Deploiement annule."
        exit 1
    fi
else
    log_warn "check-config.sh introuvable : validation de config.env ignoree."
fi

# Chargement + valeurs par defaut pour les cles absentes d'un config.env
# anterieur (voir migrate-config.sh pour les ajouter au fichier).
fluxgate_load_config "$CONFIG_FILE" || exit 1

# --- Detection des outils de design (Graceful Degradation) ---
HAS_FIGLET=false && command -v figlet &>/dev/null && HAS_FIGLET=true
HAS_GUM=false && command -v gum &>/dev/null && HAS_GUM=true

# Import de la barre de progression native
source "${SCRIPT_DIR}/progress_bar.sh" 2>/dev/null || true

# Import de l'installation verifiee du CRS (sha256 + signature GPG)
# shellcheck source=lib/crs.sh
source "${SCRIPT_DIR}/lib/crs.sh" 2>/dev/null || log_warn "lib/crs.sh introuvable : installation CRS indisponible."

# Import du rendu de nftables.conf a partir de config.env
# shellcheck source=lib/nft-template.sh
if ! source "${SCRIPT_DIR}/lib/nft-template.sh" 2>/dev/null; then
    log_error "lib/nft-template.sh introuvable : impossible d'appliquer config.env au pare-feu."
    exit 1
fi

# -----------------------------------------------------------------------------
# render_sysctl_conf <fichier> : applique config.env au modele sysctl
# (match par cle, jamais par valeur)
# -----------------------------------------------------------------------------
render_sysctl_conf() {
    local f="$1"
    sed -i "s|^net.netfilter.nf_conntrack_max = .*|net.netfilter.nf_conntrack_max = ${CONNTRACK_MAX}|" "$f"
    sed -i "s|^net.core.somaxconn = .*|net.core.somaxconn = ${SOMAXCONN}|" "$f"
    sed -i "s|^net.ipv4.tcp_max_syn_backlog = .*|net.ipv4.tcp_max_syn_backlog = ${TCP_MAX_SYN_BACKLOG}|" "$f"
    sed -i "s|^net.core.default_qdisc = .*|net.core.default_qdisc = ${DEFAULT_QDISC}|" "$f"
    sed -i "s|^net.ipv4.tcp_congestion_control = .*|net.ipv4.tcp_congestion_control = ${TCP_CONGESTION_CONTROL}|" "$f"
}

# -----------------------------------------------------------------------------
# resolve_forward_policy : traduit NFT_FORWARD_POLICY=auto en drop/accept
# -----------------------------------------------------------------------------
# Une politique drop sur forward est definitive pour tout le trafic route,
# meme si Docker ou libvirt l'acceptent dans leur propre table : sur une
# machine qui route, elle couperait les conteneurs et les VM.
resolve_forward_policy() {
    case "${NFT_FORWARD_POLICY:-auto}" in
        drop|accept)
            echo "$NFT_FORWARD_POLICY"
            return 0
            ;;
    esac

    local reason=""
    if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]] \
       || [[ "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)" == "1" ]]; then
        reason="routage IP actif"
    elif [[ -d /etc/pve ]]; then
        reason="Proxmox VE"
    elif ip -o link show 2>/dev/null \
         | grep -qE ': (docker0|br-[0-9a-f]+|virbr[0-9]+|lxcbr[0-9]+|lxdbr[0-9]+|vmbr[0-9]+|wg[^:@]*|cni[0-9]+|flannel[^:@]*|cali[^:@]*|tailscale[0-9]+)[:@]'; then
        reason="interface de conteneur/VM/VPN"
    fi

    if [[ -n "$reason" ]]; then
        log_info "NFT_FORWARD_POLICY=auto : accept (${reason} detecte)." >&2
        echo "accept"
    else
        echo "drop"
    fi
}

# -----------------------------------------------------------------------------
# legacy_filter_table : vrai si une table "inet filter" FluxGate <= 2.0 existe
# -----------------------------------------------------------------------------
# Le set blocklist4 sert de signature : une table "inet filter" sans lui
# appartient a un autre outil et ne doit pas etre touchee.
legacy_filter_table() {
    nft list set inet filter blocklist4 &>/dev/null
}

# -----------------------------------------------------------------------------
# self_check_ssh_access : verification automatique (mode --yes)
# -----------------------------------------------------------------------------
# Moins probante qu'une vraie connexion, mais detecte les causes de lockout
# connues : port SSH absent des regles, IP de session hors ADMIN_NETS en mode
# strict, IP de session bannie.
self_check_ssh_access() {
    local ip fam_set ruleset
    ruleset=$(nft -n list chain inet fluxgate input 2>/dev/null)
    if ! grep -qE "^[[:space:]]*tcp dport ${SSH_PORT} .*accept" <<<"$ruleset"; then
        log_error "Aucune regle active n'accepte le port SSH ${SSH_PORT}."
        return 1
    fi
    if command -v ss &>/dev/null && ! ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${SSH_PORT}\$"; then
        log_warn "Aucun service n'ecoute sur le port ${SSH_PORT} : verifier SSH_PORT."
    fi

    ip=$(echo "${SSH_CLIENT:-${SSH_CONNECTION:-}}" | awk '{print $1}')
    [[ -z "$ip" ]] && return 0
    if [[ "$ip" == *:* ]]; then fam_set=6; else fam_set=4; fi

    if nft get element inet fluxgate "allowlist${fam_set}" "{ $ip }" &>/dev/null; then
        return 0
    fi
    if nft get element inet fluxgate "blocklist${fam_set}" "{ $ip }" &>/dev/null; then
        log_error "L'IP de session ${ip} est presente dans blocklist${fam_set}."
        return 1
    fi
    if [[ "$SSH_MODE" == "strict" ]] \
       && ! nft get element inet fluxgate "admin${fam_set}" "{ $ip }" &>/dev/null; then
        log_error "Mode strict : l'IP de session ${ip} n'appartient pas a admin${fam_set}."
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# confirm_firewall_access
#   0 : acces confirme
#   1 : non confirme (delai depasse, refus, ou auto-verification en echec)
#   2 : confirmation impossible (pas de terminal)
# -----------------------------------------------------------------------------
# L'ancienne version annulait le rollback apres un simple 'sleep 3' : la
# session en cours, deja etablie, survit a la plupart des erreurs de regle,
# elle ne prouve donc rien. On exige ici une preuve venant d'une NOUVELLE
# connexion SSH : l'ecriture d'un jeton aleatoire.
confirm_firewall_access() {
    if [[ "$ASSUME_YES" == "true" ]]; then
        if self_check_ssh_access; then
            log_info "Auto-verification de l'acces SSH reussie (--yes)."
            return 0
        fi
        return 1
    fi
    [[ -t 0 ]] || return 2

    local token dir="/run/fluxgate" file waited=0 key timeout=120
    token=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
    file="${dir}/confirm"
    mkdir -p "$dir"
    chmod 700 "$dir"
    rm -f "$file"

    echo ""
    echo -e "${YELLOW}=============================================${NC}"
    echo -e "  ${BOLD}Confirmation d'acces requise${NC}"
    echo -e "${YELLOW}=============================================${NC}"
    echo "  Ouvrir une NOUVELLE session SSH vers ce serveur (port ${SSH_PORT})"
    echo "  sans fermer celle-ci, puis y executer :"
    echo ""
    echo -e "      ${BOLD}echo ${token} | sudo tee ${file}${NC}"
    echo ""
    echo "  Sans confirmation sous ${timeout} s, le pare-feu precedent est restaure."
    echo "  Touche 'r' ici : restauration immediate."
    echo ""

    while (( waited < timeout )); do
        if [[ -f "$file" ]] && grep -qx "$token" "$file" 2>/dev/null; then
            rm -f "$file"
            echo ""
            return 0
        fi
        if read -rsn1 -t 1 key 2>/dev/null; then
            if [[ "$key" == "r" ]] || [[ "$key" == "R" ]]; then
                echo ""
                return 1
            fi
        fi
        waited=$((waited + 1))
        (( waited % 10 == 0 )) && printf '\r  En attente de confirmation... %3d s restantes ' $((timeout - waited))
    done
    echo ""
    rm -f "$file"
    return 1
}

# -----------------------------------------------------------------------------
# nginx_http2_directive : vrai si nginx >= 1.25.1 ("http2 on;" remplace
# l'option "listen ... http2", devenue obsolete et source d'avertissements)
# -----------------------------------------------------------------------------
nginx_http2_directive() {
    local v
    v=$(nginx -v 2>&1 | grep -oE 'nginx/[0-9.]+' | cut -d/ -f2)
    [[ -n "$v" ]] || return 1
    [[ "$(printf '%s\n1.25.1\n' "$v" | sort -V | head -1)" == "1.25.1" ]]
}

# -----------------------------------------------------------------------------
# render_caddy_conf <fichier> <waf:true|false> : rendu du profil Caddy
# -----------------------------------------------------------------------------
# Memes reglages que NGINX : NGINX_REQ_PER_SEC + NGINX_BURST sur 10 s,
# ALLOWED_METHODS, HSTS_PRELOAD. Sans les modules WAF/ratelimit dans le
# binaire, le snippet fluxgate n'importe que la partie de base.
render_caddy_conf() {
    local f="$1" waf="$2" hsts="max-age=63072000; includeSubDomains"
    local key='{remote_host}' key_doc="adresse source de la connexion"
    [[ "$HSTS_PRELOAD" == "true" ]] && hsts+="; preload"
    # En mode CDN, nftables ne laisse entrer HTTP(S) que depuis les plages
    # du CDN : l'en-tete pose par le CDN ne peut donc pas etre forge.
    if [[ "$CDN_MODE" == "cloudflare" ]]; then
        key='{http.request.header.CF-Connecting-IP}'
        key_doc="en-tete CF-Connecting-IP (CDN_MODE=cloudflare)"
    fi
    sed -i -e "s|__HSTS__|${hsts}|" \
           -e "s|__ALLOWED_METHODS__|${ALLOWED_METHODS}|" \
           -e "s|__RATE_EVENTS__|$(( NGINX_REQ_PER_SEC * 10 + NGINX_BURST ))|" \
           -e "s|__CLIENT_KEY__|${key}|" \
           -e "s|__CLIENT_KEY_DOC__|${key_doc}|" "$f"
    if [[ "$waf" != "true" ]]; then
        sed -i '/^(fluxgate) {$/,/^}$/{/import fluxgate_waf/d}' "$f"
    fi
}

# -----------------------------------------------------------------------------
# find_le_certificate : nom du certificat Let's Encrypt a utiliser
# -----------------------------------------------------------------------------
# 'ls /etc/letsencrypt/live | head -1' renvoyait "README", le fichier
# d'explication que certbot place dans ce repertoire. On ne retient que les
# repertoires qui contiennent fullchain.pem et privkey.pem.
find_le_certificate() {
    local d name found=()
    if [[ -n "$NGINX_CERT_NAME" ]]; then
        d="/etc/letsencrypt/live/${NGINX_CERT_NAME}"
        if [[ -f "$d/fullchain.pem" ]] && [[ -f "$d/privkey.pem" ]]; then
            echo "$NGINX_CERT_NAME"
            return 0
        fi
        log_warn "NGINX_CERT_NAME=${NGINX_CERT_NAME} : certificat introuvable dans /etc/letsencrypt/live." >&2
        return 1
    fi
    for d in /etc/letsencrypt/live/*/; do
        name=$(basename "$d")
        [[ -f "${d}fullchain.pem" ]] && [[ -f "${d}privkey.pem" ]] && found+=("$name")
    done
    (( ${#found[@]} > 0 )) || return 1
    if (( ${#found[@]} > 1 )); then
        log_warn "Plusieurs certificats (${found[*]}) : utilisation de ${found[0]}. Fixer NGINX_CERT_NAME pour choisir." >&2
    fi
    echo "${found[0]}"
}

# -----------------------------------------------------------------------------
# render_nginx_conf <fichier> [certificat] : applique config.env au modele
# NGINX ; avec un nom de certificat, active aussi le bloc HTTPS
# -----------------------------------------------------------------------------
render_nginx_conf() {
    local f="$1" cert="${2:-}"
    sed -i "s/rate=[0-9]\+r\/s/rate=${NGINX_REQ_PER_SEC}r\/s/g" "$f"
    # Le burst des endpoints sensibles (lignes marquees fluxgate:login) est
    # distinct : un sed global faisait passer /api/login de 5 a 50 essais.
    sed -i "/# fluxgate:login\$/ s/burst=[0-9]\+/burst=${NGINX_LOGIN_BURST}/" "$f"
    sed -i "/# fluxgate:login\$/! s/burst=[0-9]\+/burst=${NGINX_BURST}/g" "$f"
    sed -i "s/limit_conn conn_per_ip [0-9]\+/limit_conn conn_per_ip ${NGINX_MAX_CONN_PER_IP}/g" "$f"
    sed -i "s/127\.0\.0\.1:[0-9]\+/127.0.0.1:${NGINX_UPSTREAM_PORT}/g" "$f"

    if [[ "$HSTS_PRELOAD" == "true" ]]; then
        sed -i 's/max-age=63072000; includeSubDomains"/max-age=63072000; includeSubDomains; preload"/' "$f"
    fi
    if nginx_http2_directive; then
        sed -i 's/\(listen \(\[::\]:\)\?443 ssl\) http2 /\1 /' "$f"
    else
        sed -i '/# fluxgate:http2-directive$/d' "$f"
    fi

    if [[ -n "$cert" ]]; then
        # Les lignes marqueurs restent commentees (sinon "unknown directive ---")
        sed -i '/^# --- HTTPS BEGIN ---$/,/^# --- HTTPS END ---$/{/^# --- HTTPS /!s/^# //}' "$f"
        sed -i "s|/etc/ssl/certs/fluxgate.crt|/etc/letsencrypt/live/${cert}/fullchain.pem|g" "$f"
        sed -i "s|/etc/ssl/private/fluxgate.key|/etc/letsencrypt/live/${cert}/privkey.pem|g" "$f"
    fi
}

# =============================================================================
# Mode --dry-run / --diff : rendu et verification, aucune modification
# =============================================================================
if [[ "$DRY_RUN" == "true" ]]; then
    DRY_DIR=$(mktemp -d /tmp/fluxgate-dryrun.XXXXXX)
    DRY_RC=0
    echo ""
    echo -e "${CYAN}=== FluxGate : simulation (rien ne sera modifie) ===${NC}"

    cp "$PROJECT_DIR/nftables/nftables.conf" "$DRY_DIR/nftables.conf"
    NFT_FORWARD_POLICY=$(resolve_forward_policy)
    export SSH_MODE ADMIN_NETS ADMIN_NETS6 SYNPROXY_ENABLED NFT_FORWARD_POLICY
    if render_nftables_conf "$DRY_DIR/nftables.conf"; then
        echo -e "  ${GREEN}[OK]${NC}     Rendu nftables (SSH ${SSH_MODE}, forward ${NFT_FORWARD_POLICY})"
    else
        echo -e "  ${RED}[ERREUR]${NC} Rendu nftables impossible (ancre manquante)"
        DRY_RC=1
    fi
    if command -v nft &>/dev/null; then
        if nft -c -f "$DRY_DIR/nftables.conf" 2>"$DRY_DIR/nft-check.log"; then
            echo -e "  ${GREEN}[OK]${NC}     Syntaxe nftables valide (nft -c)"
        else
            echo -e "  ${RED}[ERREUR]${NC} Syntaxe nftables invalide :"
            sed 's/^/           /' "$DRY_DIR/nft-check.log"
            DRY_RC=1
        fi
    else
        echo -e "  ${YELLOW}[WARN]${NC}   nft absent : syntaxe non verifiee"
    fi

    cp "$PROJECT_DIR/sysctl/99-fluxgate-hardening.conf" "$DRY_DIR/99-fluxgate-hardening.conf"
    render_sysctl_conf "$DRY_DIR/99-fluxgate-hardening.conf"
    echo -e "  ${GREEN}[OK]${NC}     Rendu sysctl"

    if [[ "$SSH_MODE" == "strict" ]]; then
        echo -e "  ${YELLOW}[WARN]${NC}   Mode strict : l'ajout interactif de votre IP a ADMIN_NETS n'est pas simule."
    fi

    if [[ "$SHOW_DIFF" == "true" ]]; then
        for pair in "/etc/nftables.conf:nftables.conf" \
                    "/etc/sysctl.d/99-fluxgate-hardening.conf:99-fluxgate-hardening.conf"; do
            current="${pair%%:*}"
            rendered="$DRY_DIR/${pair#*:}"
            echo ""
            echo -e "${BOLD}--- diff ${current} ---${NC}"
            if [[ -f "$current" ]]; then
                diff -u "$current" "$rendered" || true
            else
                echo "(absent : serait cree)"
            fi
        done
    fi

    echo ""
    echo "  Fichiers rendus : ${DRY_DIR}"
    echo "  Les etapes NGINX, WAF, fail2ban, CrowdSec, systemd, tc et XDP ne sont pas simulees."
    echo ""
    exit "$DRY_RC"
fi

print_banner() {
    local title="$1"
    if [[ "$HAS_FIGLET" == "true" ]]; then
        echo -e "${CYAN}"
        figlet "FluxGate" 2>/dev/null || echo "FluxGate"
        echo -e "${NC}"
        echo -e "${BOLD}=== $title ===${NC}\n"
    else
        echo ""
        echo -e "${CYAN}=============================================${NC}"
        echo -e "  BRCloud FluxGate - $title"
        echo -e "${CYAN}=============================================${NC}"
        echo ""
    fi
}

print_banner "Deploiement Anti-DDoS"

echo "Interface  : $IFACE"
echo "SSH Port   : $SSH_PORT"
echo "HTTP Port  : $HTTP_PORT"
echo "HTTPS Port : $HTTPS_PORT"
echo "XDP        : $XDP_ENABLED"
echo ""

if [[ "$ASSUME_YES" == "true" ]]; then
    log_info "--yes : deploiement sans confirmation interactive."
elif [[ "$HAS_GUM" == "true" ]]; then
    gum confirm "Continuer le deploiement ?" --default=true || { log_info "Deploiement annule."; exit 0; }
else
    read -rp "Continuer le deploiement ? (y/N) " confirm
    [[ "$confirm" =~ ^[yY]$ ]] || { log_info "Deploiement annule."; exit 0; }
fi

# =============================================================================
# 1. Copier les fichiers du projet
# =============================================================================
show_progress 1 8 "Copie des fichiers du projet..."
log_info "=== Etape 1/8 : Copie des fichiers ==="
cp -r "$PROJECT_DIR"/* "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR"/xdp/*.sh "$INSTALL_DIR"/tc/*.sh "$INSTALL_DIR"/nftables/*.sh "$INSTALL_DIR"/scripts/*.sh \
         "$INSTALL_DIR"/monitoring/exporter/*.sh "$INSTALL_DIR"/cli/fluxgate 2>/dev/null || true

# =============================================================================
# 2. Sysctl (kernel tuning)
# =============================================================================
show_progress 2 8 "Optimisation noyau (sysctl)..."
log_info "=== Etape 2/8 : Kernel tuning (sysctl) ==="

# Les cles net.netfilter.* n'existent pas tant que nf_conntrack n'est pas
# charge : sans ce modprobe, sysctl --system sort en erreur et, sous
# 'set -o pipefail', interrompt tout le deploiement a l'etape 2/8.
if ! lsmod 2>/dev/null | grep -q '^nf_conntrack'; then
    log_info "Chargement du module nf_conntrack..."
    modprobe nf_conntrack 2>/dev/null || log_warn "Impossible de charger nf_conntrack (conteneur / noyau sans module ?)."
fi
# Persister le chargement au reboot
if [[ -d /etc/modules-load.d ]]; then
    echo "nf_conntrack" > /etc/modules-load.d/fluxgate-conntrack.conf
fi

SYSCTL_CONF="/etc/sysctl.d/99-fluxgate-hardening.conf"
backup_file "$SYSCTL_CONF"
cp "$INSTALL_DIR/sysctl/99-fluxgate-hardening.conf" "$SYSCTL_CONF"

# Appliquer les valeurs de config.env
render_sysctl_conf "$SYSCTL_CONF"

# nf_conntrack_buckets n'est pas reglable via sysctl.d de maniere fiable :
# il s'ecrit dans /sys au runtime et se fixe en parametre de module au boot.
if [[ -w /sys/module/nf_conntrack/parameters/hashsize ]]; then
    echo "$CONNTRACK_BUCKETS" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null \
        && log_info "conntrack hashsize = $CONNTRACK_BUCKETS" \
        || log_warn "Impossible d'ecrire conntrack hashsize."
fi
if [[ -d /etc/modprobe.d ]]; then
    echo "options nf_conntrack hashsize=${CONNTRACK_BUCKETS}" > /etc/modprobe.d/fluxgate-conntrack.conf
fi

# BBR necessite le module tcp_bbr : le charger avant d'appliquer le sysctl,
# sinon la valeur est refusee silencieusement et on reste en cubic.
if [[ "$TCP_CONGESTION_CONTROL" == "bbr" ]]; then
    modprobe tcp_bbr 2>/dev/null || true
    if ! grep -q "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        log_warn "bbr indisponible sur ce noyau : bascule sur cubic."
        sed -i "s|^net.ipv4.tcp_congestion_control = .*|net.ipv4.tcp_congestion_control = cubic|" "$SYSCTL_CONF"
    fi
fi

# Ne pas laisser une cle inconnue tuer le deploiement : on journalise et on
# verifie le resultat reel juste apres.
if sysctl --system >>"$LOG_FILE" 2>&1; then
    log_info "Sysctl applique."
else
    log_warn "sysctl --system a signale des erreurs (cles non supportees par ce noyau)."
    log_warn "Detail dans $LOG_FILE. Verification des valeurs critiques :"
fi

for key in net.ipv4.tcp_syncookies net.core.somaxconn net.ipv4.tcp_max_syn_backlog; do
    val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    log_info "  $key = $val"
done
CC_ACTIVE=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
log_info "  net.ipv4.tcp_congestion_control = $CC_ACTIVE"

# =============================================================================
# 3. nftables
# =============================================================================
show_progress 3 8 "Pare-feu nftables (L3/L4)..."
log_info "=== Etape 3/8 : Pare-feu nftables ==="
if command -v nft &>/dev/null; then
    NFTCONF="/etc/nftables.conf"
    NFT_PREV="/etc/nftables.conf.fluxgate-prev"
    NFT_STAGE="${STATE_DIR}/nftables.rendered.conf"
    NFT_ROLLBACK="${STATE_DIR}/rollback.nft"
    NFT_ROLLBACK_SH="${STATE_DIR}/rollback-nft.sh"
    FG_STATE="${INSTALL_DIR}/nftables/fluxgate-state.sh"
    FG_LISTS="${INSTALL_DIR}/nftables/fluxgate-lists.sh"
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"

    # Rendu dans un fichier de travail : /etc/nftables.conf n'est remplace
    # qu'une fois le rendu termine et valide par 'nft -c'.
    cp "$INSTALL_DIR/nftables/nftables.conf" "$NFT_STAGE"

    # --- SYNPROXY : confirmation explicite avant activation ---
    # La valeur de config.env ne suffit pas : une erreur de parametrage rend
    # le service web injoignable, on redemande donc de vive voix (sauf
    # --yes, ou la valeur de config.env fait foi).
    if [[ "$SYNPROXY_ENABLED" == "true" ]] && [[ "$ASSUME_YES" != "true" ]]; then
        log_warn "SYNPROXY demande : delegation du handshake TCP au noyau."
        log_warn "Mal configure, SYNPROXY rend le service web injoignable."
        if [[ "$HAS_GUM" == "true" ]]; then
            gum confirm "Activer SYNPROXY sur les ports ${HTTP_PORT}/${HTTPS_PORT} ?" --default=false \
                || SYNPROXY_ENABLED=false
        else
            read -rp "Activer SYNPROXY sur les ports ${HTTP_PORT}/${HTTPS_PORT} ? (y/N) " synproxy_confirm
            [[ "$synproxy_confirm" =~ ^[yY]$ ]] || SYNPROXY_ENABLED=false
        fi
        [[ "$SYNPROXY_ENABLED" == "true" ]] \
            && log_info "SYNPROXY sera active (mss=${SYNPROXY_MSS} wscale=${SYNPROXY_WSCALE})." \
            || log_info "SYNPROXY laisse desactive."
    fi

    # --- Securite anti-lockout SSH interactive ---
    echo ""
    echo -e "${CYAN}=============================================${NC}"
    echo -e "      Securisation de l'acces SSH (Port ${SSH_PORT})"
    echo -e "${CYAN}=============================================${NC}"
    echo ""
    
    # SSH_MODE vient de config.env (defaut : open). En interactif, la
    # question ci-dessous le remplace ; avec --yes, il fait foi.
    if [[ "$ASSUME_YES" == "true" ]]; then
        log_info "Mode SSH repris de config.env (--yes) : ${SSH_MODE}"
    elif [[ "$HAS_GUM" == "true" ]]; then
        SSH_MODE="open"
        SSH_CHOICE=$(gum choose "1. Ouvert a tous (avec rate-limiting et protection Fail2ban - Recommande)" "2. Strict (Restreint uniquement a ADMIN_NETS et votre IP active)")
        if [[ "$SSH_CHOICE" == *"Strict"* ]]; then
            SSH_MODE="strict"
        fi
    else
        SSH_MODE="open"
        echo "Comment voulez-vous securiser l'acces SSH ?"
        echo "  1) Ouvert a tous avec rate-limiting par IP et Fail2ban (Recommande)"
        echo "  2) Restreint aux IP de confiance uniquement (Strict, ADMIN_NETS)"
        echo ""
        read -rp "Votre choix [1/2] (defaut: 1) : " ssh_choice_input
        if [[ "${ssh_choice_input:-1}" == "2" ]]; then
            SSH_MODE="strict"
        fi
    fi

    if [[ "$SSH_MODE" == "open" ]]; then
        log_info "Option choisie : SSH ouvert a tous avec protections. Desactivation de la restriction ADMIN_NETS."
        # Le commentaire des deux lignes admin (IPv4 + IPv6) est applique par
        # render_nftables_conf via SSH_MODE, plus bas.
    else
        log_info "Option choisie : Acces SSH strict (restreint a ADMIN_NETS)."
        # --- Securite anti-lockout SSH ---
        # Determiner l'IP de connexion active
        SSH_IP=""
        if [[ -n "${SSH_CLIENT:-}" ]] || [[ -n "${SSH_CONNECTION:-}" ]]; then
            SSH_IP=$(echo "${SSH_CLIENT:-$SSH_CONNECTION}" | awk '{print $1}')
        fi
        
        # Si non detectee automatiquement (a cause de sudo -i), demander a l'utilisateur
        if [[ -z "$SSH_IP" ]] && [[ "$ASSUME_YES" != "true" ]]; then
            log_warn "Impossible de detecter automatiquement votre IP active (variable vide)."
            if [[ "$HAS_GUM" == "true" ]]; then
                SSH_IP=$(gum input --placeholder "Veuillez saisir votre IP publique actuelle pour l'ajouter a la whitelist (ex: 203.0.113.50, laisser vide pour ignorer) : ")
            else
                read -rp "Veuillez saisir manuellement votre IP publique active pour l'ajouter a la whitelist (ex: 203.0.113.50, laisser vide pour ignorer) : " SSH_IP
            fi
        fi
        
        if [[ -n "$SSH_IP" ]]; then
            log_info "IP de l'administrateur a verifier : $SSH_IP"

            # Determiner la famille : le set et le prefixe different en IPv6.
            if [[ "$SSH_IP" == *:* ]]; then
                ADMIN_DEFINE="ADMIN_NETS6"
                ADMIN_PREFIX="128"
                CURRENT_NETS="$ADMIN_NETS6"
                log_info "Session detectee en IPv6 : whitelist ciblee sur ADMIN_NETS6."
            else
                ADMIN_DEFINE="ADMIN_NETS"
                ADMIN_PREFIX="32"
                CURRENT_NETS="$ADMIN_NETS"
            fi

            # On raisonne sur la variable de config, pas sur le fichier : le
            # fichier n'est rendu qu'une fois, apres toutes les decisions.
            NETS_CONTENT=$(echo "$CURRENT_NETS" | tr -d '{}' | tr ',' ' ')

            IS_WHITELISTED=false
            if [[ -n "$NETS_CONTENT" ]]; then
                if command -v python3 &>/dev/null; then
                    PY_NETS=$(echo "$NETS_CONTENT" | awk '{for(i=1;i<=NF;i++) printf "\"%s\", ", $i}')
                    if python3 -c "import ipaddress; ip = ipaddress.ip_address('$SSH_IP'); nets = [$PY_NETS]; print('TRUE' if any(ip in ipaddress.ip_network(n.strip()) for n in nets if n.strip()) else 'FALSE')" 2>/dev/null | grep -q "TRUE"; then
                        IS_WHITELISTED=true
                    fi
                else
                    # Repli sans python3 : comparaison exacte uniquement.
                    # Volontairement conservateur, une correspondance approximative
                    # ferait croire a tort que l'IP est protegee.
                    log_warn "python3 absent : verification d'appartenance reseau limitee a l'egalite stricte."
                    for net in $NETS_CONTENT; do
                        if [[ "$SSH_IP" == "${net%/*}" ]]; then
                            IS_WHITELISTED=true
                            break
                        fi
                    done
                fi
            fi

            if [[ "$IS_WHITELISTED" == "false" ]]; then
                log_warn "Votre IP ($SSH_IP) n'est pas whitelistee dans ${ADMIN_DEFINE}."
                ADD_IP=false
                if [[ "$ASSUME_YES" == "true" ]]; then
                    ADD_IP=true
                elif [[ "$HAS_GUM" == "true" ]]; then
                    gum confirm "Ajouter votre IP (${SSH_IP}/${ADMIN_PREFIX}) a ${ADMIN_DEFINE} ?" --default=true && ADD_IP=true
                else
                    read -rp "Ajouter votre IP (${SSH_IP}/${ADMIN_PREFIX}) a ${ADMIN_DEFINE} ? (Y/n) " add_ip
                    [[ "${add_ip:-y}" =~ ^[yY]$ ]] && ADD_IP=true
                fi

                if [[ "$ADD_IP" == "true" ]]; then
                    # Ajout en tete du set, dans la variable : le rendu du
                    # fichier a lieu ensuite et prendra la valeur a jour.
                    NEW_NETS="{ ${SSH_IP}/${ADMIN_PREFIX}, ${CURRENT_NETS#\{ }"
                    if [[ "$ADMIN_DEFINE" == "ADMIN_NETS6" ]]; then
                        ADMIN_NETS6="$NEW_NETS"
                    else
                        ADMIN_NETS="$NEW_NETS"
                    fi
                    log_info "IP ${SSH_IP}/${ADMIN_PREFIX} ajoutee a ${ADMIN_DEFINE}."
                else
                    log_warn "Continuer sans whitelister votre IP active peut couper votre connexion SSH."
                    read -rp "Etes-vous sur de vouloir continuer le deploiement ? (y/N) " force_continue
                    [[ "$force_continue" =~ ^[yY]$ ]] || { log_info "Deploiement annule."; exit 0; }
                fi
            else
                log_info "Votre IP active ($SSH_IP) est deja whitelistee dans ${ADMIN_DEFINE}."
            fi
        fi
    fi

    # --- Politique forward ---
    # "auto" : accept si la machine route du trafic (Docker, libvirt, LXC,
    # Proxmox, WireGuard...), drop sinon. Un drop dans notre chaine forward
    # est definitif meme si Docker accepte dans sa propre table.
    NFT_FORWARD_POLICY=$(resolve_forward_policy)
    log_info "Politique forward : ${NFT_FORWARD_POLICY}"

    # --- Rendu de la configuration ---
    # Toutes les decisions (ports, reseaux admin, seuils, mode SSH, SYNPROXY)
    # sont prises : on applique config.env au fichier en une seule passe.
    # render_nftables_conf echoue si une ancre a disparu du modele, ce qui
    # evite de deployer silencieusement les valeurs par defaut.
    export SSH_MODE ADMIN_NETS ADMIN_NETS6 SYNPROXY_ENABLED NFT_FORWARD_POLICY
    if ! render_nftables_conf "$NFT_STAGE"; then
        log_error "Application de config.env au pare-feu impossible."
        log_error "Le modele nftables.conf a probablement ete modifie sans mettre a jour lib/nft-template.sh."
        exit 1
    fi
    log_info "Configuration rendue : SSH=${SSH_PORT} (${SSH_MODE}), SYN ${NFT_SYN_RATE}/s, HTTP ${NFT_HTTP_SYN_RATE}/s, SSH ${NFT_SSH_RATE}/min (limites par IP, IPv6 par /64)."

    # Une syntaxe invalide est bloquante : rien n'a encore ete modifie.
    log_info "Verification de la syntaxe nftables..."
    if ! nft -c -f "$NFT_STAGE" 2>>"$LOG_FILE"; then
        log_error "Erreur de syntaxe dans le ruleset rendu :"
        nft -c -f "$NFT_STAGE" 2>&1 | tee -a "$LOG_FILE" || true
        log_error "Deploiement nftables interrompu, aucune regle appliquee."
        exit 1
    fi
    log_info "Syntaxe nftables valide."

    # --- Sauvegarde de l'etat courant ---
    # 1. Les bans en cours, avec leur temps restant (rechargement = sets vides)
    bash "$FG_STATE" save 2>&1 | tee -a "$LOG_FILE" || true

    # 2. Le fichier de restauration. Il ne recree QUE nos tables : le reste
    #    du ruleset (Docker, CrowdSec...) n'est jamais touche, ni a
    #    l'application ni au rollback. Les dumps sont "stateless" (-s) pour
    #    rester rejouables.
    {
        echo "#!/usr/sbin/nft -f"
        echo "# Rollback FluxGate du $(date '+%Y-%m-%d %H:%M:%S')"
        echo "table inet fluxgate"
        echo "delete table inet fluxgate"
        nft -s list table inet fluxgate 2>/dev/null || true
        if legacy_filter_table; then
            echo "table inet filter"
            echo "delete table inet filter"
            nft -s list table inet filter 2>/dev/null
        fi
    } > "$NFT_ROLLBACK"
    chmod 600 "$NFT_ROLLBACK"

    # 3. Le script de rollback, utilise par le job 'at' et par l'echec de
    #    confirmation. Il restaure aussi /etc/nftables.conf, sinon le
    #    prochain reboot rechargerait la configuration rejetee.
    {
        echo "#!/bin/sh"
        echo "nft -f '${NFT_ROLLBACK}'"
        if [[ -f "$NFTCONF" ]]; then
            echo "cp -f '${NFT_PREV}' '${NFTCONF}'"
        else
            echo "rm -f '${NFTCONF}'"
        fi
    } > "$NFT_ROLLBACK_SH"
    chmod 700 "$NFT_ROLLBACK_SH"

    # --- Installation du fichier ---
    save_original "$NFTCONF"
    if [[ -f "$NFTCONF" ]]; then
        backup_file "$NFTCONF"
        cp -f "$NFTCONF" "$NFT_PREV"
    fi
    install -m 600 "$NFT_STAGE" "$NFTCONF"

    # --- Filet anti-lockout : rollback automatique dans 5 minutes ---
    ROLLBACK_JOB=""
    if command -v at &>/dev/null; then
        ROLLBACK_JOB=$(echo "sh ${NFT_ROLLBACK_SH}" | at now + 5 minutes 2>&1 | grep -oP 'job \K[0-9]+') || true
    fi
    if [[ -n "$ROLLBACK_JOB" ]]; then
        log_warn "Rollback automatique programme dans 5 minutes (job $ROLLBACK_JOB)."
    else
        log_warn "'at' indisponible : pas de rollback automatique en cas de coupure."
    fi

    # --- Application ---
    # 'nft -f' remplace notre table de facon atomique. On n'utilise pas
    # 'systemctl restart nftables' : son ExecStop fait un 'flush ruleset' qui
    # efface aussi les tables de Docker, CrowdSec ou wg-quick.
    log_info "Application du ruleset FluxGate..."
    if ! nft -f "$NFTCONF" 2>>"$LOG_FILE"; then
        log_error "Echec de l'application du ruleset : restauration de l'etat precedent."
        sh "$NFT_ROLLBACK_SH" 2>>"$LOG_FILE" || true
        [[ -n "$ROLLBACK_JOB" ]] && atrm "$ROLLBACK_JOB" 2>/dev/null || true
        exit 1
    fi

    # La table "inet filter" d'une version anterieure appliquerait encore sa
    # propre politique drop en parallele : on la retire (le fichier de
    # rollback la recree au besoin). Une table "inet filter" qui n'est pas
    # la notre (pas de set blocklist4) est laissee intacte.
    if legacy_filter_table; then
        nft delete table inet filter 2>>"$LOG_FILE" \
            && log_info "Ancienne table 'inet filter' (FluxGate <= 2.0) remplacee par 'inet fluxgate'."
    fi

    # Bans sauvegardes + listes de reputation / CDN
    bash "$FG_STATE" restore 2>&1 | tee -a "$LOG_FILE" || true
    if [[ "$CDN_MODE" != "off" ]] || [[ -n "$REPUTATION_LISTS" ]]; then
        log_info "Telechargement des listes (reputation : '${REPUTATION_LISTS:-aucune}', CDN : ${CDN_MODE})..."
        bash "$FG_LISTS" update 2>&1 | tee -a "$LOG_FILE" || true
    fi
    if [[ "$CDN_MODE" != "off" ]] && ! nft list set inet fluxgate cdn4 2>/dev/null | grep -q 'elements'; then
        log_error "CDN_MODE=${CDN_MODE} mais le set cdn4 est vide : tout le trafic HTTP(S) serait rejete."
        log_error "Restauration de l'etat precedent."
        sh "$NFT_ROLLBACK_SH" 2>>"$LOG_FILE" || true
        [[ -n "$ROLLBACK_JOB" ]] && atrm "$ROLLBACK_JOB" 2>/dev/null || true
        exit 1
    fi

    # --- Confirmation depuis une NOUVELLE session SSH ---
    # Les connexions deja etablies survivent a presque toutes les erreurs de
    # regle : constater que cette session repond ne prouve rien. Seule une
    # connexion neuve prouve que l'acces SSH est toujours ouvert.
    CONFIRM_RC=0
    confirm_firewall_access || CONFIRM_RC=$?
    case "$CONFIRM_RC" in
        0)
            [[ -n "$ROLLBACK_JOB" ]] && atrm "$ROLLBACK_JOB" 2>/dev/null || true
            log_info "Acces confirme : rollback automatique annule."
            ;;
        2)
            # Pas de terminal pour confirmer : on laisse le job 'at' armer
            # le rollback plutot que de risquer un lockout silencieux.
            log_warn "Confirmation impossible (pas de terminal) : le rollback automatique reste programme."
            log_warn "Pour conserver les regles, depuis une nouvelle session : atrm ${ROLLBACK_JOB:-<job>}"
            ;;
        *)
            log_error "Acces non confirme : restauration immediate de l'etat precedent."
            sh "$NFT_ROLLBACK_SH" 2>>"$LOG_FILE" || true
            [[ -n "$ROLLBACK_JOB" ]] && atrm "$ROLLBACK_JOB" 2>/dev/null || true
            bash "$FG_STATE" restore >>"$LOG_FILE" 2>&1 || true
            log_error "Pare-feu precedent restaure. Verifier SSH_PORT, ADMIN_NETS et le mode SSH, puis relancer."
            exit 1
            ;;
    esac

    # --- Persistance au boot ---
    # Le drop-in remplace le 'flush ruleset' du ExecStop Debian par la seule
    # suppression de notre table, et fluxgate-state.service sauvegarde puis
    # restaure les bans autour de chaque arret/demarrage de nftables.
    mkdir -p /etc/systemd/system/nftables.service.d
    cp "$INSTALL_DIR/systemd/nftables.service.d/fluxgate.conf" /etc/systemd/system/nftables.service.d/fluxgate.conf
    for unit in fluxgate-state.service fluxgate-state-save.service fluxgate-state-save.timer \
                fluxgate-lists.service fluxgate-lists.timer; do
        cp "$INSTALL_DIR/systemd/${unit}" "/etc/systemd/system/${unit}"
    done
    systemctl daemon-reload
    systemctl enable nftables fluxgate-state.service fluxgate-state-save.timer 2>>"$LOG_FILE" || true
    # Demarrer uniquement si inactif : un 'start' sur un service deja actif
    # ne fait rien, un 'restart' viderait les sets.
    systemctl is-active --quiet nftables || systemctl start nftables 2>>"$LOG_FILE" || true
    systemctl start fluxgate-state.service fluxgate-state-save.timer 2>>"$LOG_FILE" || true
    if [[ "$CDN_MODE" != "off" ]] || [[ -n "$REPUTATION_LISTS" ]]; then
        systemctl enable --now fluxgate-lists.timer 2>>"$LOG_FILE" || true
    else
        systemctl disable --now fluxgate-lists.timer 2>/dev/null || true
    fi
    log_info "nftables configure, actif et persistant au reboot (bans compris)."
else
    log_warn "nft non trouve. nftables non deploye."
fi

# =============================================================================
# 4. NGINX (si installe)
# =============================================================================
show_progress 4 8 "NGINX Reverse Proxy..."
log_info "=== Etape 4/8 : NGINX reverse proxy ==="
if command -v nginx &>/dev/null; then
    mkdir -p /etc/nginx/conf.d

    # Verifier que conf.d est inclus dans le contexte http{} de nginx.conf
    if ! grep -qE 'include\s+/etc/nginx/conf\.d/' /etc/nginx/nginx.conf 2>/dev/null; then
        log_warn "conf.d/ n'est pas inclus dans nginx.conf. Copie de nginx-global.conf..."
        save_original /etc/nginx/nginx.conf
        backup_file /etc/nginx/nginx.conf
        cp "$INSTALL_DIR/nginx/nginx-global.conf" /etc/nginx/nginx.conf
    fi

    # --- Rendu dans un fichier temporaire, verifie avant installation ---
    # Le certificat est choisi d'abord : la conf HTTPS et la conf HTTP seule
    # sortent du meme rendu, ce qui evite de re-appliquer config.env a la
    # main dans le chemin de repli.
    NGX_CONF=/etc/nginx/conf.d/fluxgate.conf
    NGX_STAGE=$(mktemp)
    CERT_DOMAIN=""
    if command -v certbot &>/dev/null || [[ -d /etc/letsencrypt/live ]]; then
        CERT_DOMAIN=$(find_le_certificate) || CERT_DOMAIN=""
    fi

    backup_file "$NGX_CONF"
    cp "$INSTALL_DIR/nginx/nginx-fluxgate.conf" "$NGX_STAGE"
    render_nginx_conf "$NGX_STAGE" "$CERT_DOMAIN"
    install -m 644 "$NGX_STAGE" "$NGX_CONF"

    # Supprimer le default site s'il cree un conflit "duplicate default_server"
    if [[ -f /etc/nginx/sites-enabled/default ]]; then
        if grep -q "default_server" "$NGX_CONF" 2>/dev/null; then
            log_info "Suppression de sites-enabled/default (conflit avec fluxgate.conf)."
            rm -f /etc/nginx/sites-enabled/default
        fi
    fi

    if [[ -n "$CERT_DOMAIN" ]] && ! nginx -t &>/dev/null; then
        log_warn "Erreur de configuration HTTPS ($CERT_DOMAIN) : repli sur HTTP seul."
        nginx -t 2>&1 | tee -a "$LOG_FILE" || true
        cp "$INSTALL_DIR/nginx/nginx-fluxgate.conf" "$NGX_STAGE"
        render_nginx_conf "$NGX_STAGE"
        install -m 644 "$NGX_STAGE" "$NGX_CONF"
        CERT_DOMAIN=""
    fi
    rm -f "$NGX_STAGE"

    if nginx -t 2>&1; then
        systemctl reload nginx
        if [[ -n "$CERT_DOMAIN" ]]; then
            log_info "NGINX configure et recharge, HTTPS actif (Let's Encrypt : $CERT_DOMAIN)."
        else
            log_info "NGINX configure et recharge (HTTP seul)."
            log_info "Pour activer HTTPS : sudo certbot certonly --nginx -d votre-domaine.fr, puis relancer deploy.sh"
            log_info "(certonly : certbot ne modifie pas fluxgate.conf, que deploy.sh regenere.)"
        fi
    else
        log_error "Erreur de configuration NGINX. Verifier manuellement."
    fi

    # --- ModSecurity WAF : activer si installe ---
    if [[ -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so ]] || \
       dpkg -l libnginx-mod-http-modsecurity 2>/dev/null | grep -q "^ii"; then
        log_info "ModSecurity detecte. Activation WAF..."
        
        # --- Regles OWASP CRS : installation ou mise a jour ---
        # crs_needs_update compare la version reellement installee a la version
        # cible. L'ancienne condition ne testait que l'existence du repertoire :
        # sur un serveur deja deploye, le CRS n'etait donc jamais mis a jour.
        if crs_needs_update /etc/modsecurity/crs; then
            if install_owasp_crs /etc/modsecurity/crs; then
                log_info "OWASP CRS installe et verifie."
            else
                log_error "Installation du CRS echouee."
                if [[ -d /etc/modsecurity/crs/rules ]]; then
                    log_warn "Les regles precedentes restent en place."
                else
                    log_error "Le WAF restera sans regles."
                fi
            fi
        fi

        # Copier configs WAF
        mkdir -p /etc/modsecurity /etc/modsecurity/crs
        cp "$INSTALL_DIR/waf/modsecurity/modsecurity.conf" /etc/modsecurity/ 2>/dev/null || true
        cp "$INSTALL_DIR/waf/modsecurity/crs-setup-override.conf" /etc/modsecurity/crs/ 2>/dev/null || true
        # Methodes HTTP acceptees par le CRS (regle 911100)
        sed -i "s|setvar:'tx.allowed_methods=[^']*'|setvar:'tx.allowed_methods=${ALLOWED_METHODS}'|" /etc/modsecurity/crs/crs-setup-override.conf 2>/dev/null || true
        
        # --- Assurer la presence de unicode.mapping ---
        if [[ ! -f /etc/modsecurity/unicode.mapping ]]; then
            log_info "Recherche de unicode.mapping..."
            found_mapping=""
            for path in \
                /usr/share/modsecurity-crs/unicode.mapping \
                /usr/share/doc/modsecurity-crs/unicode.mapping \
                /usr/share/doc/libmodsecurity3/unicode.mapping \
                /usr/share/doc/security2/unicode.mapping \
                /etc/modsecurity.d/unicode.mapping \
                /var/lib/modsecurity/unicode.mapping; do
                if [[ -f "$path" ]]; then
                    found_mapping="$path"
                    break
                fi
            done

            if [[ -n "$found_mapping" ]]; then
                log_info "Copie de unicode.mapping depuis $found_mapping..."
                cp "$found_mapping" /etc/modsecurity/unicode.mapping
            else
                log_warn "unicode.mapping introuvable localement. Telechargement..."
                if command -v curl &>/dev/null; then
                    curl -sSL -o /etc/modsecurity/unicode.mapping "https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping" || true
                elif command -v wget &>/dev/null; then
                    wget -q -O /etc/modsecurity/unicode.mapping "https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping" || true
                fi
            fi

            # Si toujours absent, desactiver SecUnicodeMapFile dans modsecurity.conf pour eviter de planter Nginx
            if [[ ! -f /etc/modsecurity/unicode.mapping ]]; then
                log_warn "Impossible de recuperer unicode.mapping. Desactivation de SecUnicodeMapFile..."
                sed -i 's/^[[:space:]]*SecUnicodeMapFile/# SecUnicodeMapFile/' /etc/modsecurity/modsecurity.conf
            fi
        fi

        # Activer modsecurity dans nginx. Les directives sont inserees
        # indentees : l'ancien test '^modsecurity on;' ne les retrouvait
        # jamais, les inserait une deuxieme fois, et nginx -t echouait sur le
        # doublon ; le repli supprimait alors les deux lignes. Resultat : WAF
        # desactive un deploiement sur deux.
        if ! grep -qE '^[[:space:]]*modsecurity[[:space:]]+on;' /etc/nginx/nginx.conf 2>/dev/null; then
            save_original /etc/nginx/nginx.conf
            backup_file /etc/nginx/nginx.conf
            sed -i '0,/^[[:space:]]*http[[:space:]]*{/{/^[[:space:]]*http[[:space:]]*{/a\    modsecurity on;\n    modsecurity_rules_file /etc/modsecurity/modsecurity.conf;
}' /etc/nginx/nginx.conf
        fi
        if nginx -t 2>&1; then
            systemctl reload nginx
            log_info "ModSecurity WAF active."
        else
            log_warn "Erreur config ModSecurity. Desactivation..."
            sed -i '/modsecurity on;/d; /modsecurity_rules_file/d' /etc/nginx/nginx.conf
            nginx -t 2>&1 && systemctl reload nginx
        fi
    fi
else
    log_warn "NGINX non installe. Etape ignoree."
fi

# =============================================================================
# 5. Apache (si installe et NGINX absent)
# =============================================================================
show_progress 5 8 "Apache (alternatif)..."
log_info "=== Etape 5/8 : Apache (alternatif) ==="
if command -v apachectl &>/dev/null && ! command -v nginx &>/dev/null; then
    backup_file /etc/apache2/conf-available/fluxgate-security.conf
    backup_file /etc/httpd/conf.d/fluxgate-security.conf
    APACHE_CONF=""
    if [[ -d /etc/apache2/conf-available ]]; then
        cp "$INSTALL_DIR/apache/security-hardening.conf" /etc/apache2/conf-available/fluxgate-security.conf
        APACHE_CONF="/etc/apache2/conf-available/fluxgate-security.conf"
    elif [[ -d /etc/httpd/conf.d ]]; then
        cp "$INSTALL_DIR/apache/security-hardening.conf" /etc/httpd/conf.d/fluxgate-security.conf
        APACHE_CONF="/etc/httpd/conf.d/fluxgate-security.conf"
    fi

    # Appliquer les valeurs de config.env (jamais cablees auparavant)
    if [[ -n "$APACHE_CONF" ]]; then
        sed -i "s|^\([[:space:]]*\)RequestReadTimeout .*|\1RequestReadTimeout header=${APACHE_HEADER_TIMEOUT_MIN}-${APACHE_HEADER_TIMEOUT_MAX},MinRate=${APACHE_HEADER_MIN_RATE} body=${APACHE_BODY_TIMEOUT_MIN}-${APACHE_BODY_TIMEOUT_MAX},MinRate=${APACHE_BODY_MIN_RATE}|" "$APACHE_CONF"
        sed -i "s|^\([[:space:]]*\)MaxRequestWorkers .*|\1MaxRequestWorkers ${APACHE_MAX_REQUEST_WORKERS}|" "$APACHE_CONF"
        log_info "Timeouts Apache appliques (header ${APACHE_HEADER_TIMEOUT_MIN}-${APACHE_HEADER_TIMEOUT_MAX}, body ${APACHE_BODY_TIMEOUT_MIN}-${APACHE_BODY_TIMEOUT_MAX})."
    fi

    a2enmod reqtimeout headers rewrite 2>/dev/null || true
    a2enconf fluxgate-security 2>/dev/null || true

    if apachectl configtest 2>&1; then
        systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null || true
        log_info "Apache configure."
    else
        log_error "Erreur de configuration Apache."
    fi
else
    log_info "Apache non deploye (NGINX present ou Apache non installe)."
fi

# --- Caddy (si installe et NGINX absent) ---
# Le Caddyfile de l'utilisateur n'est pas modifie : seuls des snippets sont
# installes, a importer dans les sites (voir caddy/fluxgate.caddy).
if command -v caddy &>/dev/null && ! command -v nginx &>/dev/null; then
    log_info "Caddy detecte : profil FluxGate."
    CADDY_WAF=false
    if caddy list-modules 2>/dev/null | grep -qx 'http.handlers.waf' \
       && caddy list-modules 2>/dev/null | grep -qx 'http.handlers.rate_limit'; then
        CADDY_WAF=true
    fi
    CADDY_TMP=$(mktemp -d)
    cp "$INSTALL_DIR/caddy/fluxgate.caddy" "$CADDY_TMP/fluxgate.caddy"
    render_caddy_conf "$CADDY_TMP/fluxgate.caddy" "$CADDY_WAF"
    # Validation sur un site factice avant d'installer quoi que ce soit
    printf 'import %s\n\n:65080 {\n\timport fluxgate\n\trespond "ok"\n}\n' \
        "$CADDY_TMP/fluxgate.caddy" > "$CADDY_TMP/Caddyfile"
    if caddy validate --adapter caddyfile --config "$CADDY_TMP/Caddyfile" >"$CADDY_TMP/validate.log" 2>&1; then
        save_original /etc/caddy/fluxgate.caddy
        install -m 644 "$CADDY_TMP/fluxgate.caddy" /etc/caddy/fluxgate.caddy
        install -d -m 755 -o caddy -g caddy /var/log/caddy 2>/dev/null || mkdir -p /var/log/caddy
        log_info "Snippets installes : /etc/caddy/fluxgate.caddy"
        if [[ "$CADDY_WAF" == "true" ]]; then
            log_info "  WAF Coraza + OWASP CRS et limite de debit actifs dans 'import fluxgate'."
        else
            log_warn "  Binaire Caddy sans Coraza ni caddy-ratelimit : en-tetes et methodes seulement."
            log_warn "  Pour le WAF et la limite de debit : sudo bash $INSTALL_DIR/caddy/build-caddy.sh"
        fi
        if grep -qs 'fluxgate.caddy' /etc/caddy/Caddyfile; then
            if caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile &>>"$LOG_FILE"; then
                systemctl reload caddy 2>/dev/null || true
            else
                log_error "Caddyfile invalide avec les nouveaux snippets (Caddy non recharge) : voir $LOG_FILE"
            fi
        else
            log_warn "  A ajouter dans /etc/caddy/Caddyfile : 'import /etc/caddy/fluxgate.caddy'"
            log_warn "  puis 'import fluxgate' dans chaque site, et : systemctl reload caddy"
        fi
    else
        log_error "Profil Caddy invalide, non installe :"
        sed 's/^/    /' "$CADDY_TMP/validate.log" | tail -5 | tee -a "$LOG_FILE"
    fi
    rm -rf "$CADDY_TMP"
fi

# =============================================================================
# 6. fail2ban
# =============================================================================
show_progress 6 8 "fail2ban (Analyse logs)..."
log_info "=== Etape 6/8 : fail2ban ==="
if command -v fail2ban-client &>/dev/null; then
    mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/filter.d
    
    # Backup des anciennes configs fail2ban si elles existent
    for f in "$INSTALL_DIR/fail2ban/jail.d/"*.conf; do
        backup_file "/etc/fail2ban/jail.d/$(basename "$f")"
    done
    for f in "$INSTALL_DIR/fail2ban/filter.d/"*.conf; do
        backup_file "/etc/fail2ban/filter.d/$(basename "$f")"
    done
    
    cp "$INSTALL_DIR/fail2ban/filter.d/"*.conf /etc/fail2ban/filter.d/

    # Copier SSH jail (toujours actif)
    cp "$INSTALL_DIR/fail2ban/jail.d/fluxgate-sshd.conf" /etc/fail2ban/jail.d/

    # Copier NGINX jail uniquement si NGINX est installe
    if command -v nginx &>/dev/null; then
        cp "$INSTALL_DIR/fail2ban/jail.d/fluxgate-nginx.conf" /etc/fail2ban/jail.d/
        mkdir -p /var/log/nginx
        touch /var/log/nginx/access.log /var/log/nginx/error.log
    else
        rm -f /etc/fail2ban/jail.d/fluxgate-nginx.conf
    fi

    # Copier Apache jail uniquement si Apache est installe
    if command -v apachectl &>/dev/null || command -v httpd &>/dev/null; then
        cp "$INSTALL_DIR/fail2ban/jail.d/fluxgate-apache.conf" /etc/fail2ban/jail.d/
        mkdir -p /var/log/apache2
        touch /var/log/apache2/access-timing.log /var/log/apache2/error.log
    else
        rm -f /etc/fail2ban/jail.d/fluxgate-apache.conf
    fi

    # Adapter les valeurs SSH (match par cle, pas par valeur)
    sed -i "s/^maxretry = .*/maxretry = ${F2B_SSH_MAXRETRY}/" /etc/fail2ban/jail.d/fluxgate-sshd.conf
    sed -i "s/^findtime = .*/findtime = ${F2B_SSH_FINDTIME}/" /etc/fail2ban/jail.d/fluxgate-sshd.conf
    sed -i "s/^bantime  = .*/bantime  = ${F2B_SSH_BANTIME}/" /etc/fail2ban/jail.d/fluxgate-sshd.conf

    # Le port SSH declare doit figurer dans la jail, sinon les actions qui
    # raisonnent par port (autres que allports) visent le mauvais service.
    sed -i "s/^port     = ssh$/port     = ${SSH_PORT}/" /etc/fail2ban/jail.d/fluxgate-sshd.conf

    # backend = systemd exige python3-systemd. Sans lui, on lit auth.log s'il
    # existe ; sinon la jail ne pourrait pas demarrer et entrainerait fail2ban.
    if ! python3 -c 'import systemd.journal' &>/dev/null; then
        if [[ -s /var/log/auth.log ]] || [[ -s /var/log/secure ]]; then
            log_warn "python3-systemd absent : la jail sshd lit les fichiers de log (apt install python3-systemd recommande)."
            sed -i 's/^backend  = systemd$/backend  = auto\nlogpath  = %(sshd_log)s/' /etc/fail2ban/jail.d/fluxgate-sshd.conf
        else
            log_error "python3-systemd absent et aucun auth.log : la jail sshd ne peut pas demarrer."
            log_error "Installer python3-systemd (apt install python3-systemd) puis relancer."
            sed -i 's/^enabled  = true$/enabled  = false/' /etc/fail2ban/jail.d/fluxgate-sshd.conf
        fi
    fi

    # --- Reseaux jamais bannis : ADMIN_NETS et allowlists ---
    # Sans cela, quelques erreurs de mot de passe depuis le poste
    # d'administration suffisaient a s'enfermer dehors pendant F2B_SSH_BANTIME.
    F2B_IGNORE=$(echo "127.0.0.1/8 ::1 ${ADMIN_NETS} ${ADMIN_NETS6} ${ALLOWLIST4} ${ALLOWLIST6}" | tr -d '{},' | xargs)
    backup_file /etc/fail2ban/jail.d/00-fluxgate-ignoreip.conf
    cat > /etc/fail2ban/jail.d/00-fluxgate-ignoreip.conf <<EOF_F2B
# Genere par FluxGate deploy.sh depuis ADMIN_NETS, ADMIN_NETS6, ALLOWLIST4 et
# ALLOWLIST6 (config.env) : ne pas modifier, relancer deploy.sh.
[DEFAULT]
ignoreip = ${F2B_IGNORE}
EOF_F2B
    log_info "fail2ban ignore : ${F2B_IGNORE}"

    # --- Seuils HTTP (jail principale nginx-4xx / apache-4xx) ---
    # Ces valeurs n'etaient jusqu'ici jamais appliquees depuis config.env.
    # On ne touche que la premiere jail de chaque fichier : les jails
    # limit-req et botsearch gardent leurs seuils propres, plus agressifs.
    for jail_file in /etc/fail2ban/jail.d/fluxgate-nginx.conf /etc/fail2ban/jail.d/fluxgate-apache.conf; do
        [[ -f "$jail_file" ]] || continue
        sed -i "0,/^maxretry = .*/s//maxretry = ${F2B_HTTP_MAXRETRY}/" "$jail_file"
        sed -i "0,/^findtime = .*/s//findtime = ${F2B_HTTP_FINDTIME}/" "$jail_file"
        sed -i "0,/^bantime  = .*/s//bantime  = ${F2B_HTTP_BANTIME}/" "$jail_file"
        log_info "Seuils HTTP appliques a $(basename "$jail_file")."
    done

    # --- Action de ban : sets FluxGate plutot que table f2b separee ---
    if [[ "$F2B_USE_FLUXGATE_SETS" == "true" ]] && [[ -f "$INSTALL_DIR/fail2ban/action.d/fluxgate-nft.conf" ]]; then
        mkdir -p /etc/fail2ban/action.d
        cp "$INSTALL_DIR/fail2ban/action.d/fluxgate-nft.conf" /etc/fail2ban/action.d/
        # Rediriger toutes les jails FluxGate vers cette action
        sed -i "s/^banaction = nftables\[type=allports\]$/banaction = fluxgate-nft/" /etc/fail2ban/jail.d/fluxgate-*.conf
        log_info "fail2ban bannira dans les sets FluxGate (blocklist4, blocklist6net : IPv6 par /64)."
        log_info "  Consultation : bash $INSTALL_DIR/nftables/nft-manage.sh list-blocked"
    else
        log_info "fail2ban conserve l'action nftables standard (table f2b dediee)."
    fi

    log_info "Redemarrage du service fail2ban..."
    systemctl enable fail2ban 2>/dev/null || true
    if systemctl restart fail2ban 2>/dev/null; then
        log_info "Service fail2ban configure, active et redemarre avec succes."
    else
        log_error "Echec du redemarrage du service fail2ban !"
        log_info "=== Logs recents de fail2ban ==="
        journalctl -n 20 -u fail2ban --no-pager || true
        log_info "=== Statut de fail2ban ==="
        systemctl status fail2ban --no-pager || true
        log_info "=== Logs internes de fail2ban (/var/log/fail2ban.log) ==="
        tail -n 20 /var/log/fail2ban.log 2>/dev/null || true
    fi
else
    log_warn "fail2ban non installe."
fi

# =============================================================================
# 7. CrowdSec (si installe)
# =============================================================================
show_progress 7 8 "CrowdSec (Reputation)..."
log_info "=== Etape 7/8 : CrowdSec ==="
if command -v cscli &>/dev/null; then
    mkdir -p /etc/crowdsec/acquis.d
    cp "$INSTALL_DIR/crowdsec/acquis.yaml" /etc/crowdsec/acquis.d/fluxgate.yaml 2>/dev/null || true

    # Profil Caddy : sans la collection, le journal JSON de Caddy est lu
    # mais aucun parseur ne le comprend.
    if command -v caddy &>/dev/null && ! command -v nginx &>/dev/null; then
        if cscli collections install crowdsecurity/caddy &>>"$LOG_FILE"; then
            log_info "Collection CrowdSec crowdsecurity/caddy installee."
        else
            log_warn "Collection crowdsecurity/caddy non installee (hub injoignable ?) : cscli collections install crowdsecurity/caddy"
        fi
    fi

    # --- LAPI hors du port de l'application ---
    # CrowdSec ecoute par defaut sur 127.0.0.1:8080, le port de l'upstream
    # NGINX : le premier des deux a demarrer prenait le port, l'autre
    # echouait. Seule la valeur par defaut est remplacee : un port deja
    # personnalise est laisse tel quel.
    for cs_file in /etc/crowdsec/config.yaml /etc/crowdsec/local_api_credentials.yaml \
                   /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml; do
        [[ -f "$cs_file" ]] || continue
        if grep -qE '127\.0\.0\.1:8080\b|localhost:8080\b' "$cs_file"; then
            save_original "$cs_file"
            backup_file "$cs_file"
            sed -i -E "s#(127\.0\.0\.1|localhost):8080\b#\1:${CROWDSEC_LAPI_PORT}#g" "$cs_file"
            log_info "CrowdSec LAPI : port ${CROWDSEC_LAPI_PORT} dans $(basename "$cs_file")."
        fi
    done

    systemctl restart crowdsec 2>/dev/null || true
    if systemctl list-unit-files crowdsec-firewall-bouncer.service &>/dev/null; then
        systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true
    fi
    log_info "CrowdSec configure (SSH lu depuis le journal systemd)."
    log_warn "Configurer le bouncer firewall manuellement (cle API requise)."
else
    log_warn "CrowdSec non installe."
fi

# =============================================================================
# 8. systemd resource control
# =============================================================================
show_progress 8 8 "systemd resource control (Fini !)"
log_info "=== Etape 8/8 : systemd resource control ==="

# L'ancienne version copiait le dossier 'fluxgate-web.service.d' tel quel dans
# /etc/systemd/system/ : systemd n'applique un drop-in que s'il est place dans
# <nom-du-service>.service.d/, donc les limites n'etaient appliquees a rien.
# On cible desormais le service reel indique par SVC_NAME.
if systemctl list-unit-files "${SVC_NAME}.service" &>/dev/null && \
   systemctl cat "${SVC_NAME}.service" &>/dev/null; then

    DROPIN_DIR="/etc/systemd/system/${SVC_NAME}.service.d"
    mkdir -p "$DROPIN_DIR"
    backup_file "${DROPIN_DIR}/fluxgate-resource-limits.conf"
    cp "$INSTALL_DIR/systemd/fluxgate-web.service.d/resource-limits.conf" \
       "${DROPIN_DIR}/fluxgate-resource-limits.conf"

    DROPIN="${DROPIN_DIR}/fluxgate-resource-limits.conf"
    # CPUQuota se compte en % d'UN coeur : "auto" = 80% de chaque coeur.
    # "none" retire le plafond (CPUWeight seul arbitre alors en cas de
    # contention, sans jamais brider un service seul sur la machine).
    case "$SVC_CPU_QUOTA" in
        auto) CPU_QUOTA_VALUE="$(( $(nproc 2>/dev/null || echo 1) * 80 ))%" ;;
        none) CPU_QUOTA_VALUE="" ;;
        *)    CPU_QUOTA_VALUE="$SVC_CPU_QUOTA" ;;
    esac
    sed -i "s/^CPUQuota=.*/CPUQuota=${CPU_QUOTA_VALUE}/"      "$DROPIN"
    sed -i "s/^MemoryMax=.*/MemoryMax=${SVC_MEMORY_MAX}/"     "$DROPIN"
    sed -i "s/^MemoryHigh=.*/MemoryHigh=${SVC_MEMORY_HIGH}/"  "$DROPIN"
    sed -i "s/^LimitNOFILE=.*/LimitNOFILE=${SVC_LIMIT_NOFILE}/" "$DROPIN"

    # ProtectSystem=strict casse les serveurs web qui ecrivent leurs logs et
    # leur cache hors /var/log : on ne l'impose pas a un service existant
    # dont on ne connait pas les chemins.
    sed -i "s/^ProtectSystem=strict/ProtectSystem=full/" "$DROPIN"

    systemctl daemon-reload
    log_info "Limites appliquees a ${SVC_NAME}.service : CPU=${CPU_QUOTA_VALUE:-illimite}, RAM=${SVC_MEMORY_MAX}, NOFILE=${SVC_LIMIT_NOFILE}"
    log_info "Actives au prochain redemarrage : systemctl restart ${SVC_NAME}"

    if systemctl show "${SVC_NAME}.service" -p CPUQuotaPerSecUSec --value 2>/dev/null | grep -qv "infinity"; then
        log_info "Drop-in pris en compte par systemd."
    fi
else
    log_warn "Service '${SVC_NAME}' introuvable : limites de ressources non appliquees."
    log_warn "Renseigner SVC_NAME dans config.env avec un service existant (ex: nginx, apache2)."
    # Le template reste disponible pour une application manuelle
    mkdir -p /etc/systemd/system/fluxgate-web.service.d
    cp "$INSTALL_DIR/systemd/fluxgate-web.service.d/resource-limits.conf" \
       /etc/systemd/system/fluxgate-web.service.d/ 2>/dev/null || true
    log_info "Template laisse dans /etc/systemd/system/fluxgate-web.service.d/"
fi

# Socket d'activation : template, adapte mais volontairement pas active.
# L'activer d'office detournerait le port d'un service applicatif existant.
if [[ -f "$INSTALL_DIR/systemd/fluxgate-app.socket" ]]; then
    cp "$INSTALL_DIR/systemd/fluxgate-app.socket" /etc/systemd/system/
    sed -i "s/^ListenStream=.*/ListenStream=${SVC_LISTEN_PORT}/"                     /etc/systemd/system/fluxgate-app.socket
    sed -i "s/^MaxConnectionsPerSource=.*/MaxConnectionsPerSource=${SVC_MAX_CONN_PER_SOURCE}/" /etc/systemd/system/fluxgate-app.socket
    sed -i "s/^Backlog=.*/Backlog=${SVC_BACKLOG}/"                                   /etc/systemd/system/fluxgate-app.socket
    log_info "Socket template configure (port ${SVC_LISTEN_PORT}, ${SVC_MAX_CONN_PER_SOURCE} conn/IP), non active."
fi

cp "$INSTALL_DIR/systemd/fluxgate-xdp.service" "$INSTALL_DIR/systemd/fluxgate-xdp-autoblock.service" \
   /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload

# =============================================================================
# XDP (optionnel)
# =============================================================================
# fluxgate-xdp.service rattache le programme et rejoue les bans au boot ;
# l'auto-block n'est lance que sur demande (XDP_AUTOBLOCK=true).
if [[ "${XDP_ENABLED}" == "true" ]]; then
    log_info "=== Option : XDP ==="
    if command -v xdp-filter &>/dev/null; then
        systemctl enable --now fluxgate-xdp.service
        log_info "XDP active sur $IFACE (persistant au reboot)."
        if [[ "${XDP_AUTOBLOCK}" == "true" ]]; then
            systemctl enable --now fluxgate-xdp-autoblock.service
            log_info "Auto-block XDP actif (seuil ${XDP_BLOCK_THRESHOLD} conn/IP, ban ${XDP_BLOCK_TIMEOUT}s)."
        fi
    else
        log_warn "xdp-filter non disponible."
    fi
else
    systemctl disable --now fluxgate-xdp-autoblock.service fluxgate-xdp.service &>/dev/null || true
fi

# =============================================================================
# Outils d'exploitation : commande fluxgate, logrotate, metriques
# =============================================================================
log_info "=== Outils d'exploitation ==="
ln -sfn "$INSTALL_DIR/cli/fluxgate" /usr/local/sbin/fluxgate
log_info "Commande installee : fluxgate (menu interactif, ou 'fluxgate help')."
if ! command -v gum &>/dev/null && ! command -v whiptail &>/dev/null; then
    log_info "  gum ou whiptail absents : le menu sera en mode texte."
fi

if [[ -d /etc/logrotate.d ]]; then
    install -m 644 "$INSTALL_DIR/logrotate/fluxgate" /etc/logrotate.d/fluxgate
    log_info "Rotation des journaux : /etc/logrotate.d/fluxgate"
else
    log_warn "logrotate absent : /var/log/fluxgate et l'audit ModSecurity ne seront pas tournes."
fi

cp "$INSTALL_DIR/systemd/fluxgate-exporter.service" "$INSTALL_DIR/systemd/fluxgate-exporter.timer" \
   /etc/systemd/system/
systemctl daemon-reload
if [[ "${FLUXGATE_EXPORTER_ENABLED}" == "true" ]]; then
    systemctl enable --now fluxgate-exporter.timer 2>>"$LOG_FILE" || true
    log_info "Metriques FluxGate : /var/lib/prometheus/node-exporter/fluxgate.prom (chaque minute)."
    if ! systemctl list-unit-files 2>/dev/null | grep -q '^prometheus-node-exporter'; then
        log_warn "  node_exporter non detecte : installer prometheus-node-exporter pour les exposer."
    fi
else
    systemctl disable --now fluxgate-exporter.timer &>/dev/null || true
    rm -f /var/lib/prometheus/node-exporter/fluxgate.prom
fi

# =============================================================================
# Resume
# =============================================================================
echo ""
echo "============================================="
echo "  Deploiement termine !"
echo "============================================="
echo ""
log_info "Fichiers installes dans : $INSTALL_DIR"
log_info "Logs dans : /var/log/fluxgate/"
log_info ""
log_info "Prochaines etapes :"
log_info "  1. Verifier : sudo fluxgate validate"
log_info "  2. Adapter les services systemd selon votre application"
log_info "  3. Monitoring : monitoring/prometheus, monitoring/alertmanager (Discord), Grafana"
log_info "  4. Tester avec une montee en charge controlee"
echo ""
