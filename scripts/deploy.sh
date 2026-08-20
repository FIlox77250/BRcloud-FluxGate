#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Script de Deploiement Principal
# =============================================================================
# Deploie l'ensemble de la stack anti-DDoS sur le serveur.
# Execution : sudo bash scripts/deploy.sh
#
# IMPORTANT : Executer UNIQUEMENT sur des systemes que vous administrez.
# Lire et adapter config.env AVANT le deploiement.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${SCRIPT_DIR}/config.env"
INSTALL_DIR="/opt/fluxgate"
LOG_FILE="/var/log/fluxgate/deploy.log"

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

mkdir -p /var/log/fluxgate "$INSTALL_DIR"

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

# shellcheck source=/dev/null
source "$CONFIG_FILE"

# --- Valeurs par defaut pour les options ajoutees en v2.0 ---
# Permet de reutiliser un config.env issu d'une version anterieure sans le
# reecrire entierement : les nouvelles cles prennent une valeur sure.
ADMIN_NETS="${ADMIN_NETS:-{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/24 \}}"
ADMIN_NETS6="${ADMIN_NETS6:-{ fc00::/7, fe80::/10 \}}"
NFT_SYN_RATE="${NFT_SYN_RATE:-100}"
NFT_SYN_BURST="${NFT_SYN_BURST:-150}"
NFT_HTTP_SYN_RATE="${NFT_HTTP_SYN_RATE:-50}"
NFT_HTTP_SYN_BURST="${NFT_HTTP_SYN_BURST:-100}"
SYNPROXY_ENABLED="${SYNPROXY_ENABLED:-false}"
SYNPROXY_MSS="${SYNPROXY_MSS:-1460}"
SYNPROXY_WSCALE="${SYNPROXY_WSCALE:-7}"
CONNTRACK_MAX="${CONNTRACK_MAX:-262144}"
CONNTRACK_BUCKETS="${CONNTRACK_BUCKETS:-65536}"
SOMAXCONN="${SOMAXCONN:-4096}"
TCP_MAX_SYN_BACKLOG="${TCP_MAX_SYN_BACKLOG:-8192}"
TCP_CONGESTION_CONTROL="${TCP_CONGESTION_CONTROL:-bbr}"
DEFAULT_QDISC="${DEFAULT_QDISC:-fq}"
F2B_HTTP_MAXRETRY="${F2B_HTTP_MAXRETRY:-100}"
F2B_HTTP_FINDTIME="${F2B_HTTP_FINDTIME:-60}"
F2B_HTTP_BANTIME="${F2B_HTTP_BANTIME:-600}"
F2B_USE_FLUXGATE_SETS="${F2B_USE_FLUXGATE_SETS:-true}"
SVC_NAME="${SVC_NAME:-nginx}"
SVC_CPU_QUOTA="${SVC_CPU_QUOTA:-80%}"
SVC_MEMORY_MAX="${SVC_MEMORY_MAX:-2G}"
SVC_MEMORY_HIGH="${SVC_MEMORY_HIGH:-1800M}"
SVC_LIMIT_NOFILE="${SVC_LIMIT_NOFILE:-65536}"
SVC_MAX_CONN_PER_SOURCE="${SVC_MAX_CONN_PER_SOURCE:-50}"
SVC_BACKLOG="${SVC_BACKLOG:-4096}"
SVC_LISTEN_PORT="${SVC_LISTEN_PORT:-8080}"
APACHE_HEADER_TIMEOUT_MIN="${APACHE_HEADER_TIMEOUT_MIN:-10}"
APACHE_HEADER_TIMEOUT_MAX="${APACHE_HEADER_TIMEOUT_MAX:-40}"
APACHE_HEADER_MIN_RATE="${APACHE_HEADER_MIN_RATE:-500}"
APACHE_BODY_TIMEOUT_MIN="${APACHE_BODY_TIMEOUT_MIN:-10}"
APACHE_BODY_TIMEOUT_MAX="${APACHE_BODY_TIMEOUT_MAX:-60}"
APACHE_BODY_MIN_RATE="${APACHE_BODY_MIN_RATE:-500}"
APACHE_MAX_REQUEST_WORKERS="${APACHE_MAX_REQUEST_WORKERS:-256}"

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

if [[ "$HAS_GUM" == "true" ]]; then
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
chmod +x "$INSTALL_DIR"/xdp/*.sh "$INSTALL_DIR"/tc/*.sh "$INSTALL_DIR"/nftables/*.sh "$INSTALL_DIR"/scripts/*.sh 2>/dev/null || true

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

# Appliquer les valeurs de config.env (match par cle, jamais par valeur)
sed -i "s|^net.netfilter.nf_conntrack_max = .*|net.netfilter.nf_conntrack_max = ${CONNTRACK_MAX}|" "$SYSCTL_CONF"
sed -i "s|^net.core.somaxconn = .*|net.core.somaxconn = ${SOMAXCONN}|" "$SYSCTL_CONF"
sed -i "s|^net.ipv4.tcp_max_syn_backlog = .*|net.ipv4.tcp_max_syn_backlog = ${TCP_MAX_SYN_BACKLOG}|" "$SYSCTL_CONF"
sed -i "s|^net.core.default_qdisc = .*|net.core.default_qdisc = ${DEFAULT_QDISC}|" "$SYSCTL_CONF"
sed -i "s|^net.ipv4.tcp_congestion_control = .*|net.ipv4.tcp_congestion_control = ${TCP_CONGESTION_CONTROL}|" "$SYSCTL_CONF"

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
    # Substituer les variables dans la config
    NFTCONF="/etc/nftables.conf"
    backup_file "$NFTCONF"
    cp "$INSTALL_DIR/nftables/nftables.conf" "$NFTCONF"

    # --- SYNPROXY : confirmation explicite avant activation ---
    # La valeur de config.env ne suffit pas : une erreur de parametrage rend
    # le service web injoignable, on redemande donc de vive voix.
    if [[ "$SYNPROXY_ENABLED" == "true" ]]; then
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
    
    SSH_MODE="open"
    if [[ "$HAS_GUM" == "true" ]]; then
        SSH_CHOICE=$(gum choose "1. Ouvert a tous (avec rate-limiting et protection Fail2ban - Recommande)" "2. Strict (Restreint uniquement a ADMIN_NETS et votre IP active)")
        if [[ "$SSH_CHOICE" == *"Strict"* ]]; then
            SSH_MODE="strict"
        fi
    else
        echo "Comment voulez-vous securiser l'acces SSH ?"
        echo "  1) Ouvert a tous avec rate-limiting et Fail2ban (Recommande, 0% risque lockout)"
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
        if [[ -z "$SSH_IP" ]]; then
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
                if [[ "$HAS_GUM" == "true" ]]; then
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

    # --- Rendu de la configuration ---
    # Toutes les decisions (ports, reseaux admin, seuils, mode SSH, SYNPROXY)
    # sont prises : on applique config.env au fichier en une seule passe.
    # render_nftables_conf echoue si une ancre a disparu du modele, ce qui
    # evite de deployer silencieusement les valeurs par defaut.
    export SSH_MODE ADMIN_NETS ADMIN_NETS6 SYNPROXY_ENABLED
    if ! render_nftables_conf "$NFTCONF"; then
        log_error "Application de config.env dans $NFTCONF impossible."
        log_error "Le modele nftables.conf a probablement ete modifie sans mettre a jour lib/nft-template.sh."
        exit 1
    fi
    log_info "Configuration appliquee : SSH=${SSH_PORT} (${SSH_MODE}), ${NFT_SYN_RATE}/s par IP, ${NFT_HTTP_SYN_RATE}/s global HTTP(S)."

    # Backup des regles actuelles avant application.
    # 'nft list ruleset' produit un dump SANS 'flush ruleset' en tete : le
    # rejouer tel quel empile les regles sur celles deja en place au lieu de
    # restaurer l'etat d'origine. On prefixe donc le flush nous-memes, sinon
    # le filet anti-lockout ne rend pas la main comme prevu.
    NFT_BACKUP="/etc/nftables.conf.bak"
    {
        echo "#!/usr/sbin/nft -f"
        echo "# Backup FluxGate du $(date '+%Y-%m-%d %H:%M:%S') - restaurable tel quel"
        echo "flush ruleset"
        nft list ruleset 2>/dev/null || true
    } > "$NFT_BACKUP"
    chmod 600 "$NFT_BACKUP"
    log_info "Backup nftables sauvegarde dans $NFT_BACKUP (avec flush prealable)."

    # Programmer un rollback automatique dans 5 minutes (filet anti-lockout SSH)
    ROLLBACK_JOB=""
    if command -v at &>/dev/null; then
        ROLLBACK_JOB=$(echo "nft -f ${NFT_BACKUP} 2>/dev/null || nft flush ruleset" | at now + 5 minutes 2>&1 | grep -oP 'job \K[0-9]+') || true
        if [[ -n "$ROLLBACK_JOB" ]]; then
            log_warn "Rollback automatique programme dans 5 minutes (job $ROLLBACK_JOB)."
            log_warn "Si tout va bien, il sera annule automatiquement."
        fi
    else
        log_warn "'at' non disponible. Pas de rollback automatique programme."
    fi

    # Tester la syntaxe de nftables avant d'appliquer.
    # Une syntaxe invalide est bloquante : appliquer quand meme laisserait le
    # serveur soit sans pare-feu, soit avec un ruleset partiel.
    log_info "Verification de la syntaxe nftables..."
    if nft -c -f "$NFTCONF" 2>>"$LOG_FILE"; then
        log_info "Syntaxe nftables valide."
    else
        log_error "Erreur de syntaxe dans $NFTCONF :"
        nft -c -f "$NFTCONF" 2>&1 | tee -a "$LOG_FILE" || true
        log_error "Deploiement nftables interrompu, aucune regle appliquee."
        log_info "Les regles actuelles sont intactes. Backup : $NFT_BACKUP"
        [[ -n "${ROLLBACK_JOB:-}" ]] && atrm "$ROLLBACK_JOB" 2>/dev/null || true
        exit 1
    fi

    # Appliquer les nouvelles regles et charger le service
    log_info "Redemarrage du service nftables..."
    if systemctl restart nftables 2>/dev/null; then
        log_info "Service nftables redemarre avec succes."
    else
        log_error "Echec du redemarrage du service nftables !"
        log_info "=== Logs recents de nftables ==="
        journalctl -n 20 -u nftables --no-pager || true
        log_info "=== Statut de nftables ==="
        systemctl status nftables --no-pager || true
        log_info "Tentative d'application directe des regles en memoire..."
        nft -f "$NFTCONF" || true
    fi

    # Tester la connectivite (attendre 3 sec, verifier qu'on a toujours le controle)
    sleep 3
    if [[ -n "${ROLLBACK_JOB:-}" ]]; then
        atrm "$ROLLBACK_JOB" 2>/dev/null || true
        log_info "Rollback annule. Connexion OK apres application nftables."
    fi

    systemctl enable nftables 2>/dev/null || true
    log_info "nftables configure, demarre et actif."
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
        backup_file /etc/nginx/nginx.conf
        cp "$INSTALL_DIR/nginx/nginx-global.conf" /etc/nginx/nginx.conf
    fi

    backup_file /etc/nginx/conf.d/fluxgate.conf
    cp "$INSTALL_DIR/nginx/nginx-fluxgate.conf" /etc/nginx/conf.d/fluxgate.conf

    # Adapter les valeurs (match par pattern, pas par valeur exacte)
    sed -i "s/rate=[0-9]\+r\/s/rate=${NGINX_REQ_PER_SEC}r\/s/g" /etc/nginx/conf.d/fluxgate.conf
    sed -i "s/burst=[0-9]\+/burst=${NGINX_BURST}/g" /etc/nginx/conf.d/fluxgate.conf
    sed -i "s/limit_conn conn_per_ip [0-9]\+/limit_conn conn_per_ip ${NGINX_MAX_CONN_PER_IP}/g" /etc/nginx/conf.d/fluxgate.conf
    sed -i "s/127\.0\.0\.1:[0-9]\+/127.0.0.1:${NGINX_UPSTREAM_PORT}/g" /etc/nginx/conf.d/fluxgate.conf

    # Supprimer le default site s'il cree un conflit "duplicate default_server"
    if [[ -f /etc/nginx/sites-enabled/default ]]; then
        if grep -q "default_server" /etc/nginx/conf.d/fluxgate.conf 2>/dev/null; then
            log_info "Suppression de sites-enabled/default (conflit avec fluxgate.conf)."
            rm -f /etc/nginx/sites-enabled/default
        fi
    fi

    if nginx -t 2>&1; then
        systemctl reload nginx
        log_info "NGINX configure et recharge."
    else
        log_error "Erreur de configuration NGINX. Verifier manuellement."
    fi

    # --- Let's Encrypt : activer HTTPS si certificat present ---
    if command -v certbot &>/dev/null; then
        # Detecter un certificat existant
        CERT_DOMAIN=""
        if [[ -d /etc/letsencrypt/live ]]; then
            CERT_DOMAIN=$(ls /etc/letsencrypt/live/ 2>/dev/null | head -1)
        fi
        if [[ -n "$CERT_DOMAIN" ]] && [[ -f "/etc/letsencrypt/live/$CERT_DOMAIN/fullchain.pem" ]]; then
            log_info "Certificat Let's Encrypt detecte pour $CERT_DOMAIN. Activation HTTPS..."
            # Decommenter le bloc HTTPS et injecter les chemins du cert
            sed -i '/^# --- HTTPS BEGIN ---$/,/^# --- HTTPS END ---$/{s/^# //}' /etc/nginx/conf.d/fluxgate.conf
            sed -i "s|/etc/ssl/certs/fluxgate.crt|/etc/letsencrypt/live/$CERT_DOMAIN/fullchain.pem|g" /etc/nginx/conf.d/fluxgate.conf
            sed -i "s|/etc/ssl/private/fluxgate.key|/etc/letsencrypt/live/$CERT_DOMAIN/privkey.pem|g" /etc/nginx/conf.d/fluxgate.conf
            if nginx -t 2>&1; then
                systemctl reload nginx
                log_info "HTTPS active avec Let's Encrypt ($CERT_DOMAIN)."
            else
                log_warn "Erreur config HTTPS. Restauration de la conf precedente."
                # Le repli d'origine cherchait '^--- HTTPS BEGIN ---' alors que
                # le marqueur reel est '# --- HTTPS BEGIN ---' : il ne matchait
                # jamais et laissait nginx avec une conf cassee. On restaure
                # directement la copie de reference plutot que de re-commenter
                # a la main un bloc deja modifie par deux sed successifs.
                cp "$INSTALL_DIR/nginx/nginx-fluxgate.conf" /etc/nginx/conf.d/fluxgate.conf
                sed -i "s/rate=[0-9]\+r\/s/rate=${NGINX_REQ_PER_SEC}r\/s/g" /etc/nginx/conf.d/fluxgate.conf
                sed -i "s/burst=[0-9]\+/burst=${NGINX_BURST}/g" /etc/nginx/conf.d/fluxgate.conf
                sed -i "s/limit_conn conn_per_ip [0-9]\+/limit_conn conn_per_ip ${NGINX_MAX_CONN_PER_IP}/g" /etc/nginx/conf.d/fluxgate.conf
                sed -i "s/127\.0\.0\.1:[0-9]\+/127.0.0.1:${NGINX_UPSTREAM_PORT}/g" /etc/nginx/conf.d/fluxgate.conf
                if nginx -t 2>&1; then
                    systemctl reload nginx
                    log_info "Conf NGINX sans HTTPS restauree et rechargee."
                else
                    log_error "NGINX reste en erreur apres restauration : verifier manuellement."
                fi
            fi
        else
            log_info "Pas de certificat Let's Encrypt detecte."
            log_info "Pour activer HTTPS : sudo certbot --nginx -d votre-domaine.fr"
        fi
    fi

    # --- ModSecurity WAF : activer si installe ---
    if [[ -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so ]] || \
       dpkg -l libnginx-mod-http-modsecurity 2>/dev/null | grep -q "^ii"; then
        log_info "ModSecurity detecte. Activation WAF..."
        
        # --- Assurer la presence des regles OWASP CRS ---
        if [[ ! -d /etc/modsecurity/crs/rules ]] || [[ -z "$(ls -A /etc/modsecurity/crs/rules 2>/dev/null)" ]]; then
            log_warn "Regles OWASP CRS manquantes dans /etc/modsecurity/crs/rules."
            if install_owasp_crs /etc/modsecurity/crs; then
                log_info "OWASP CRS installe et verifie."
            else
                log_error "Installation du CRS echouee : le WAF restera sans regles."
            fi
        fi

        # Copier configs WAF
        mkdir -p /etc/modsecurity /etc/modsecurity/crs
        cp "$INSTALL_DIR/waf/modsecurity/modsecurity.conf" /etc/modsecurity/ 2>/dev/null || true
        cp "$INSTALL_DIR/waf/modsecurity/crs-setup-override.conf" /etc/modsecurity/crs/ 2>/dev/null || true
        
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

        # Activer modsecurity dans nginx
        if ! grep -q "^modsecurity on;" /etc/nginx/nginx.conf 2>/dev/null; then
            backup_file /etc/nginx/nginx.conf
            sed -i '/http {/a\    modsecurity on;\n    modsecurity_rules_file /etc/modsecurity/modsecurity.conf;' /etc/nginx/nginx.conf
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
        log_info "fail2ban bannira dans les sets FluxGate (blocklist4/blocklist6)."
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
    cp "$INSTALL_DIR/crowdsec/acquis.yaml" /etc/crowdsec/acquis.d/fluxgate.yaml 2>/dev/null || true
    systemctl restart crowdsec 2>/dev/null || true
    log_info "CrowdSec configure."
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
    sed -i "s/^CPUQuota=.*/CPUQuota=${SVC_CPU_QUOTA}/"        "$DROPIN"
    sed -i "s/^MemoryMax=.*/MemoryMax=${SVC_MEMORY_MAX}/"     "$DROPIN"
    sed -i "s/^MemoryHigh=.*/MemoryHigh=${SVC_MEMORY_HIGH}/"  "$DROPIN"
    sed -i "s/^LimitNOFILE=.*/LimitNOFILE=${SVC_LIMIT_NOFILE}/" "$DROPIN"

    # ProtectSystem=strict casse les serveurs web qui ecrivent leurs logs et
    # leur cache hors /var/log : on ne l'impose pas a un service existant
    # dont on ne connait pas les chemins.
    sed -i "s/^ProtectSystem=strict/ProtectSystem=full/" "$DROPIN"

    systemctl daemon-reload
    log_info "Limites appliquees a ${SVC_NAME}.service : CPU=${SVC_CPU_QUOTA}, RAM=${SVC_MEMORY_MAX}, NOFILE=${SVC_LIMIT_NOFILE}"
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

cp "$INSTALL_DIR/systemd/fluxgate-xdp-autoblock.service" /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload

# =============================================================================
# XDP (optionnel)
# =============================================================================
if [[ "${XDP_ENABLED}" == "true" ]]; then
    log_info "=== Option : XDP ==="
    if command -v xdp-filter &>/dev/null; then
        "$INSTALL_DIR/xdp/xdp-manage.sh" load
        log_info "XDP active sur $IFACE."
    else
        log_warn "xdp-filter non disponible."
    fi
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
log_info "  1. Verifier : sudo bash $INSTALL_DIR/scripts/validate.sh"
log_info "  2. Adapter les services systemd selon votre application"
log_info "  3. Configurer le monitoring (Prometheus + Grafana)"
log_info "  4. Tester avec une montee en charge controlee"
echo ""
