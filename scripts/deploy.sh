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
        local backup="${file}.bak-$(date +%s)"
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

# shellcheck source=/dev/null
source "$CONFIG_FILE"

mkdir -p /var/log/fluxgate "$INSTALL_DIR"

# --- Detection des outils de design (Graceful Degradation) ---
HAS_FIGLET=false && command -v figlet &>/dev/null && HAS_FIGLET=true
HAS_GUM=false && command -v gum &>/dev/null && HAS_GUM=true

# Import de la barre de progression native
source "${SCRIPT_DIR}/progress_bar.sh" 2>/dev/null || true

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
backup_file /etc/sysctl.d/99-fluxgate-hardening.conf
cp "$INSTALL_DIR/sysctl/99-fluxgate-hardening.conf" /etc/sysctl.d/
sysctl --system 2>&1 | tail -5 | tee -a "$LOG_FILE"
log_info "Sysctl applique."

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

    # Remplacer les valeurs de ports (match par nom de variable, pas par valeur)
    sed -i "s/^define SSH_PORT   = .*/define SSH_PORT   = ${SSH_PORT}/" "$NFTCONF"
    sed -i "s/^define HTTP_PORT  = .*/define HTTP_PORT  = ${HTTP_PORT}/" "$NFTCONF"
    sed -i "s/^define HTTPS_PORT = .*/define HTTPS_PORT = ${HTTPS_PORT}/" "$NFTCONF"

    # --- Securite anti-lockout SSH ---
    if [[ -n "${SSH_CLIENT:-}" ]] || [[ -n "${SSH_CONNECTION:-}" ]]; then
        SSH_IP=$(echo "${SSH_CLIENT:-$SSH_CONNECTION}" | awk '{print $1}')
        if [[ -n "$SSH_IP" ]]; then
            log_info "Connexion active de l'administrateur depuis : $SSH_IP"
            
            # Extraire le contenu entre les accolades de define ADMIN_NETS
            NETS_CONTENT=$(grep -E '^[[:space:]]*define ADMIN_NETS[[:space:]]*=' "$NFTCONF" | grep -oP '\{\K[^\}]+' | sed 's/,/ /g' || echo "")
            
            IS_WHITELISTED=false
            if [[ -n "$NETS_CONTENT" ]]; then
                # Utiliser Python pour valider l'appartenance CIDR
                if command -v python3 &>/dev/null; then
                    PY_NETS=$(echo "$NETS_CONTENT" | awk '{for(i=1;i<=NF;i++) printf "\"%s\", ", $i}')
                    if python3 -c "import ipaddress; ip = ipaddress.ip_address('$SSH_IP'); nets = [$PY_NETS]; print('TRUE' if any(ip in ipaddress.ip_network(n.strip()) for n in nets if n.strip()) else 'FALSE')" 2>/dev/null | grep -q "TRUE"; then
                        IS_WHITELISTED=true
                    fi
                else
                    # Fallback simple si Python est absent
                    for net in $NETS_CONTENT; do
                        if [[ "$SSH_IP" == "${net%/32}" ]] || [[ "$SSH_IP" == ${net%.*}* ]]; then
                            IS_WHITELISTED=true
                            break
                        fi
                    done
                fi
            fi

            if [[ "$IS_WHITELISTED" == "false" ]]; then
                log_warn "Votre IP SSH active ($SSH_IP) n'est PAS whitelistee dans ADMIN_NETS dans nftables.conf."
                log_warn "ADMIN_NETS contient actuellement : { $NETS_CONTENT }"
                echo -e "${YELLOW}!!! RISQUE DE LOCKOUT SSH !!!${NC}"
                read -rp "Voulez-vous ajouter dynamiquement votre IP ($SSH_IP/32) a la whitelist ? (Y/n) " add_ip
                if [[ "${add_ip:-y}" =~ ^[yY]$ ]]; then
                    sed -i "s/define ADMIN_NETS[[:space:]]*=[[:space:]]*{[[:space:]]*/define ADMIN_NETS = { ${SSH_IP}\/32, /" "$NFTCONF"
                    log_info "IP $SSH_IP/32 ajoutee dynamiquement a ADMIN_NETS dans $NFTCONF."
                else
                    log_warn "Continuer sans Whitelister votre IP active peut couper votre connexion SSH."
                    read -rp "Etes-vous sur de vouloir continuer le deploiement ? (y/N) " force_continue
                    [[ "$force_continue" =~ ^[yY]$ ]] || { log_info "Deploiement annule."; exit 0; }
                fi
            else
                log_info "Votre IP SSH active ($SSH_IP) est correctement whitelistee dans ADMIN_NETS."
            fi
        fi
    fi

    # Backup des regles actuelles avant application
    nft list ruleset > /etc/nftables.conf.bak 2>/dev/null || true
    log_info "Backup nftables sauvegarde dans /etc/nftables.conf.bak"

    # Programmer un rollback automatique dans 5 minutes (filet anti-lockout SSH)
    ROLLBACK_JOB=""
    if command -v at &>/dev/null; then
        ROLLBACK_JOB=$(echo "nft -f /etc/nftables.conf.bak 2>/dev/null || nft flush ruleset" | at now + 5 minutes 2>&1 | grep -oP 'job \K[0-9]+') || true
        if [[ -n "$ROLLBACK_JOB" ]]; then
            log_warn "Rollback automatique programme dans 5 minutes (job $ROLLBACK_JOB)."
            log_warn "Si tout va bien, il sera annule automatiquement."
        fi
    else
        log_warn "'at' non disponible. Pas de rollback automatique programme."
    fi

    # Tester la syntaxe de nftables avant d'appliquer
    log_info "Verification de la syntaxe nftables..."
    if nft -c -f "$NFTCONF" 2>/dev/null; then
        log_info "Syntaxe nftables valide."
    else
        log_warn "Erreur de syntaxe detectee dans nftables.conf !"
        nft -c -f "$NFTCONF" || true
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
                log_warn "Erreur config HTTPS. Bloc HTTPS desactive."
                sed -i '/^--- HTTPS BEGIN ---$/,/^--- HTTPS END ---$/{s/# //; s/^/# /}' /etc/nginx/conf.d/fluxgate.conf
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
    cp "$INSTALL_DIR/apache/security-hardening.conf" /etc/apache2/conf-available/fluxgate-security.conf 2>/dev/null || \
    cp "$INSTALL_DIR/apache/security-hardening.conf" /etc/httpd/conf.d/fluxgate-security.conf 2>/dev/null || true

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
# Copier les templates (l'utilisateur doit adapter le nom du service)
cp -r "$INSTALL_DIR/systemd/"* /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload
log_info "Templates systemd copies. Adapter selon vos services."

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
