#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Script d'Installation des Prerequis
# =============================================================================
# Installe tous les packages et dependances necessaires avant deploy.sh.
# Execution : sudo bash scripts/install.sh
#
# IMPORTANT : Executer UNIQUEMENT sur des systemes que vous administrez.
# Lire et adapter config.env AVANT l'installation.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${SCRIPT_DIR}/config.env"
LOG_DIR="/var/log/fluxgate"
LOG_FILE="${LOG_DIR}/install.log"

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Compteurs pour le resume ---
INSTALLED=()
SKIPPED=()
FAILED=()

# =============================================================================
# Fonctions utilitaires
# =============================================================================

log_info()  { echo -e "${GREEN}[INFO]${NC}  $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE" >&2; }

section() {
    echo "" | tee -a "$LOG_FILE"
    echo -e "${CYAN}${BOLD}--- $* ---${NC}" | tee -a "$LOG_FILE"
}

ask_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local yn
    if [[ "$default" == "y" ]]; then
        read -rp "$prompt [Y/n] " yn
        [[ -z "$yn" || "$yn" =~ ^[yY]$ ]]
    else
        read -rp "$prompt [y/N] " yn
        [[ "$yn" =~ ^[yY]$ ]]
    fi
}

# Installe un ou plusieurs packages selon le gestionnaire detecte
pkg_install() {
    local packages=("$@")
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        apt-get install -y "${packages[@]}" >> "$LOG_FILE" 2>&1
    elif [[ "$PKG_MANAGER" == "dnf" ]]; then
        dnf install -y "${packages[@]}" >> "$LOG_FILE" 2>&1
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        yum install -y "${packages[@]}" >> "$LOG_FILE" 2>&1
    fi
}

# Verifie si un package est deja installe
pkg_installed() {
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        dpkg -l "$1" 2>/dev/null | grep -q "^ii"
    else
        rpm -q "$1" &>/dev/null
    fi
}

# Active et demarre un service systemd
enable_and_start() {
    local svc="$1"
    if systemctl list-unit-files "${svc}.service" &>/dev/null; then
        systemctl enable "$svc" 2>/dev/null || true
        systemctl start "$svc" 2>/dev/null || true
    fi
}

# =============================================================================
# 1. Verifications initiales
# =============================================================================

# --- Root requis ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} Ce script doit etre execute en root (sudo)."
    exit 1
fi

# --- Creer le repertoire de logs tot pour que log_* fonctionne ---
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"

# --- Detection des outils de design (Graceful Degradation) ---
HAS_FIGLET=false && command -v figlet &>/dev/null && HAS_FIGLET=true
HAS_GUM=false && command -v gum &>/dev/null && HAS_GUM=true
HAS_GLOW=false && command -v glow &>/dev/null && HAS_GLOW=true

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

print_banner "Installation Prerequis"

# --- Detection OS ---
PKG_MANAGER=""
OS_FAMILY=""

if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
    OS_FAMILY="debian"
    log_info "OS detecte : famille Debian/Ubuntu (apt)"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    OS_FAMILY="rhel"
    log_info "OS detecte : famille RHEL/Fedora (dnf)"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    OS_FAMILY="rhel"
    log_info "OS detecte : famille RHEL/CentOS (yum)"
else
    log_error "Gestionnaire de paquets non supporte (apt/dnf/yum requis)."
    exit 1
fi

# --- Verification kernel >= 4.4 ---
KERNEL_VERSION="$(uname -r | cut -d'-' -f1)"
KERNEL_MAJOR="$(echo "$KERNEL_VERSION" | cut -d'.' -f1)"
KERNEL_MINOR="$(echo "$KERNEL_VERSION" | cut -d'.' -f2)"

if [[ "$KERNEL_MAJOR" -lt 4 ]] || { [[ "$KERNEL_MAJOR" -eq 4 ]] && [[ "$KERNEL_MINOR" -lt 4 ]]; }; then
    log_error "Kernel $KERNEL_VERSION detecte. Minimum requis : 4.4 (pour nftables/XDP)."
    exit 1
fi
log_info "Kernel $KERNEL_VERSION OK (>= 4.4)"

# --- Reparation dpkg si packages partiellement installes ---
if [[ "$PKG_MANAGER" == "apt" ]]; then
    if dpkg --audit 2>/dev/null | grep -q .; then
        log_warn "Packages partiellement installes detectes. Reparation..."
        dpkg --configure -a 2>>"$LOG_FILE" || true
        apt-get install -f -y 2>>"$LOG_FILE" || true
        log_info "Reparation dpkg terminee."
    fi
fi

# --- Charger config.env ---
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    log_info "config.env charge."
else
    log_warn "config.env introuvable. Valeurs par defaut utilisees."
    XDP_ENABLED="${XDP_ENABLED:-false}"
fi

echo ""
echo "Interface  : ${IFACE:-eth0}"
echo "XDP        : ${XDP_ENABLED:-false}"
echo ""

# =============================================================================
# 2. Confirmation et choix interactifs
# =============================================================================

section "Choix des composants a installer"

INSTALL_PREMIUM_CLI=false

if [[ "$HAS_GUM" == "true" ]]; then
    # --- Choix interactif avec Gum ---
    echo "Choisissez le serveur web a installer :"
    web_choice=$(gum choose "nginx (recommande)" "apache2/httpd" "Aucun (deja installe ou non necessaire)")
    case "$web_choice" in
        "nginx (recommande)") WEB_SERVER="nginx" ;;
        "apache2/httpd") WEB_SERVER="apache" ;;
        *) WEB_SERVER="none" ;;
    esac

    echo -e "\nSelectionnez les options (Espace pour cocher, Entree pour valider) :"
    options_choice=$(gum choose --no-limit \
        "Certbot (Let's Encrypt HTTPS automatique)" \
        "WAF ModSecurity + OWASP CRS (protection L7 Nginx)" \
        "CrowdSec (detection collaborative et bouncer)" \
        "Monitoring (Prometheus + Grafana)" \
        "Outils graphiques Premium (Gum, Glow, Figlet) pour ce terminal")

    INSTALL_CERTBOT=false && [[ "$options_choice" == *"Certbot"* ]] && INSTALL_CERTBOT=true
    INSTALL_WAF=false && [[ "$options_choice" == *"WAF"* ]] && INSTALL_WAF=true
    INSTALL_CROWDSEC=false && [[ "$options_choice" == *"CrowdSec"* ]] && INSTALL_CROWDSEC=true
    INSTALL_MONITORING=false && [[ "$options_choice" == *"Monitoring"* ]] && INSTALL_MONITORING=true
    INSTALL_PREMIUM_CLI=false && [[ "$options_choice" == *"Outils graphiques Premium"* ]] && INSTALL_PREMIUM_CLI=true
else
    # --- Fallback classique sans Gum ---
    # --- Choix serveur web ---
    WEB_SERVER="none"
    echo ""
    echo "Serveur web a installer :"
    echo "  1) nginx (recommande)"
    echo "  2) apache2/httpd"
    echo "  3) Aucun (deja installe ou non necessaire)"
    echo ""
    read -rp "Votre choix [1/2/3] (defaut: 1) : " web_choice
    case "${web_choice:-1}" in
        1) WEB_SERVER="nginx" ;;
        2) WEB_SERVER="apache" ;;
        3) WEB_SERVER="none" ;;
        *) WEB_SERVER="nginx" ;;
    esac

    # --- Certbot (Let's Encrypt) ---
    INSTALL_CERTBOT=false
    if [[ "$WEB_SERVER" != "none" ]]; then
        if ask_yes_no "Installer Certbot (Let's Encrypt) pour HTTPS automatique ?"; then
            INSTALL_CERTBOT=true
        fi
    fi

    # --- CrowdSec ---
    INSTALL_CROWDSEC=false
    if ask_yes_no "Installer CrowdSec (detection collaborative) ?"; then
        INSTALL_CROWDSEC=true
    fi

    # --- WAF ModSecurity ---
    INSTALL_WAF=false
    if [[ "$WEB_SERVER" == "nginx" ]]; then
        if ask_yes_no "Installer ModSecurity WAF + OWASP CRS (protection L7) ?"; then
            INSTALL_WAF=true
        fi
    fi

    # --- Monitoring ---
    INSTALL_MONITORING=false
    if ask_yes_no "Installer le monitoring (Prometheus + Grafana) ?"; then
        INSTALL_MONITORING=true
    fi
fi

# --- Resume des choix ---
echo ""
echo "============================================="
echo "  Resume des composants"
echo "============================================="
echo "  Base (nftables, conntrack, at...) : OUI"
echo "  Serveur web                      : $WEB_SERVER"
echo "  Certbot (Let's Encrypt)          : $INSTALL_CERTBOT"
echo "  fail2ban                         : OUI"
echo "  CrowdSec                         : $INSTALL_CROWDSEC"
echo "  ModSecurity WAF + OWASP CRS      : $INSTALL_WAF"
echo "  XDP                              : ${XDP_ENABLED:-false}"
echo "  Monitoring                       : $INSTALL_MONITORING"
echo "  Outils graphiques Premium        : $INSTALL_PREMIUM_CLI"
echo "============================================="
echo ""

if [[ "$HAS_GUM" == "true" ]]; then
    gum confirm "Lancer l'installation ?" --default=true || { log_info "Installation annulee."; exit 0; }
else
    if ! ask_yes_no "Lancer l'installation ?"; then
        log_info "Installation annulee par l'utilisateur."
        exit 0
    fi
fi

# =============================================================================
# 3. Mise a jour du cache des paquets
# =============================================================================

section "Mise a jour du cache des paquets"

if [[ "$PKG_MANAGER" == "apt" ]]; then
    apt-get update >> "$LOG_FILE" 2>&1
    log_info "Cache apt mis a jour."
elif [[ "$PKG_MANAGER" == "dnf" ]]; then
    dnf makecache >> "$LOG_FILE" 2>&1
    log_info "Cache dnf mis a jour."
elif [[ "$PKG_MANAGER" == "yum" ]]; then
    yum makecache >> "$LOG_FILE" 2>&1
    log_info "Cache yum mis a jour."
fi

# =============================================================================
# 4. Packages de base
# =============================================================================

show_progress 1 6 "Installation des packages de base..."
section "Etape 1/6 : Packages de base"

if [[ "$OS_FAMILY" == "debian" ]]; then
    BASE_PKGS=(nftables conntrack iproute2 ethtool curl wget gnupg lsb-release at)
    if [[ "${INSTALL_PREMIUM_CLI}" == "true" ]]; then
        log_info "Configuration du depot Charm.sh pour Gum/Glow..."
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://repo.charm.sh/apt/gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/charm.gpg >> "$LOG_FILE" 2>&1 || true
        echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" > /etc/apt/sources.list.d/charm.list
        apt-get update >> "$LOG_FILE" 2>&1 || true
        BASE_PKGS+=(figlet gum glow)
    fi
else
    BASE_PKGS=(nftables conntrack-tools iproute ethtool curl wget gnupg2 at)
    if [[ "${INSTALL_PREMIUM_CLI}" == "true" ]]; then
        log_info "Configuration du depot Charm.sh pour Gum/Glow..."
        cat > /etc/yum.repos.d/charm.repo <<'EOF'
[charm]
name=Charm
baseurl=https://repo.charm.sh/yum/
enabled=1
gpgcheck=1
gpgkey=https://repo.charm.sh/yum/gpg.key
EOF
        BASE_PKGS+=(figlet gum glow)
    fi
fi

log_info "Installation : ${BASE_PKGS[*]}"
if pkg_install "${BASE_PKGS[@]}"; then
    INSTALLED+=("base (nftables, conntrack, iproute2, ethtool)")
    log_info "Packages de base installes."
else
    FAILED+=("base")
    log_error "Echec installation des packages de base. Voir $LOG_FILE"
fi

# =============================================================================
# 5. Serveur web
# =============================================================================

show_progress 2 6 "Installation du serveur web ($WEB_SERVER)..."
section "Etape 2/6 : Serveur web ($WEB_SERVER)"

if [[ "$WEB_SERVER" == "nginx" ]]; then
    if [[ "$OS_FAMILY" == "debian" ]]; then
        WEB_PKGS=(nginx)
    else
        WEB_PKGS=(nginx)
    fi
    log_info "Installation : ${WEB_PKGS[*]}"
    if pkg_install "${WEB_PKGS[@]}"; then
        enable_and_start nginx
        INSTALLED+=("nginx")
        log_info "NGINX installe et demarre."
    else
        FAILED+=("nginx")
        log_error "Echec installation NGINX."
    fi
elif [[ "$WEB_SERVER" == "apache" ]]; then
    if [[ "$OS_FAMILY" == "debian" ]]; then
        WEB_PKGS=(apache2 libapache2-mod-security2)
    else
        WEB_PKGS=(httpd mod_security)
    fi
    log_info "Installation : ${WEB_PKGS[*]}"
    if pkg_install "${WEB_PKGS[@]}"; then
        if [[ "$OS_FAMILY" == "debian" ]]; then
            enable_and_start apache2
        else
            enable_and_start httpd
        fi
        INSTALLED+=("apache")
        log_info "Apache installe et demarre."
    else
        FAILED+=("apache")
        log_error "Echec installation Apache."
    fi
else
    SKIPPED+=("serveur web")
    log_info "Installation serveur web ignoree."
fi

# =============================================================================
# 6. fail2ban
# =============================================================================

show_progress 3 6 "Installation de fail2ban..."
section "Etape 3/6 : fail2ban"

log_info "Installation : fail2ban"
if pkg_install fail2ban; then
    enable_and_start fail2ban
    INSTALLED+=("fail2ban")
    log_info "fail2ban installe et demarre."
else
    FAILED+=("fail2ban")
    log_error "Echec installation fail2ban."
fi

# =============================================================================
# 6b. Certbot / Let's Encrypt (optionnel)
# =============================================================================

section "Etape 3b/6 : Certbot (Let's Encrypt)"

if [[ "$INSTALL_CERTBOT" == "true" ]]; then
    if [[ "$WEB_SERVER" == "nginx" ]]; then
        CERTBOT_PKGS=(certbot python3-certbot-nginx)
    else
        CERTBOT_PKGS=(certbot python3-certbot-apache)
    fi
    log_info "Installation : ${CERTBOT_PKGS[*]}"
    if pkg_install "${CERTBOT_PKGS[@]}"; then
        INSTALLED+=("certbot")
        log_info "Certbot installe."
        log_info "Apres deploiement, lancer : sudo certbot --nginx -d votre-domaine.fr"
    else
        FAILED+=("certbot")
        log_error "Echec installation Certbot."
    fi
else
    SKIPPED+=("certbot")
fi

# =============================================================================
# 7. CrowdSec (optionnel)
# =============================================================================

show_progress 4 6 "Installation des systemes de detection (fail2ban/CrowdSec)..."
section "Etape 4/6 : CrowdSec"

if [[ "$INSTALL_CROWDSEC" == "true" ]]; then
    # Ajouter le depot CrowdSec si absent
    if [[ "$OS_FAMILY" == "debian" ]]; then
        if [[ ! -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]]; then
            log_info "Ajout du depot CrowdSec..."
            curl -s https://install.crowdsec.net | bash >> "$LOG_FILE" 2>&1 || true
            apt-get update >> "$LOG_FILE" 2>&1
        fi
    else
        if ! rpm -q crowdsec-release &>/dev/null; then
            log_info "Ajout du depot CrowdSec..."
            curl -s https://install.crowdsec.net | bash >> "$LOG_FILE" 2>&1 || true
        fi
    fi

    # Reparer dpkg si necessaire avant chaque installation CrowdSec
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        dpkg --configure -a 2>>"$LOG_FILE" || true
    fi

    # 1. Installer CrowdSec d'abord, seul
    log_info "Installation : crowdsec"
    if pkg_install crowdsec; then
        enable_and_start crowdsec
        INSTALLED+=("crowdsec")
        log_info "CrowdSec installe et demarre."
    else
        FAILED+=("crowdsec")
        log_error "Echec installation CrowdSec. Voir $LOG_FILE"
    fi

    # Reparer dpkg si necessaire avant le bouncer
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        dpkg --configure -a 2>>"$LOG_FILE" || true
    fi

    # 2. Generer la cle API pour le bouncer AVANT d'installer le bouncer
    BOUNCER_KEY=""
    if command -v cscli &>/dev/null; then
        BOUNCER_KEY=$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)
        cscli bouncers add crowdsec-firewall-bouncer -k "$BOUNCER_KEY" 2>/dev/null || true
        log_info "Cle API bouncer generee et enregistree dans CrowdSec."
    fi

    # 3. Installer le bouncer nftables
    log_info "Installation : crowdsec-firewall-bouncer-nftables"
    if pkg_install crowdsec-firewall-bouncer-nftables; then
        INSTALLED+=("crowdsec-firewall-bouncer-nftables")
        log_info "Bouncer nftables installe."
    else
        FAILED+=("crowdsec-firewall-bouncer-nftables")
        log_error "Echec installation bouncer nftables. Voir $LOG_FILE"
    fi

    # 4. Mettre la cle dans la config du bouncer et redemarrer
    if [[ -n "$BOUNCER_KEY" ]] && [[ -f /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml ]]; then
        sed -i "s/^api_key:.*/api_key: $BOUNCER_KEY/" /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
        systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true
        log_info "Bouncer configure avec la cle API et redemarre."
    fi
else
    SKIPPED+=("crowdsec")
    log_info "CrowdSec non selectionne, etape ignoree."
fi

# =============================================================================
# 7b. ModSecurity WAF + OWASP CRS (optionnel)
# =============================================================================

section "Etape 4b/6 : ModSecurity WAF + OWASP CRS"

if [[ "$INSTALL_WAF" == "true" ]]; then
    # Installer libmodsecurity et le connecteur nginx
    if [[ "$OS_FAMILY" == "debian" ]]; then
        WAF_PKGS=(libmodsecurity3 libnginx-mod-http-modsecurity)
    else
        WAF_PKGS=(libmodsecurity mod_security)
    fi
    log_info "Installation : ${WAF_PKGS[*]}"
    if pkg_install "${WAF_PKGS[@]}"; then
        INSTALLED+=("modsecurity")
        log_info "ModSecurity installe."
    else
        FAILED+=("modsecurity")
        log_error "Echec installation ModSecurity."
    fi

    # Telecharger OWASP CRS v4
    CRS_VERSION="4.0.0"
    CRS_DIR="/etc/modsecurity/crs"
    if [[ ! -d "$CRS_DIR/rules" ]]; then
        log_info "Telechargement OWASP CRS v${CRS_VERSION}..."
        mkdir -p "$CRS_DIR"
        curl -sL "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
            | tar xz --strip-components=1 -C "$CRS_DIR" 2>>"$LOG_FILE"
        if [[ -f "$CRS_DIR/crs-setup.conf.example" ]]; then
            cp "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"
            log_info "OWASP CRS v${CRS_VERSION} installe dans $CRS_DIR"
            INSTALLED+=("owasp-crs-v${CRS_VERSION}")
        else
            log_error "Echec telechargement CRS."
            FAILED+=("owasp-crs")
        fi
    else
        log_info "OWASP CRS deja present dans $CRS_DIR"
    fi

    # Creer les repertoires necessaires
    mkdir -p /var/log/modsecurity /tmp/modsecurity/tmp /tmp/modsecurity/data
    # Copier unicode.mapping si absent
    if [[ ! -f /etc/modsecurity/unicode.mapping ]] && [[ -f "$CRS_DIR/unicode.mapping" ]]; then
        cp "$CRS_DIR/unicode.mapping" /etc/modsecurity/
    fi
else
    SKIPPED+=("modsecurity + owasp-crs")
fi

# =============================================================================
# 8. XDP (si XDP_ENABLED=true)
# =============================================================================

show_progress 5 6 "Configuration XDP/eBPF..."
section "Etape 5/6 : XDP"

if [[ "${XDP_ENABLED:-false}" == "true" ]]; then
    if [[ "$OS_FAMILY" == "debian" ]]; then
        XDP_PKGS=(xdp-tools bpftool linux-headers-"$(uname -r)")
    else
        XDP_PKGS=(xdp-tools bpftool kernel-headers-"$(uname -r)")
    fi

    log_info "Installation : ${XDP_PKGS[*]}"
    if pkg_install "${XDP_PKGS[@]}"; then
        INSTALLED+=("xdp-tools")
        log_info "XDP tools installes."
    else
        FAILED+=("xdp-tools")
        log_error "Echec installation XDP tools. Voir $LOG_FILE"
        log_warn "Verifiez que les headers du kernel $(uname -r) sont disponibles."
    fi
else
    SKIPPED+=("xdp (XDP_ENABLED=false)")
    log_info "XDP non active dans config.env, etape ignoree."
fi

# =============================================================================
# 9. Monitoring (optionnel)
# =============================================================================

show_progress 6 6 "Installation du monitoring et finalisation..."
section "Etape 6/6 : Monitoring (Prometheus + Grafana)"

if [[ "$INSTALL_MONITORING" == "true" ]]; then
    # --- Prometheus & Node Exporter ---
    if [[ "$OS_FAMILY" == "debian" ]]; then
        MON_PKGS=(prometheus prometheus-node-exporter)
    else
        MON_PKGS=(prometheus node_exporter)
    fi

    log_info "Installation : ${MON_PKGS[*]}"
    if pkg_install "${MON_PKGS[@]}"; then
        INSTALLED+=("prometheus + node-exporter")
        log_info "Prometheus et Node Exporter installes."
    else
        FAILED+=("prometheus")
        log_error "Echec installation Prometheus. Voir $LOG_FILE"
    fi

    # --- Grafana ---
    if [[ "$OS_FAMILY" == "debian" ]]; then
        # Ajouter le depot Grafana si absent
        if [[ ! -f /etc/apt/sources.list.d/grafana.list ]]; then
            log_info "Ajout du depot Grafana..."
            apt-get install -y apt-transport-https software-properties-common >> "$LOG_FILE" 2>&1 || true
            wget -q -O /usr/share/keyrings/grafana.key https://apt.grafana.com/gpg.key 2>>"$LOG_FILE" || true
            echo "deb [signed-by=/usr/share/keyrings/grafana.key] https://apt.grafana.com stable main" \
                > /etc/apt/sources.list.d/grafana.list
            apt-get update >> "$LOG_FILE" 2>&1
        fi
    else
        # Ajouter le depot Grafana si absent
        if [[ ! -f /etc/yum.repos.d/grafana.repo ]]; then
            log_info "Ajout du depot Grafana..."
            cat > /etc/yum.repos.d/grafana.repo <<'REPO'
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
REPO
        fi
    fi

    log_info "Installation : grafana"
    if pkg_install grafana; then
        INSTALLED+=("grafana")
        log_info "Grafana installe."
    else
        FAILED+=("grafana")
        log_error "Echec installation Grafana. Voir $LOG_FILE"
    fi

    # --- Copier les configs monitoring ---
    log_info "Copie des configurations monitoring..."

    # Prometheus
    if [[ -d /etc/prometheus ]]; then
        mkdir -p /etc/prometheus/rules
        cp "$PROJECT_DIR/monitoring/prometheus/prometheus.yml" /etc/prometheus/prometheus.yml 2>/dev/null || true
        cp "$PROJECT_DIR/monitoring/prometheus/fluxgate-alerts.yml" /etc/prometheus/rules/fluxgate-alerts.yml 2>/dev/null || true
        chown -R prometheus:prometheus /etc/prometheus/ 2>/dev/null || true
        log_info "Configuration Prometheus copiee."
    fi

    # Grafana provisioning
    if [[ -d /etc/grafana ]]; then
        mkdir -p /etc/grafana/provisioning/dashboards
        mkdir -p /etc/grafana/provisioning/datasources
        mkdir -p /var/lib/grafana/dashboards/fluxgate

        cp "$PROJECT_DIR/monitoring/grafana/provisioning-dashboards.yml" \
            /etc/grafana/provisioning/dashboards/fluxgate.yml 2>/dev/null || true
        cp "$PROJECT_DIR/monitoring/grafana/provisioning-datasources.yml" \
            /etc/grafana/provisioning/datasources/fluxgate.yml 2>/dev/null || true
        cp "$PROJECT_DIR/monitoring/grafana/dashboards/"*.json \
            /var/lib/grafana/dashboards/fluxgate/ 2>/dev/null || true
        log_info "Configuration Grafana copiee."
    fi

    # Demarrer les services monitoring
    enable_and_start prometheus
    enable_and_start prometheus-node-exporter 2>/dev/null || enable_and_start node_exporter 2>/dev/null || true
    enable_and_start grafana-server

    log_info "Services monitoring demarres."
else
    SKIPPED+=("monitoring (prometheus, grafana)")
    log_info "Monitoring non selectionne, etape ignoree."
fi

# =============================================================================
# 10. Configuration post-install
# =============================================================================

section "Configuration post-installation"

# Creer les repertoires FluxGate
mkdir -p /var/log/fluxgate
mkdir -p /opt/fluxgate
log_info "Repertoires /var/log/fluxgate/ et /opt/fluxgate/ crees."

# Verifier les services actifs
log_info "Verification des services..."
for svc in nftables nginx apache2 httpd fail2ban crowdsec prometheus grafana-server; do
    if systemctl is-active "$svc" &>/dev/null; then
        log_info "  $svc : actif"
    fi
done

# =============================================================================
# 11. Resume final
# =============================================================================

echo ""
echo "============================================="
echo "  Installation terminee !"
echo "============================================="
echo ""

if [[ ${#INSTALLED[@]} -gt 0 ]]; then
    echo -e "${GREEN}Installes :${NC}"
    for item in "${INSTALLED[@]}"; do
        echo -e "  ${GREEN}+${NC} $item"
    done
fi

if [[ ${#SKIPPED[@]} -gt 0 ]]; then
    echo -e "${YELLOW}Ignores :${NC}"
    for item in "${SKIPPED[@]}"; do
        echo -e "  ${YELLOW}-${NC} $item"
    done
fi

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo -e "${RED}Echecs :${NC}"
    for item in "${FAILED[@]}"; do
        echo -e "  ${RED}x${NC} $item"
    done
    echo ""
    log_warn "Certaines installations ont echoue. Consulter $LOG_FILE pour les details."
fi

echo ""
log_info "Prochaine etape : sudo bash scripts/deploy.sh"
echo ""
