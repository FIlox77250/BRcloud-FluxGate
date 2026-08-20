#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Script de Rollback
# =============================================================================
# Revient a l'etat initial en supprimant les configurations FluxGate.
# Execution : sudo bash scripts/rollback.sh
#
# ATTENTION : Ce script supprime les regles firewall et les configurations.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.env"

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

if [[ $EUID -ne 0 ]]; then
    echo "Ce script doit etre execute en root (sudo)." >&2
    exit 1
fi

echo ""
echo -e "${RED}============================================="
echo "  BRCloud FluxGate - ROLLBACK"
echo "=============================================${NC}"
echo ""
echo "Ce script va :"
echo "  - Vider les regles nftables"
echo "  - Detacher XDP"
echo "  - Supprimer le shaping tc"
echo "  - Retirer les configs fail2ban/NGINX/Apache FluxGate"
echo "  - Retirer les sysctl FluxGate"
echo ""
read -rp "Confirmer le rollback ? (y/N) " confirm
[[ "$confirm" =~ ^[yY]$ ]] || { log_info "Rollback annule."; exit 0; }

# --- XDP ---
log_info "Detachement XDP..."
if command -v xdp-filter &>/dev/null; then
    IFACE="${IFACE:-eth0}"
    xdp-filter unload --dev "$IFACE" 2>/dev/null || true
fi
log_info "XDP detache."

# --- nftables ---
log_info "Flush regles nftables..."
if command -v nft &>/dev/null; then
    nft flush ruleset 2>/dev/null || true
fi
log_info "nftables vide."

# --- tc ---
log_info "Suppression shaping tc..."
IFACE="${IFACE:-eth0}"
tc qdisc del dev "$IFACE" root 2>/dev/null || true
log_info "tc nettoye."

# --- sysctl ---
log_info "Suppression sysctl FluxGate..."
rm -f /etc/sysctl.d/99-fluxgate-hardening.conf
# Fichiers poses par le deploiement v2.0 pour conntrack
rm -f /etc/modules-load.d/fluxgate-conntrack.conf
rm -f /etc/modprobe.d/fluxgate-conntrack.conf
sysctl --system >/dev/null 2>&1 || true
log_info "Sysctl retire (reboot recommande pour valeurs par defaut)."

# --- NGINX ---
log_info "Suppression config NGINX FluxGate..."
rm -f /etc/nginx/conf.d/fluxgate.conf
if command -v nginx &>/dev/null; then
    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
fi

# --- Apache ---
log_info "Suppression config Apache FluxGate..."
rm -f /etc/apache2/conf-available/fluxgate-security.conf 2>/dev/null
rm -f /etc/httpd/conf.d/fluxgate-security.conf 2>/dev/null
a2disconf fluxgate-security 2>/dev/null || true

# --- fail2ban ---
log_info "Suppression jails fail2ban FluxGate..."
rm -f /etc/fail2ban/jail.d/fluxgate-*.conf
rm -f /etc/fail2ban/filter.d/nginx-4xx.conf /etc/fail2ban/filter.d/apache-4xx.conf
rm -f /etc/fail2ban/action.d/fluxgate-nft.conf
systemctl restart fail2ban 2>/dev/null || true

# --- systemd ---
log_info "Suppression overrides systemd FluxGate..."
rm -rf /etc/systemd/system/fluxgate-*.service 2>/dev/null
rm -rf /etc/systemd/system/fluxgate-*.socket 2>/dev/null
rm -rf /etc/systemd/system/fluxgate-web.service.d 2>/dev/null

# Le drop-in v2.0 est pose dans <SVC_NAME>.service.d/ : sans ce nettoyage,
# les limites CPU/RAM survivraient au rollback sans que rien ne l'indique.
SVC_NAME="${SVC_NAME:-nginx}"
if [[ -f "/etc/systemd/system/${SVC_NAME}.service.d/fluxgate-resource-limits.conf" ]]; then
    log_info "Retrait des limites de ressources sur ${SVC_NAME}.service..."
    rm -f "/etc/systemd/system/${SVC_NAME}.service.d/fluxgate-resource-limits.conf"
    # Ne supprimer le repertoire que s'il est vide : d'autres drop-ins,
    # etrangers a FluxGate, peuvent y cohabiter.
    rmdir "/etc/systemd/system/${SVC_NAME}.service.d" 2>/dev/null || true
fi
systemctl daemon-reload
if systemctl is-active "$SVC_NAME" &>/dev/null; then
    log_warn "Redemarrer ${SVC_NAME} pour liberer les limites : systemctl restart ${SVC_NAME}"
fi

echo ""
log_info "Rollback termine."
log_warn "Un reboot est recommande pour restaurer tous les parametres par defaut."
echo ""
