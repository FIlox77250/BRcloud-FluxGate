#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Script de Rollback
# =============================================================================
# Revient a l'etat d'avant FluxGate en supprimant ses configurations.
# Execution : sudo bash scripts/rollback.sh [--yes]
#
# - Seules les tables FluxGate sont supprimees : plus de 'flush ruleset',
#   qui effacait aussi Docker, CrowdSec, libvirt ou wg-quick.
# - /etc/nftables.conf et les autres fichiers systeme modifies sont remis
#   dans leur etat d'origine (copie prise par deploy.sh avant la premiere
#   modification, dans /var/lib/fluxgate/orig). L'ancienne version laissait
#   /etc/nftables.conf en place : le pare-feu FluxGate revenait au reboot.
# - Unites systemd, drop-ins, timers, XDP, CLI et logrotate sont retires.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${FLUXGATE_CONFIG:-${SCRIPT_DIR}/config.env}"
STATE_DIR="${FLUXGATE_STATE_DIR:-/var/lib/fluxgate}"
ORIG_DIR="${STATE_DIR}/orig"

# shellcheck source=lib/defaults.sh
source "${SCRIPT_DIR}/lib/defaults.sh"
if [[ -f "$CONFIG_FILE" ]]; then
    fluxgate_load_config "$CONFIG_FILE" || exit 1
else
    fluxgate_apply_defaults
fi
IFACE="${IFACE:-eth0}"

ASSUME_YES=false
case "${1:-}" in
    -y|--yes) ASSUME_YES=true ;;
    -h|--help) echo "Usage: $0 [--yes]"; exit 0 ;;
esac

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
echo "  - Supprimer les tables nftables FluxGate (les autres sont conservees)"
echo "  - Restaurer /etc/nftables.conf d'origine"
echo "  - Arreter et retirer les services/timers FluxGate, detacher XDP"
echo "  - Supprimer le shaping tc"
echo "  - Retirer les configs fail2ban/NGINX/Apache/CrowdSec FluxGate"
echo "  - Retirer les sysctl FluxGate"
echo ""
if [[ "$ASSUME_YES" != "true" ]]; then
    read -rp "Confirmer le rollback ? (y/N) " confirm
    [[ "$confirm" =~ ^[yY]$ ]] || { log_info "Rollback annule."; exit 0; }
fi

# restore_original <fichier> : remet la copie d'origine, ou supprime le
# fichier s'il n'existait pas avant FluxGate. Retour 1 si aucune trace.
restore_original() {
    local file="$1" saved="${ORIG_DIR}${1}"
    if [[ -f "$saved" ]]; then
        cp -p "$saved" "$file"
        log_info "Restaure : $file"
    elif [[ -e "${saved}.absent" ]]; then
        rm -f "$file"
        log_info "Supprime (absent avant FluxGate) : $file"
    else
        return 1
    fi
}

# --- Services et timers ---
log_info "Arret des services FluxGate..."
for unit in fluxgate-xdp-autoblock.service fluxgate-xdp.service \
            fluxgate-state-save.timer fluxgate-lists.timer \
            fluxgate-shield-off.timer fluxgate-emergency-restore.timer \
            fluxgate-exporter.timer; do
    systemctl disable --now "$unit" &>/dev/null || true
done
# Sans sauvegarde finale : les bans ne doivent pas etre rejoues plus tard.
systemctl disable fluxgate-state.service &>/dev/null || true

# --- XDP ---
log_info "Detachement XDP..."
if [[ -x /opt/fluxgate/xdp/xdp-manage.sh ]]; then
    /opt/fluxgate/xdp/xdp-manage.sh -i "$IFACE" unload 2>/dev/null || true
elif command -v xdp-filter &>/dev/null; then
    xdp-filter unload "$IFACE" 2>/dev/null || true
fi
# Wrapper xdp-loader pose par FluxGate <= 2.0
for p in /usr/sbin/xdp-loader /usr/bin/xdp-loader /sbin/xdp-loader /bin/xdp-loader; do
    if [[ -f "${p}.real" ]] && grep -q 'Wrapper de compatibilite cree par FluxGate' "$p" 2>/dev/null; then
        mv -f "${p}.real" "$p"
        log_info "xdp-loader d'origine restaure : $p"
    fi
done

# --- nftables ---
log_info "Suppression des tables nftables FluxGate..."
if command -v nft &>/dev/null; then
    nft delete table inet fluxgate 2>/dev/null || true
    nft delete table inet fluxgate_emergency 2>/dev/null || true
    # Tables de FluxGate <= 2.0, reconnues a leur contenu
    if nft list set inet filter blocklist4 &>/dev/null; then
        nft delete table inet filter 2>/dev/null || true
    fi
    nft delete table inet emergency 2>/dev/null || true
fi

if ! restore_original /etc/nftables.conf; then
    # Installation anterieure a la sauvegarde d'origine : on remet le
    # fichier le plus ancien sauvegarde par deploy.sh, a defaut un ruleset
    # vide, pour que le prochain boot ne recharge pas FluxGate.
    oldest=$(ls -1 /etc/nftables.conf.bak-* 2>/dev/null | sort -t- -k2 -n | head -1 || true)
    if [[ -n "$oldest" ]] && ! grep -q 'table inet fluxgate' "$oldest"; then
        cp -p "$oldest" /etc/nftables.conf
        log_info "Restaure depuis la plus ancienne sauvegarde : $oldest"
    elif grep -qE 'table inet (fluxgate|filter)' /etc/nftables.conf 2>/dev/null; then
        cp -p /etc/nftables.conf "/etc/nftables.conf.fluxgate-$(date +%s)"
        cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
# Ruleset vide pose par le rollback FluxGate (aucune version d'origine
# connue). L'ancienne configuration FluxGate est conservee a cote.
EOF
        log_warn "Pas de version d'origine : /etc/nftables.conf remplace par un ruleset vide."
    fi
fi
rm -f /etc/systemd/system/nftables.service.d/fluxgate.conf
rmdir /etc/systemd/system/nftables.service.d 2>/dev/null || true
log_info "nftables nettoye (les autres tables sont intactes)."

# --- tc ---
log_info "Suppression shaping tc..."
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
rm -f /etc/nginx/conf.d/fluxgate.conf /etc/nginx/conf.d/fluxgate-realip.conf
if [[ -f /etc/nginx/nginx.conf ]]; then
    cp -p /etc/nginx/nginx.conf /etc/nginx/nginx.conf.pre-rollback
    restore_original /etc/nginx/nginx.conf || true
fi
if command -v nginx &>/dev/null; then
    if nginx -t &>/dev/null; then
        systemctl reload nginx 2>/dev/null || true
    elif [[ -f /etc/nginx/nginx.conf.pre-rollback ]]; then
        log_warn "nginx -t echoue avec nginx.conf d'origine : version courante conservee."
        cp -p /etc/nginx/nginx.conf.pre-rollback /etc/nginx/nginx.conf
        sed -i '/^[[:space:]]*modsecurity on;$/d; /^[[:space:]]*modsecurity_rules_file \/etc\/modsecurity\/modsecurity.conf;$/d' /etc/nginx/nginx.conf
        nginx -t &>/dev/null && systemctl reload nginx 2>/dev/null || true
    fi
fi
rm -f /etc/nginx/nginx.conf.pre-rollback

# --- Apache ---
log_info "Suppression config Apache FluxGate..."
a2disconf fluxgate-security &>/dev/null || true
rm -f /etc/apache2/conf-available/fluxgate-security.conf 2>/dev/null
rm -f /etc/httpd/conf.d/fluxgate-security.conf 2>/dev/null

# --- fail2ban ---
log_info "Suppression jails fail2ban FluxGate..."
rm -f /etc/fail2ban/jail.d/fluxgate-*.conf /etc/fail2ban/jail.d/00-fluxgate-ignoreip.conf
rm -f /etc/fail2ban/filter.d/nginx-4xx.conf /etc/fail2ban/filter.d/apache-4xx.conf
rm -f /etc/fail2ban/action.d/fluxgate-nft.conf
systemctl restart fail2ban 2>/dev/null || true

# --- CrowdSec ---
log_info "Suppression acquisition CrowdSec FluxGate..."
rm -f /etc/crowdsec/acquis.d/fluxgate.yaml
cs_changed=false
for cs_file in /etc/crowdsec/config.yaml /etc/crowdsec/local_api_credentials.yaml \
               /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml; do
    restore_original "$cs_file" 2>/dev/null && cs_changed=true || true
done
if command -v cscli &>/dev/null; then
    systemctl restart crowdsec 2>/dev/null || true
    [[ "$cs_changed" == "true" ]] && systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true
fi

# --- systemd ---
log_info "Suppression unites et overrides systemd FluxGate..."
rm -f /etc/systemd/system/fluxgate-*.service /etc/systemd/system/fluxgate-*.timer
rm -f /etc/systemd/system/fluxgate-*.socket
rm -rf /etc/systemd/system/fluxgate-web.service.d

# Le drop-in est pose dans <SVC_NAME>.service.d/ : sans ce nettoyage,
# les limites CPU/RAM survivraient au rollback sans que rien ne l'indique.
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

# --- CLI, logrotate, exporter, etat ---
rm -f /usr/local/sbin/fluxgate /etc/logrotate.d/fluxgate
restore_original /etc/caddy/fluxgate.caddy || rm -f /etc/caddy/fluxgate.caddy
if grep -qs 'fluxgate.caddy' /etc/caddy/Caddyfile; then
    log_warn "/etc/caddy/Caddyfile importe encore fluxgate.caddy : retirer l'import et les 'import fluxgate' avant de recharger Caddy."
fi
rm -f /var/lib/prometheus/node-exporter/fluxgate.prom
rm -rf /run/fluxgate
rm -rf "$STATE_DIR"
log_info "Etat FluxGate supprime (${STATE_DIR})."

echo ""
log_info "Rollback termine."
log_info "Fichiers conserves : /opt/fluxgate, /var/log/fluxgate, /etc/modsecurity (CRS)."
log_warn "Un reboot est recommande pour restaurer tous les parametres par defaut."
echo ""
