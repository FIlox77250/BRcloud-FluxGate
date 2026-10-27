#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Caddy avec Coraza (WAF) et caddy-ratelimit
# =============================================================================
# Le Caddy des depots n'a ni WAF ni limite de debit. Ce script compile un
# binaire avec les deux modules (xcaddy) et le met a la place de celui du
# paquet, avec dpkg-divert pour qu'une mise a jour du paquet ne l'ecrase pas.
#
#   sudo bash caddy/build-caddy.sh
#
# Prerequis : Go >= 1.22 (paquet golang-go recent, ou go.dev/dl) et le
# paquet caddy deja installe (unite systemd, utilisateur caddy).
# Les versions sont figees ci-dessous : les relire avant de les monter.
# =============================================================================

set -euo pipefail

CADDY_VERSION="${CADDY_VERSION:-v2.8.4}"
XCADDY_VERSION="${XCADDY_VERSION:-v0.4.4}"
CORAZA_CADDY_VERSION="${CORAZA_CADDY_VERSION:-v2.0.0}"
RATELIMIT_VERSION="${RATELIMIT_VERSION:-v0.1.0}"

[[ $EUID -eq 0 ]] || { echo "A lancer en root." >&2; exit 1; }
command -v go &>/dev/null || { echo "Go introuvable (apt install golang-go)." >&2; exit 1; }
command -v caddy &>/dev/null || { echo "Installer d'abord le paquet caddy." >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export GOBIN="$WORK/bin" GOPATH="$WORK/go" GOCACHE="$WORK/cache"

echo "[1/4] xcaddy ${XCADDY_VERSION}"
go install "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}"

echo "[2/4] Compilation de Caddy ${CADDY_VERSION} (coraza ${CORAZA_CADDY_VERSION}, ratelimit ${RATELIMIT_VERSION})"
(cd "$WORK" && "$GOBIN/xcaddy" build "$CADDY_VERSION" \
    --with "github.com/corazawaf/coraza-caddy/v2@${CORAZA_CADDY_VERSION}" \
    --with "github.com/mholt/caddy-ratelimit@${RATELIMIT_VERSION}" \
    --output "$WORK/caddy")

echo "[3/4] Verification des modules"
for m in http.handlers.waf http.handlers.rate_limit; do
    "$WORK/caddy" list-modules | grep -qx "$m" || { echo "Module $m absent du binaire." >&2; exit 1; }
done

echo "[4/4] Installation"
if ! dpkg-divert --list /usr/bin/caddy | grep -q fluxgate; then
    dpkg-divert --package fluxgate --divert /usr/bin/caddy.default --rename /usr/bin/caddy
fi
install -m 755 "$WORK/caddy" /usr/bin/caddy.custom
update-alternatives --install /usr/bin/caddy caddy /usr/bin/caddy.default 10
update-alternatives --install /usr/bin/caddy caddy /usr/bin/caddy.custom 50
caddy version

echo ""
echo "Binaire installe. Relancer le deploiement pour activer le snippet WAF :"
echo "  sudo fluxgate deploy"
echo "Retour au binaire du paquet :"
echo "  update-alternatives --set caddy /usr/bin/caddy.default"
