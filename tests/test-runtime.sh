#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Tests d'execution (root)
# =============================================================================
# Complement de test-templating.sh : ici les fichiers rendus sont reellement
# charges par les outils.
#   - nftables : ruleset charge dans un espace de noms reseau isole
#                (unshare -n), puis nft-manage (ban, bouclier, urgence),
#                l'exporteur et la commande fluxgate
#   - nginx    : rendu HTTP et HTTPS, puis nginx -t
#   - fail2ban : fail2ban-regex sur des lignes d'acces types
#   - caddy    : rendu du profil et caddy validate
#   - config   : check-config.sh accepte l'exemple et refuse une erreur
#
# Execution :  sudo bash tests/test-runtime.sh
# Un outil absent fait sauter sa section (SKIP). En CI, FLUXGATE_TEST_STRICT=1
# transforme ces SKIP en echecs pour qu'un paquet manquant ne passe pas
# inapercu.
#
# Effets hors du repertoire temporaire : le ruleset ne vit que dans l'espace
# de noms isole, mais nft-manage ecrit son marqueur dans /run/fluxgate.
# =============================================================================

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$TEST_DIR")"
STRICT="${FLUXGATE_TEST_STRICT:-0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; FAIL=$((FAIL+1)); }
skip() {
    if [[ "$STRICT" == "1" ]]; then
        fail "$* (outil absent, FLUXGATE_TEST_STRICT=1)"
    else
        echo -e "  ${YELLOW}[SKIP]${NC} $*"; SKIP=$((SKIP+1))
    fi
}

# check <description> <commande...> : PASS si la commande reussit
check() {
    local desc="$1"; shift
    local out
    if out=$("$@" 2>&1); then
        pass "$desc"
    else
        fail "$desc"
        printf '%s\n' "$out" | tail -5 | sed 's/^/         /'
    fi
}

# check_fails <description> <commande...> : PASS si la commande echoue
check_fails() {
    local desc="$1"; shift
    if "$@" &>/dev/null; then fail "$desc"; else pass "$desc"; fi
}

# check_out <description> <motif grep -E> <commande...>
check_out() {
    local desc="$1" pattern="$2"; shift 2
    local out
    out=$("$@" 2>&1)
    if grep -qE "$pattern" <<<"$out"; then
        pass "$desc"
    else
        fail "$desc"
        echo "         motif absent : $pattern"
        printf '%s\n' "$out" | tail -5 | sed 's/^/         /'
    fi
}

if [[ $EUID -ne 0 ]]; then
    echo "A lancer en root : sudo bash $0" >&2
    exit 1
fi

# Les fonctions de log de la lib sont silencieuses pendant les tests
log_info()  { :; }
log_warn()  { :; }
log_error() { echo "    (error) $*"; }

WORK=$(mktemp -d)
trap 'traffic_cleanup &>/dev/null; rm -rf "$WORK"' EXIT

# Configuration de test : l'exemple, avec un bouclier sans echeance pour ne
# pas dependre de systemd-run, et des permissions acceptees par la lib.
cp "${PROJECT_DIR}/scripts/config.env.example" "$WORK/config.env"
sed -i 's/^SHIELD_DURATION=.*/SHIELD_DURATION="0"/' "$WORK/config.env"
chmod 600 "$WORK/config.env"
export FLUXGATE_CONFIG="$WORK/config.env"

# shellcheck source=../scripts/lib/defaults.sh
source "${PROJECT_DIR}/scripts/lib/defaults.sh"
# shellcheck disable=SC1090
source "$FLUXGATE_CONFIG"
fluxgate_apply_defaults
# shellcheck source=../scripts/lib/nft-template.sh
source "${PROJECT_DIR}/scripts/lib/nft-template.sh"

# Fonctions de rendu de deploy.sh, sans executer le script
eval "$(sed -n '/^nginx_http2_directive() {/,/^}/p;/^render_nginx_conf() {/,/^}/p;/^render_caddy_conf() {/,/^}/p' \
    "${PROJECT_DIR}/scripts/deploy.sh")"

# =============================================================================
# nftables (espace de noms reseau isole)
# =============================================================================
# Execute dans "unshare -n" : la table chargee n'existe que la et disparait
# avec le processus. Le poste ou le runner garde son pare-feu intact.
nft_section() {
    local NFT="${PROJECT_DIR}/nftables/nft-manage.sh"
    local CLI="${PROJECT_DIR}/cli/fluxgate"
    export FLUXGATE_NFT_CONF="$WORK/nftables.conf"
    export FLUXGATE_STATE_DIR="$WORK/state" FLUXGATE_TEXTFILE_DIR="$WORK/textfile"
    mkdir -p "$FLUXGATE_STATE_DIR" "$FLUXGATE_TEXTFILE_DIR"

    check "Chargement du ruleset rendu" nft -f "$FLUXGATE_NFT_CONF"
    check_out "Table inet fluxgate presente" '^table inet fluxgate$' nft list tables
    check_out "Chaine shield vide au demarrage" 'chain shield' nft list chain inet fluxgate shield

    check "Ban IPv4 (nft-manage block)" bash "$NFT" block 192.0.2.10 10m
    check "Ban IPv6 /64" bash "$NFT" block 2001:db8:1::/64 1h
    check_out "IPv4 dans blocklist4" '192\.0\.2\.10' nft list set inet fluxgate blocklist4
    check_out "/64 dans blocklist6net" '2001:db8:1::' nft list set inet fluxgate blocklist6net
    check_fails "IP invalide refusee" bash "$NFT" block 999.1.1.1
    check "Deban IPv4" bash "$NFT" unblock 192.0.2.10
    if nft list set inet fluxgate blocklist4 | grep -q '192\.0\.2\.10'; then
        fail "IPv4 retiree de blocklist4"
    else
        pass "IPv4 retiree de blocklist4"
    fi

    check "Rechargement (apply) avec bans en place" bash "$NFT" apply
    check_out "Le ban /64 survit au rechargement" '2001:db8:1::' nft list set inet fluxgate blocklist6net

    check "Bouclier actif" bash "$NFT" shield on
    check_out "Chaine shield remplie" 'drop|reject' nft list chain inet fluxgate shield
    check_out "Exporteur : bouclier vu" '^fluxgate_shield_active 1' \
        bash "${PROJECT_DIR}/monitoring/exporter/fluxgate-exporter.sh" --stdout
    check "Bouclier coupe" bash "$NFT" shield off
    if nft list chain inet fluxgate shield | grep -qE 'drop|reject'; then
        fail "Chaine shield videe"
    else
        pass "Chaine shield videe"
    fi

    check "Mode urgence" bash "$NFT" emergency-drop-all
    check_out "Table d'urgence chargee" 'fluxgate_emergency' nft list tables
    check_out "Exporteur : urgence vue" '^fluxgate_emergency_active 1' \
        bash "${PROJECT_DIR}/monitoring/exporter/fluxgate-exporter.sh" --stdout
    check "Sortie du mode urgence" bash "$NFT" restore
    if nft list tables | grep -q fluxgate_emergency; then
        fail "Table d'urgence retiree"
    else
        pass "Table d'urgence retiree"
    fi

    check "Exporteur : ecriture du fichier .prom" \
        bash "${PROJECT_DIR}/monitoring/exporter/fluxgate-exporter.sh"
    check_out "Fichier .prom lisible" '^fluxgate_nft_table_loaded 1' cat "$FLUXGATE_TEXTFILE_DIR/fluxgate.prom"

    check_out "CLI : aide" 'Usage : fluxgate' bash "$CLI" help
    check_fails "CLI : commande inconnue refusee" bash "$CLI" bogus
    check "CLI : ban" bash "$CLI" ban 198.51.100.7 5m
    check_out "CLI : bans" '198\.51\.100\.7' bash "$CLI" bans
    check "CLI : unban" bash "$CLI" unban 198.51.100.7
}

echo ""
echo "=== nftables (unshare -n) ==="
if ! command -v nft &>/dev/null || ! command -v unshare &>/dev/null; then
    skip "nft ou unshare absent"
else
    cp "${PROJECT_DIR}/nftables/nftables.conf" "$WORK/nftables.conf"
    export SSH_MODE ADMIN_NETS ADMIN_NETS6 NFT_FORWARD_POLICY=drop
    # SYNPROXY demande nft_synproxy, absent de certains noyaux (WSL2) :
    # c'est le job nftables de la CI qui le couvre.
    export SYNPROXY_ENABLED=false
    if render_nftables_conf "$WORK/nftables.conf"; then
        pass "Rendu de nftables.conf"
        # Sous-shell dans un nouvel espace de noms : compteurs remontes par
        # fichier, les variables du sous-processus ne revenant pas.
        export -f nft_section pass fail skip check check_fails check_out log_info log_warn log_error
        export PROJECT_DIR WORK STRICT RED GREEN YELLOW NC
        unshare -n bash -c 'PASS=0; FAIL=0; SKIP=0; nft_section; echo "$PASS $FAIL $SKIP" > "$WORK/nft.count"'
        if [[ -f "$WORK/nft.count" ]]; then
            read -r p f s < "$WORK/nft.count"
            PASS=$((PASS+p)); FAIL=$((FAIL+f)); SKIP=$((SKIP+s))
        else
            fail "Section nftables interrompue"
        fi
    else
        fail "Rendu de nftables.conf"
    fi
fi

# =============================================================================
# Trafic reel a travers le pare-feu (deux espaces de noms relies par veth)
# =============================================================================
# fg-srv porte le pare-feu et deux ecouteurs (HTTP_PORT et SSH_PORT) ;
# fg-cli (192.0.2.2) joue le visiteur. On verifie ce que le pare-feu laisse
# reellement passer, pas seulement la presence des regles.
NS_SRV=fg-test-srv
NS_CLI=fg-test-cli
SRV_IP=192.0.2.1
CLI_IP=192.0.2.2

traffic_cleanup() {
    [[ -n "${LISTEN_PIDS:-}" ]] && kill $LISTEN_PIDS 2>/dev/null
    ip netns del "$NS_SRV" 2>/dev/null
    ip netns del "$NS_CLI" 2>/dev/null
    true
}

# tcp_open <port> : la connexion TCP depuis le client aboutit-elle ?
tcp_open() {
    ip netns exec "$NS_CLI" timeout 3 bash -c "exec 3<>/dev/tcp/${SRV_IP}/$1" 2>/dev/null
}

# load_fw <ADMIN_NETS> : rendu en mode strict et chargement dans fg-srv
load_fw() {
    cp "${PROJECT_DIR}/nftables/nftables.conf" "$WORK/traffic.conf"
    ( export SSH_MODE=strict ADMIN_NETS="$1" ADMIN_NETS6="{ fc00::/7 }" \
             NFT_FORWARD_POLICY=drop SYNPROXY_ENABLED=false
      render_nftables_conf "$WORK/traffic.conf" ) &&
    ip netns exec "$NS_SRV" nft -f "$WORK/traffic.conf"
}

echo ""
echo "=== trafic (veth entre deux netns) ==="
if ! command -v ip &>/dev/null || ! command -v python3 &>/dev/null || ! command -v nft &>/dev/null; then
    skip "ip, python3 ou nft absent"
else
    traffic_cleanup
    ip netns add "$NS_SRV" && ip netns add "$NS_CLI" &&
    ip link add fg-veth-s type veth peer name fg-veth-c &&
    ip link set fg-veth-s netns "$NS_SRV" && ip link set fg-veth-c netns "$NS_CLI" &&
    ip -n "$NS_SRV" addr add "${SRV_IP}/24" dev fg-veth-s &&
    ip -n "$NS_CLI" addr add "${CLI_IP}/24" dev fg-veth-c &&
    ip -n "$NS_SRV" link set fg-veth-s up && ip -n "$NS_SRV" link set lo up &&
    ip -n "$NS_CLI" link set fg-veth-c up && ip -n "$NS_CLI" link set lo up
    if [[ $? -ne 0 ]]; then
        fail "Creation des espaces de noms de test"
    else
        LISTEN_PIDS=""
        for port in "$HTTP_PORT" "$SSH_PORT"; do
            ip netns exec "$NS_SRV" python3 -m http.server "$port" --bind "$SRV_IP" &>/dev/null &
            LISTEN_PIDS+=" $!"
        done
        sleep 1

        # Client hors ADMIN_NETS
        if load_fw "{ 10.0.0.0/8 }"; then
            pass "Pare-feu charge dans ${NS_SRV}"
            if tcp_open "$HTTP_PORT"; then pass "HTTP joignable"; else fail "HTTP joignable"; fi
            if tcp_open "$SSH_PORT"; then
                fail "SSH refuse hors ADMIN_NETS (mode strict)"
            else
                pass "SSH refuse hors ADMIN_NETS (mode strict)"
            fi

            ip netns exec "$NS_SRV" env FLUXGATE_NFT_CONF="$WORK/traffic.conf" \
                bash "${PROJECT_DIR}/nftables/nft-manage.sh" block "$CLI_IP" 5m &>/dev/null
            if tcp_open "$HTTP_PORT"; then fail "HTTP coupe pour une IP bannie"; else pass "HTTP coupe pour une IP bannie"; fi
            ip netns exec "$NS_SRV" env FLUXGATE_NFT_CONF="$WORK/traffic.conf" \
                bash "${PROJECT_DIR}/nftables/nft-manage.sh" unblock "$CLI_IP" &>/dev/null
            if tcp_open "$HTTP_PORT"; then pass "HTTP rouvert apres deban"; else fail "HTTP rouvert apres deban"; fi

            ip netns exec "$NS_SRV" env FLUXGATE_NFT_CONF="$WORK/traffic.conf" \
                bash "${PROJECT_DIR}/nftables/nft-manage.sh" emergency-drop-all &>/dev/null
            if tcp_open "$HTTP_PORT"; then fail "Mode urgence : HTTP coupe"; else pass "Mode urgence : HTTP coupe"; fi
            ip netns exec "$NS_SRV" env FLUXGATE_NFT_CONF="$WORK/traffic.conf" \
                bash "${PROJECT_DIR}/nftables/nft-manage.sh" restore &>/dev/null
            if tcp_open "$HTTP_PORT"; then pass "Apres urgence : HTTP rouvert"; else fail "Apres urgence : HTTP rouvert"; fi
        else
            fail "Pare-feu charge dans ${NS_SRV}"
        fi

        # Client dans ADMIN_NETS : le SSH doit passer
        ip netns exec "$NS_SRV" nft delete table inet fluxgate 2>/dev/null
        if load_fw "{ ${CLI_IP}/32 }"; then
            if tcp_open "$SSH_PORT"; then pass "SSH accepte depuis ADMIN_NETS"; else fail "SSH accepte depuis ADMIN_NETS"; fi
        else
            fail "Pare-feu (ADMIN_NETS client) charge"
        fi
    fi
    traffic_cleanup
fi

# =============================================================================
# nginx -t
# =============================================================================
echo ""
echo "=== nginx ==="
nginx_test() {
    local conf="$1" main="$WORK/nginx-main.conf"
    cat > "$main" <<EOF
pid ${WORK}/nginx.pid;
error_log ${WORK}/nginx-error.log;
events {}
http {
    include /etc/nginx/mime.types;
    include ${conf};
}
EOF
    nginx -t -q -c "$main"
}

if ! command -v nginx &>/dev/null; then
    skip "nginx absent"
else
    mkdir -p /var/log/nginx
    cp "${PROJECT_DIR}/nginx/nginx-fluxgate.conf" "$WORK/http.conf"
    render_nginx_conf "$WORK/http.conf"
    check "nginx -t : rendu HTTP" nginx_test "$WORK/http.conf"
    check_out "Limite de debit reportee" "rate=${NGINX_REQ_PER_SEC}r/s" cat "$WORK/http.conf"

    # HTTPS : certificat autosigne a la place du chemin Let's Encrypt
    if command -v openssl &>/dev/null; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=fluxgate.test" \
            -keyout "$WORK/privkey.pem" -out "$WORK/fullchain.pem" &>/dev/null
        cp "${PROJECT_DIR}/nginx/nginx-fluxgate.conf" "$WORK/https.conf"
        HSTS_PRELOAD=true render_nginx_conf "$WORK/https.conf" ci-test
        sed -i "s|/etc/letsencrypt/live/ci-test/|${WORK}/|g" "$WORK/https.conf"
        check "nginx -t : rendu HTTPS" nginx_test "$WORK/https.conf"
        check_out "HSTS preload en HTTPS" 'includeSubDomains; preload' cat "$WORK/https.conf"
    else
        skip "openssl absent (rendu HTTPS)"
    fi
fi

# =============================================================================
# fail2ban-regex
# =============================================================================
echo ""
echo "=== fail2ban ==="
if ! command -v fail2ban-regex &>/dev/null; then
    skip "fail2ban-regex absent"
else
    cat > "$WORK/access.log" <<'EOF'
203.0.113.5 - - [26/Oct/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "curl/8.0"
203.0.113.5 - - [26/Oct/2026:10:00:01 +0000] "POST /api/login HTTP/1.1" 429 0 "-" "curl/8.0"
203.0.113.6 - - [26/Oct/2026:10:00:02 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"
203.0.113.7 - - [26/Oct/2026:10:00:03 +0000] "GET /health HTTP/1.1" 404 0 "-" "probe"
203.0.113.8 - - [26/Oct/2026:10:00:04 +0000] "GET /favicon.ico HTTP/1.1" 404 0 "-" "Mozilla/5.0"
EOF
    # Attendu : les deux 4xx de 203.0.113.5 ; ni le 200, ni /health, ni
    # /favicon.ico (ignorees par nginx-4xx ; apache-4xx n'ignore que /health
    # et retient donc aussi favicon).
    for spec in nginx-4xx:2 apache-4xx:3; do
        flt="${spec%%:*}" want="${spec#*:}"
        # Copie : avec un espace dans le chemin, fail2ban-regex prend
        # l'argument pour une expression et non pour un fichier.
        cp "${PROJECT_DIR}/fail2ban/filter.d/${flt}.conf" "$WORK/${flt}.conf"
        out=$(fail2ban-regex "$WORK/access.log" "$WORK/${flt}.conf" 2>&1)
        matched=$(grep -oE '^Lines: [0-9]+ lines, [0-9]+ ignored, [0-9]+ matched' <<<"$out" | awk '{print $6}')
        if [[ "$matched" == "$want" ]]; then
            pass "fail2ban-regex ${flt} : ${matched} lignes retenues"
        else
            fail "fail2ban-regex ${flt} : ${matched:-?} lignes retenues, ${want} attendues"
            printf '%s\n' "$out" | tail -5 | sed 's/^/         /'
        fi
    done
fi

# =============================================================================
# Caddy
# =============================================================================
echo ""
echo "=== caddy ==="
if ! command -v caddy &>/dev/null; then
    skip "caddy absent"
else
    for cdn in off cloudflare; do
        cp "${PROJECT_DIR}/caddy/fluxgate.caddy" "$WORK/fluxgate-${cdn}.caddy"
        CDN_MODE="$cdn" render_caddy_conf "$WORK/fluxgate-${cdn}.caddy" false
        printf 'import %s\n\n:65080 {\n\timport fluxgate\n\trespond "ok"\n}\n' \
            "$WORK/fluxgate-${cdn}.caddy" > "$WORK/Caddyfile-${cdn}"
        check "caddy validate (CDN_MODE=${cdn}, sans WAF)" \
            caddy validate --adapter caddyfile --config "$WORK/Caddyfile-${cdn}"
    done
    check_out "Cle de limite CF-Connecting-IP en mode cloudflare" 'key \{http\.request\.header\.CF-Connecting-IP\}' \
        cat "$WORK/fluxgate-cloudflare.caddy"
    if grep -E '__[A-Z_]+__' "$WORK/fluxgate-off.caddy" | grep -qv '__XXX__'; then
        fail "Marqueurs non remplaces dans le profil Caddy"
    else
        pass "Tous les marqueurs du profil Caddy remplaces"
    fi
fi

# =============================================================================
# check-config.sh
# =============================================================================
echo ""
echo "=== check-config ==="
# L'interface de l'exemple (eth0) peut ne pas exister ici
IFACE_REAL=$(ip -br link 2>/dev/null | awk '$1 != "lo" {sub(/@.*/, "", $1); print $1; exit}')
sed -i "s/^IFACE=.*/IFACE=\"${IFACE_REAL:-lo}\"/" "$WORK/config.env"
check "Exemple accepte" bash "${PROJECT_DIR}/scripts/check-config.sh"
cp "$WORK/config.env" "$WORK/config.bad"
sed -i 's/^SSH_MODE=.*/SSH_MODE="ouvert"/' "$WORK/config.bad"
check_fails "SSH_MODE invalide refuse" env FLUXGATE_CONFIG="$WORK/config.bad" bash "${PROJECT_DIR}/scripts/check-config.sh"
chmod 666 "$WORK/config.env"
check_fails "config.env modifiable par tous refuse" bash "${PROJECT_DIR}/scripts/check-config.sh"
chmod 600 "$WORK/config.env"

# =============================================================================
echo ""
echo "Resultat : ${PASS} reussis, ${FAIL} echoues, ${SKIP} sautes."
[[ $FAIL -eq 0 ]]
