#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Migration de config.env
# =============================================================================
# Ajoute a un config.env existant les cles apparues dans une nouvelle version,
# sans jamais toucher aux valeurs deja renseignees.
#
#   bash scripts/migrate-config.sh              # applique
#   bash scripts/migrate-config.sh --dry-run    # montre sans rien ecrire
#
# Pourquoi c'est necessaire :
#   La v2.0 introduit des cles obligatoires (ADMIN_NETS6, NFT_HTTP_SYN_RATE...).
#   Un config.env de la v1 les ignore, et le deploiement s'arrete a la
#   validation. Recopier config.env.example ferait perdre tous vos reglages :
#   ce script fait la fusion dans le bon sens.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.env"
EXAMPLE_FILE="${SCRIPT_DIR}/config.env.example"

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()  { echo -e "${RED}[ERREUR]${NC} $*" >&2; }

echo ""
echo -e "${CYAN}=============================================${NC}"
echo "  BRCloud FluxGate - Migration de config.env"
echo -e "${CYAN}=============================================${NC}"
echo ""

if [[ ! -f "$EXAMPLE_FILE" ]]; then
    log_err "Modele introuvable : $EXAMPLE_FILE"
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    log_warn "Aucun config.env existant."
    log_info "Il s'agit d'une premiere installation :"
    log_info "  cp $EXAMPLE_FILE $CONFIG_FILE"
    exit 0
fi

# -----------------------------------------------------------------------------
# Reperer les cles manquantes
# -----------------------------------------------------------------------------
# On compare les noms de variables, pas les lignes : une valeur personnalisee
# ne doit jamais etre consideree comme une difference a corriger.
mapfile -t EXAMPLE_KEYS < <(grep -oE '^[A-Z_][A-Z0-9_]*=' "$EXAMPLE_FILE" | tr -d '=')

MISSING=()
for key in "${EXAMPLE_KEYS[@]}"; do
    if ! grep -qE "^[[:space:]]*${key}=" "$CONFIG_FILE"; then
        MISSING+=("$key")
    fi
done

# Cles presentes chez l'utilisateur mais disparues du modele : on les signale
# sans y toucher, elles peuvent etre volontaires.
mapfile -t CONFIG_KEYS < <(grep -oE '^[A-Z_][A-Z0-9_]*=' "$CONFIG_FILE" | tr -d '=')
OBSOLETE=()
for key in "${CONFIG_KEYS[@]}"; do
    if ! printf '%s\n' "${EXAMPLE_KEYS[@]}" | grep -qx "$key"; then
        OBSOLETE+=("$key")
    fi
done

if [[ ${#MISSING[@]} -eq 0 ]]; then
    log_info "config.env est deja a jour (${#CONFIG_KEYS[@]} cles, aucune manquante)."
    if [[ ${#OBSOLETE[@]} -gt 0 ]]; then
        echo ""
        log_warn "Cles presentes chez vous mais absentes du modele : ${OBSOLETE[*]}"
        log_warn "Elles ne sont pas supprimees. Verifier si elles servent encore."
    fi
    echo ""
    exit 0
fi

echo "Cles a ajouter (${#MISSING[@]}) :"
for key in "${MISSING[@]}"; do
    value=$(grep -E "^${key}=" "$EXAMPLE_FILE" | head -1 | cut -d= -f2-)
    printf '  %-28s = %s\n' "$key" "$value"
done
echo ""

if [[ ${#OBSOLETE[@]} -gt 0 ]]; then
    log_warn "Cles chez vous mais absentes du modele (conservees) : ${OBSOLETE[*]}"
    echo ""
fi

if [[ "$DRY_RUN" == "true" ]]; then
    log_info "Mode --dry-run : aucune modification ecrite."
    echo ""
    exit 0
fi

# -----------------------------------------------------------------------------
# Sauvegarde puis ajout
# -----------------------------------------------------------------------------
BACKUP="${CONFIG_FILE}.bak-$(date +%Y%m%d-%H%M%S)"
cp "$CONFIG_FILE" "$BACKUP"
log_info "Sauvegarde : $BACKUP"

{
    echo ""
    echo "# ============================================================================="
    echo "# Cles ajoutees par migrate-config.sh le $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Valeurs par defaut du modele : les relire et les adapter si besoin."
    echo "# ============================================================================="
} >> "$CONFIG_FILE"

for key in "${MISSING[@]}"; do
    # Recuperer les lignes de commentaire qui precedent la cle dans le modele,
    # pour ne pas perdre l'explication qui va avec la valeur.
    awk -v k="$key" '
        /^#/            { buf = buf $0 "\n"; next }
        /^[[:space:]]*$/ { buf = ""; next }
        $0 ~ "^" k "="  { printf "%s%s\n", buf, $0; exit }
                        { buf = "" }
    ' "$EXAMPLE_FILE" >> "$CONFIG_FILE"
done

ADDED=$(grep -cE '^[A-Z_][A-Z0-9_]*=' "$CONFIG_FILE")
echo ""
log_info "${#MISSING[@]} cle(s) ajoutee(s). config.env contient maintenant $ADDED cles."
echo ""
log_info "Etape suivante : verifier la configuration"
echo "    bash ${SCRIPT_DIR}/check-config.sh"
echo ""
log_warn "Relire en particulier ADMIN_NETS et ADMIN_NETS6 : les valeurs par"
log_warn "defaut ne couvrent que les reseaux prives, pas une IP publique."
echo ""
