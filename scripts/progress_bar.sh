#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Shareable Bash Progress Bar Helper
# =============================================================================
# Fournit une fonction native de barre de progression avec zero dependance.
# Usage :
#   source progress_bar.sh
#   show_progress 3 8 "Pare-feu nftables"
# =============================================================================

show_progress() {
    local current="${1:-0}"
    local total="${2:-10}"
    local message="${3:-En cours...}"
    
    local width=25
    # Calculer le pourcentage de chargement
    local percentage=$(( current * 100 / total ))
    # Calculer le nombre de blocs remplis
    local filled=$(( current * width / total ))
    local empty=$(( width - filled ))
    
    # Couleurs ANSI
    local GREEN='\033[0;32m'
    local CYAN='\033[0;36m'
    local NC='\033[0m'
    
    # Construire la chaine graphique de la barre
    local bar=""
    for ((i=0; i<filled; i++)); do bar="${bar}█"; done
    for ((i=0; i<empty; i++)); do bar="${bar}░"; done
    
    # Affichage propre sur une seule ligne (effacement de fin de ligne via \033[K)
    printf "\r${CYAN}[Étape %d/%d]${NC} ${GREEN}[%s]${NC} %3d%% - %s\033[K" "$current" "$total" "$bar" "$percentage" "$message"
    
    # Ajouter un saut de ligne automatique a la fin
    if [[ "$current" -eq "$total" ]]; then
        echo ""
    fi
}
