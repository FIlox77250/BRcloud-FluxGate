#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Preservation des IP bloquees
# =============================================================================
# Un redeploiement passe par 'flush ruleset', qui recree les sets vides. Sans
# precaution, tous les attaquants bannis sont relaches d'un coup, au pire
# moment. Ces fonctions relevent les adresses avant, pour les reinjecter apres.
#
# Pourquoi une lib separee plutot que du code en ligne dans deploy.sh :
#   La premiere version etait une pipeline dans une substitution de commande.
#   Quand la blocklist est VIDE, grep ne trouve rien et sort en 1 ; sous
#   'set -o pipefail' l'affectation echoue et deploy.sh s'arretait en silence
#   juste avant de redemarrer nftables. Le cas "aucune IP bloquee" est le cas
#   NORMAL d'un premier deploiement : il doit etre traite comme tel, et c'est
#   testable seulement si la fonction accepte son entree en argument.
# =============================================================================

# -----------------------------------------------------------------------------
# parse_blocklist_ips <texte> <famille>
#   texte   : sortie de 'nft list set inet filter blocklistN'
#   famille : 4 ou 6
# Affiche les adresses trouvees, separees par des espaces. Aucune adresse =
# sortie vide et code retour 0 : ce n'est pas une erreur.
# -----------------------------------------------------------------------------
parse_blocklist_ips() {
    local text="${1:-}"
    local family="${2:-4}"
    local pattern

    if [[ "$family" == "6" ]]; then
        pattern='\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b'
    else
        pattern='\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'
    fi

    [[ -n "$text" ]] || return 0

    # Chaque '|| true' couvre le cas "aucune correspondance", qui est legitime.
    local elements
    elements=$(sed -n '/elements = {/,/}/p' <<< "$text" || true)
    [[ -n "$elements" ]] || return 0

    local ips
    ips=$(grep -oE "$pattern" <<< "$elements" | sort -u || true)
    [[ -n "$ips" ]] || return 0

    tr '\n' ' ' <<< "$ips"
    return 0
}

# -----------------------------------------------------------------------------
# save_blocklists
# Renseigne SAVED_BLOCKED4 / SAVED_BLOCKED6 depuis le ruleset en cours.
# -----------------------------------------------------------------------------
save_blocklists() {
    SAVED_BLOCKED4=""
    SAVED_BLOCKED6=""

    local raw
    if raw=$(nft list set inet filter blocklist4 2>/dev/null); then
        SAVED_BLOCKED4=$(parse_blocklist_ips "$raw" 4)
    fi
    if raw=$(nft list set inet filter blocklist6 2>/dev/null); then
        SAVED_BLOCKED6=$(parse_blocklist_ips "$raw" 6)
    fi

    # wc sur une chaine vide renvoie 0 : pas de cas particulier a gerer
    echo "$SAVED_BLOCKED4 $SAVED_BLOCKED6" | wc -w
}

# -----------------------------------------------------------------------------
# restore_blocklists <ips_v4> <ips_v6>
# Reinjecte les adresses. Le temps d'expiration restant n'etant pas
# conservable, les entrees repartent sur le timeout par defaut du set.
# -----------------------------------------------------------------------------
restore_blocklists() {
    local ips4="${1:-}"
    local ips6="${2:-}"
    local restored=0
    local ip

    for ip in $ips4; do
        nft add element inet filter blocklist4 "{ $ip }" 2>/dev/null && restored=$((restored+1))
    done
    for ip in $ips6; do
        nft add element inet filter blocklist6 "{ $ip }" 2>/dev/null && restored=$((restored+1))
    done

    echo "$restored"
}
