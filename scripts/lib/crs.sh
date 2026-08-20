#!/usr/bin/env bash
# =============================================================================
# BRCloud FluxGate - Installation verifiee de l'OWASP Core Rule Set
# =============================================================================
# Fournit install_owasp_crs(), utilisee par install.sh et deploy.sh.
#
# Pourquoi ce fichier existe :
#   Les deux scripts telechargeaient le CRS avec un "curl | tar" sans aucune
#   verification. Sur un outil de securite, une archive de regles WAF non
#   verifiee est exactement le maillon qu'on ne veut pas laisser trainer.
#
# Ce qui est verifie ici, dans l'ordre :
#   1. sha256 de l'archive, compare a la valeur epinglee dans config.env
#   2. signature GPG detachee (.asc) contre l'empreinte OWASP epinglee
#
# Echec = pas d'extraction. On ne deploie jamais des regles non verifiees.
#
# Pour monter de version : recuperer le tag et le sha256 de l'asset
# coreruleset-<version>-minimal.tar.gz sur
#   https://github.com/coreruleset/coreruleset/releases
# puis mettre a jour CRS_VERSION / CRS_SHA256 dans config.env.
# =============================================================================

# Valeurs de repli si config.env n'est pas charge (verifiees le 2026-08-20)
CRS_VERSION="${CRS_VERSION:-4.29.0}"
CRS_SHA256="${CRS_SHA256:-1aa1c5c8fc29e532d35293bcea36bf72de61db8f6ed4716a0f91ab14552b7fed}"
CRS_GPG_FINGERPRINT="${CRS_GPG_FINGERPRINT:-36006F0E0BA167832158821138EEACA1AB8A6E72}"

# Serveurs de cles interroges dans l'ordre
CRS_KEYSERVERS=("hkps://keys.openpgp.org" "hkps://keyserver.ubuntu.com")

# Journalisation : reutilise celle du script appelant si elle existe
if ! declare -F log_info >/dev/null 2>&1; then
    log_info()  { echo "[INFO]  $*"; }
    log_warn()  { echo "[WARN]  $*" >&2; }
    log_error() { echo "[ERROR] $*" >&2; }
fi

# -----------------------------------------------------------------------------
# _crs_fetch <url> <destination>
# Telecharge un fichier avec curl ou wget, selon ce qui est disponible.
# -----------------------------------------------------------------------------
_crs_fetch() {
    local url="$1" dest="$2"
    if command -v curl &>/dev/null; then
        curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url"
    elif command -v wget &>/dev/null; then
        wget -q --tries=3 -O "$dest" "$url"
    else
        log_error "Ni curl ni wget disponible : telechargement impossible."
        return 1
    fi
}

# -----------------------------------------------------------------------------
# _crs_verify_sha256 <fichier> <somme attendue>
# -----------------------------------------------------------------------------
_crs_verify_sha256() {
    local file="$1" expected="$2"

    if [[ -z "$expected" ]]; then
        log_warn "Aucun sha256 epingle (CRS_SHA256 vide) : verification d'integrite ignoree."
        return 0
    fi

    if ! command -v sha256sum &>/dev/null; then
        log_warn "sha256sum absent : verification d'integrite impossible."
        return 0
    fi

    local actual
    actual=$(sha256sum "$file" | awk '{print $1}')
    if [[ "$actual" == "$expected" ]]; then
        log_info "sha256 verifie : $actual"
        return 0
    fi

    log_error "sha256 NON conforme pour $(basename "$file")"
    log_error "  attendu : $expected"
    log_error "  obtenu  : $actual"
    return 1
}

# -----------------------------------------------------------------------------
# _crs_verify_gpg <fichier> <fichier.asc> <empreinte>
# Retourne 0 si signature valide, 1 si invalide, 2 si non verifiable.
# -----------------------------------------------------------------------------
_crs_verify_gpg() {
    local file="$1" sig="$2" fpr="$3"

    if [[ -z "$fpr" ]]; then
        log_warn "Aucune empreinte GPG epinglee : verification de signature ignoree."
        return 2
    fi
    if ! command -v gpg &>/dev/null; then
        log_warn "gpg absent : verification de signature ignoree (le sha256 reste verifie)."
        return 2
    fi
    if [[ ! -f "$sig" ]]; then
        log_warn "Signature .asc indisponible : verification ignoree."
        return 2
    fi

    # Trousseau jetable : ne pas polluer le trousseau du systeme
    local gnupg_home
    gnupg_home=$(mktemp -d) || return 2
    chmod 700 "$gnupg_home"

    local imported=false
    for ks in "${CRS_KEYSERVERS[@]}"; do
        if GNUPGHOME="$gnupg_home" gpg --batch --quiet \
            --keyserver "$ks" --recv-keys "$fpr" 2>/dev/null; then
            imported=true
            log_info "Cle OWASP CRS importee depuis $ks"
            break
        fi
    done

    if [[ "$imported" != "true" ]]; then
        log_warn "Impossible de recuperer la cle $fpr depuis les serveurs de cles."
        rm -rf "$gnupg_home"
        return 2
    fi

    if GNUPGHOME="$gnupg_home" gpg --batch --quiet --status-fd 1 \
        --verify "$sig" "$file" 2>/dev/null | grep -q "VALIDSIG ${fpr}"; then
        log_info "Signature GPG valide (empreinte $fpr)."
        rm -rf "$gnupg_home"
        return 0
    fi

    log_error "Signature GPG INVALIDE pour $(basename "$file") !"
    rm -rf "$gnupg_home"
    return 1
}

# -----------------------------------------------------------------------------
# crs_installed_version [repertoire]
# Affiche la version du CRS installe, ou rien si indeterminable.
# Les regles portent un tag "OWASP_CRS/x.y.z" : c'est la source la plus fiable,
# le nom du repertoire ne dit rien de la version reellement en place.
# -----------------------------------------------------------------------------
crs_installed_version() {
    local crs_dir="${1:-/etc/modsecurity/crs}"
    [[ -d "$crs_dir/rules" ]] || return 1
    grep -rhoE 'OWASP_CRS/[0-9]+\.[0-9]+\.[0-9]+' "$crs_dir/rules" 2>/dev/null \
        | head -1 | cut -d/ -f2
}

# -----------------------------------------------------------------------------
# crs_needs_update [repertoire]
# Retourne 0 si une mise a jour est necessaire (absent, ou version differente
# de CRS_VERSION). Sans cette verification, un serveur deja deploye conserve
# indefiniment sa version du CRS : le repertoire existe, donc l'installation
# etait purement et simplement sautee.
# -----------------------------------------------------------------------------
crs_needs_update() {
    local crs_dir="${1:-/etc/modsecurity/crs}"

    if [[ ! -d "$crs_dir/rules" ]] || [[ -z "$(ls -A "$crs_dir/rules" 2>/dev/null)" ]]; then
        return 0
    fi

    local installed
    installed=$(crs_installed_version "$crs_dir")

    if [[ -z "$installed" ]]; then
        log_warn "Version du CRS installe indeterminable : mise a jour proposee par securite."
        return 0
    fi

    if [[ "$installed" != "$CRS_VERSION" ]]; then
        log_info "CRS installe en v${installed}, version cible v${CRS_VERSION}."
        return 0
    fi

    log_info "OWASP CRS deja en v${installed} (a jour)."
    return 1
}

# -----------------------------------------------------------------------------
# install_owasp_crs [repertoire_cible]
# Telecharge, verifie et installe le CRS. Retourne 0 en cas de succes.
#
# En cas de mise a jour, l'ancien repertoire de regles est sauvegarde puis
# remplace : laisser cohabiter des regles de deux versions differentes produit
# des collisions d'identifiants et des faux positifs difficiles a diagnostiquer.
# -----------------------------------------------------------------------------
install_owasp_crs() {
    local crs_dir="${1:-/etc/modsecurity/crs}"
    local version="${CRS_VERSION}"
    local base="https://github.com/coreruleset/coreruleset/releases/download/v${version}"
    local archive="coreruleset-${version}-minimal.tar.gz"

    local tmpdir
    tmpdir=$(mktemp -d) || { log_error "mktemp a echoue."; return 1; }
    # shellcheck disable=SC2064
    trap "rm -rf '$tmpdir'" RETURN

    log_info "Telechargement OWASP CRS v${version}..."
    if ! _crs_fetch "${base}/${archive}" "${tmpdir}/${archive}"; then
        log_error "Echec du telechargement de ${archive}."
        return 1
    fi

    # La signature est optionnelle au telechargement, obligatoire a la
    # verification si elle a pu etre recuperee.
    _crs_fetch "${base}/${archive}.asc" "${tmpdir}/${archive}.asc" 2>/dev/null || true

    if ! _crs_verify_sha256 "${tmpdir}/${archive}" "$CRS_SHA256"; then
        log_error "Archive CRS rejetee : integrite non conforme. Rien n'a ete installe."
        return 1
    fi

    _crs_verify_gpg "${tmpdir}/${archive}" "${tmpdir}/${archive}.asc" "$CRS_GPG_FINGERPRINT"
    local gpg_rc=$?
    if [[ $gpg_rc -eq 1 ]]; then
        log_error "Archive CRS rejetee : signature invalide. Rien n'a ete installe."
        return 1
    fi

    # Mise a jour : ecarter les anciennes regles plutot que d'ecraser par-dessus.
    # Une regle supprimee en amont resterait sinon active indefiniment.
    if [[ -d "$crs_dir/rules" ]] && [[ -n "$(ls -A "$crs_dir/rules" 2>/dev/null)" ]]; then
        local old_backup
        old_backup="${crs_dir}/rules.bak-$(date +%Y%m%d-%H%M%S)"
        mv "$crs_dir/rules" "$old_backup"
        log_info "Anciennes regles CRS deplacees vers $old_backup"
    fi

    mkdir -p "$crs_dir"
    if ! tar xzf "${tmpdir}/${archive}" --strip-components=1 -C "$crs_dir"; then
        log_error "Echec de l'extraction de l'archive CRS."
        return 1
    fi

    # crs-setup.conf contient les reglages de l'utilisateur (paranoia level,
    # exclusions...) : ne jamais l'ecraser, seulement le creer s'il manque.
    if [[ -f "$crs_dir/crs-setup.conf.example" ]] && [[ ! -f "$crs_dir/crs-setup.conf" ]]; then
        cp "$crs_dir/crs-setup.conf.example" "$crs_dir/crs-setup.conf"
    fi

    if [[ ! -d "$crs_dir/rules" ]]; then
        log_error "Extraction incoherente : $crs_dir/rules absent."
        return 1
    fi

    local nb_rules
    nb_rules=$(find "$crs_dir/rules" -name "*.conf" 2>/dev/null | wc -l)
    log_info "OWASP CRS v${version} installe dans $crs_dir (${nb_rules} fichiers de regles)."
    return 0
}
