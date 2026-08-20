# Changelog

Toutes les évolutions notables du projet.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

---

## [2.0.0] — 2026-08-20

Reprise du projet après une période sans maintenance. Le socle multi-couche est
conservé ; cette version corrige des défauts de fond et remet les composants
tiers à jour.

### Corrigé

- **`config.env` n'était appliqué qu'à moitié.** Sur une quarantaine de
  variables, une dizaine seulement était réellement câblée. `NFT_SYN_RATE`,
  `CONNTRACK_MAX`, `SOMAXCONN`, `TCP_MAX_SYN_BACKLOG`, tous les `SVC_*`,
  `F2B_HTTP_*`, `APACHE_*` n'apparaissaient nulle part ailleurs que dans
  l'exemple : les modifier n'avait aucun effet. Toutes sont désormais
  appliquées, et une ancre de substitution manquante fait échouer le
  déploiement au lieu de repartir en silence sur les valeurs par défaut.
- **Le déploiement pouvait s'arrêter à l'étape 2/8.** `sysctl --system` sortait
  en erreur quand `nf_conntrack` n'était pas chargé et, sous `set -o pipefail`,
  interrompait tout le script. Le module est maintenant chargé au préalable
  (et persisté), et les erreurs sysctl sont journalisées sans être fatales.
- **Le filet anti-lockout nftables ne restaurait rien.** Le backup produit par
  `nft list ruleset` ne contient pas de `flush ruleset` : le rejouer empilait
  les règles sur celles en place. Le `flush` est désormais écrit en tête.
- **Le rollback HTTPS de NGINX ne se déclenchait jamais.** Le motif `sed` de
  secours cherchait `^--- HTTPS BEGIN ---` là où le marqueur réel est
  `# --- HTTPS BEGIN ---`. En cas d'échec de `nginx -t` après activation d'un
  certificat, la configuration restait cassée. La conf de référence est
  maintenant restaurée puis rechargée.
- **Risque de lockout en IPv6.** `ADMIN_NETS` était un set IPv4 uniquement :
  une session SSH arrivant en IPv6 tombait sur le rate-limit `5/minute` sans
  possibilité d'être whitelistée. Ajout de `ADMIN_NETS6` et d'une règle admin
  IPv6 symétrique ; la détection anti-lockout reconnaît la famille de l'IP.
- **Une syntaxe nftables invalide n'était plus bloquante.** `nft -c -f` en échec
  se contentait d'un avertissement avant d'appliquer quand même. Le déploiement
  s'interrompt désormais, règles courantes intactes.
- **Les limites systemd ne s'appliquaient à aucun service.** Le dossier
  `fluxgate-web.service.d` était copié tel quel dans `/etc/systemd/system/` ;
  systemd n'applique un drop-in que dans `<service>.service.d/`. Le service
  cible est maintenant désigné par `SVC_NAME`.
- **`emergency-drop-all` n'était pas restrictif.** La commande acceptait le port
  SSH depuis n'importe quelle source malgré son intitulé « sauf SSH admin ».
  Elle respecte désormais `ADMIN_NETS` / `ADMIN_NETS6`, sauvegarde le ruleset
  courant, et une commande `restore` permet de revenir en arrière.
- `SC2155` corrigé dans `deploy.sh` (`local` et affectation séparés).

### Mise à jour depuis la v1

Deux défauts rendaient la mise à jour d'un serveur déjà déployé impossible ou
inopérante ; ils sont corrigés :

- **`check-config.sh` bloquait toute mise à jour.** Un `config.env` de la v1 ne
  contient pas les 17 clés ajoutées depuis ; elles étaient traitées comme des
  erreurs fatales et le déploiement s'arrêtait avant de commencer. Ces clés sont
  désormais des avertissements, avec repli sur les valeurs par défaut et renvoi
  vers `migrate-config.sh`.
- **Le CRS n'était jamais mis à jour.** La condition testait l'existence du
  répertoire de règles, pas la version : un serveur déjà déployé serait resté
  indéfiniment en 4.0.0, alors que c'est le principal apport de cette version.
  `crs_needs_update()` compare la version réellement installée à la cible.

Ajout de `scripts/migrate-config.sh` (fusion des clés manquantes sans écraser
les valeurs existantes, idempotent, `--dry-run` disponible) et préservation des
IP bloquées à travers le `flush ruleset` d'un redéploiement.

Procédure complète dans le README, section « Mettre à jour un serveur déjà
déployé ».

### Ajouté

- `scripts/check-config.sh` — validation de `config.env` avant tout déploiement :
  placeholders, bornes numériques, existence de l'interface, cohérence du port
  SSH avec ce qui écoute réellement, format des sets nftables.
- `scripts/lib/nft-template.sh` — application de `config.env` dans
  `nftables.conf`, avec vérification préalable de chaque ancre.
- `scripts/lib/crs.sh` — installation de l'OWASP CRS avec vérification sha256
  **et** signature GPG. Remplace deux `curl | tar` non vérifiés dupliqués.
- `fail2ban/action.d/fluxgate-nft.conf` — action bannissant dans les sets
  FluxGate (`blocklist4` / `blocklist6`) au lieu d'une table `f2b` séparée :
  les bans manuels, fail2ban et CrowdSec sont visibles au même endroit.
- `tests/test-templating.sh` — 27 assertions sur le rendu du pare-feu, dont la
  non-régression des limites ICMP et l'ordre SYNPROXY / drop des invalides.
- CI GitHub Actions : shellcheck, syntaxe `nft -c -f` sur trois rendus
  différents, tests, validation de `config.env.example`, lint YAML, et contrôle
  des fins de ligne.
- `.gitattributes` — verrouille les fins de ligne en LF. Avec
  `core.autocrlf=true` côté Windows, les scripts partaient en CRLF et
  échouaient sur le serveur avec « bad interpreter ».
- `LICENSE` (MIT) — annoncé dans le README depuis le début, mais absent du dépôt.
- SYNPROXY optionnel, désactivé par défaut, avec confirmation interactive.
- Commande `nft-manage.sh restore`.
- Contrôle de congestion **BBR** + qdisc **fq** dans les sysctl, avec repli
  automatique en `cubic` si le noyau ne fournit pas `bbr`.

### Modifié

- **OWASP CRS 4.0.0 → 4.29.0.** La version épinglée datait de janvier 2024.
- **CrowdSec** : `curl -s https://install.crowdsec.net | bash` remplacé par la
  déclaration directe du dépôt packagecloud signé. Exécuter en root un script
  téléchargé à la volée donnait au serveur distant un contrôle total sur la
  machine.
- `validate.sh` vérifie en plus : BBR/fq, parité IPv6 du ruleset, cohérence
  SYNPROXY, persistance de nftables au reboot, présence d'une règle SSH,
  version du CRS installée, `unicode.mapping`, action fail2ban.
- `rollback.sh` nettoie les nouveaux artefacts (modprobe.d, modules-load.d,
  action fail2ban, drop-in systemd du service ciblé).
- Pré-requis documentés en distributions réellement visées plutôt qu'en
  « kernel >= 4.4 ».
- README : structure du dépôt remise à jour (sept répertoires n'y figuraient
  pas), sections configuration, SYNPROXY, chaîne d'approvisionnement.

### Sécurité

- Aucune archive tierce n'est extraite sans vérification d'intégrité.
- Plus aucun script distant n'est exécuté en root pendant l'installation.

---

## [1.0.0] — 2024

Version initiale : stack anti-DDoS 7 couches, scripts d'installation, de
déploiement, de validation, de rollback et de supervision.
