# Changelog

Toutes les évolutions notables du projet.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

---

## [2.1.0] — 2026-10-26

Corrections issues de la revue du 26 octobre 2026 : d'abord ce qui pouvait
bloquer l'accès au serveur ou couper une protection sans prévenir, puis les
défauts de conception, puis les ajouts.

### Corrigé — risques de lockout et protections désactivées

- **Le filet anti-lockout ne vérifiait rien.** Le rollback `at` était annulé
  après un `sleep 3`, alors que la session en cours, déjà établie, survit à
  presque toutes les erreurs de règle. `deploy.sh` exige désormais qu'une
  **nouvelle** session SSH écrive un jeton aléatoire sous 120 s ; sinon
  l'ancien pare-feu est restauré. Avec `--yes`, une auto-vérification prend le
  relais (port SSH accepté, IP de session ni bannie ni hors `ADMIN_NETS`).
- **`nft-manage.sh apply` chargeait le modèle brut** (port SSH 22, `ADMIN_NETS`
  d'exemple). Il recharge maintenant `/etc/nftables.conf`, rendu avec vos
  valeurs, en conservant les bans. La section *reverse proxy* du README, qui
  conseillait la même copie, est corrigée.
- **Le WAF se désactivait un déploiement sur deux.** La détection cherchait
  `^modsecurity on;` alors que la ligne insérée est indentée : la directive
  était ajoutée en double, `nginx -t` échouait, et le repli retirait toutes les
  lignes `modsecurity`.
- **HTTPS ne s'activait jamais en locale C.** `ls /etc/letsencrypt/live | head -1`
  renvoyait `README`. Seuls les répertoires contenant `fullchain.pem` et
  `privkey.pem` sont retenus ; `NGINX_CERT_NAME` permet de choisir.
- **Limites globales SSH et HTTP.** 50 SYN/s usurpés suffisaient à couper le
  site pour tout le monde, et le bruit des scanners à bloquer SSH en mode
  ouvert. Toutes les limites sont désormais **par IP**, et par **/64** en IPv6.
- **ICMPv6 :** Neighbor Discovery, RA et Packet Too Big partageaient le seau des
  pings ; un ping flood coupait l'IPv6. Seul `echo-request` est limité.

### Changé — table dédiée

- **Table `inet fluxgate` au lieu de `flush ruleset`.** Chaque déploiement
  effaçait les règles de Docker, du bouncer CrowdSec, de wg-quick ou de
  Proxmox. FluxGate supprime et recrée uniquement sa table ; l'ancienne
  `inet filter` de la v2.0 est migrée. La politique forward devient
  configurable (`NFT_FORWARD_POLICY=auto|drop|accept`, `auto` détectant Docker,
  libvirt, LXC et `ip_forward`).

### Corrigé — autres bugs

- `/api/login` perdait sa limite stricte : le `sed` des `burst` s'appliquait à
  tout le fichier (5 devenait 50). Les endpoints sensibles ont leur propre
  `NGINX_LOGIN_BURST`.
- `crs-setup-override.conf` n'était jamais inclus. Il l'est, ses IDs sortent
  de la plage 900xxx réservée au CRS, et son rate-limit (dont l'`expirevar`
  rejoué à chaque requête aurait renvoyé un 429 à tout visiteur actif) est
  retiré au profit de NGINX.
- fail2ban (jail SSH) et CrowdSec lisaient `/var/log/auth.log`, absent sur
  Debian 12/13 : passage à `backend = systemd` et à la source `journalctl`.
- Le rollback ne survivait pas au reboot : `/etc/nftables.conf` est remis dans
  sa version d'origine (ou remplacé par un ruleset vide).
- Conflit de port entre l'API locale CrowdSec et `NGINX_UPSTREAM_PORT` (8080) :
  `CROWDSEC_LAPI_PORT=8081`, et `check-config.sh` détecte les collisions.
- `xdp-auto-block.sh` comptait les deux `src=` de chaque entrée conntrack (vos
  serveurs amont pouvaient être bannis), n'avait pas de liste blanche et
  ignorait `XDP_BLOCK_TIMEOUT` (bans permanents). Les trois sont corrigés, et
  `xdp-manage.sh` ne remplace plus `/usr/sbin/xdp-loader`.
- `status.sh` affichait « 0 0 » et ne comptait que `blocklist4`.
- Les alertes en pourcentage affichaient 1 % au lieu de 85 %
  (`humanizePercentage`).
- Le job Prometheus `crowdsec-bouncer` déclenchait un `ServiceDown` permanent
  sans CrowdSec : remplacé par un job `crowdsec` commenté.
- `listen … http2` (obsolète depuis nginx 1.25.1) n'est plus émis sur les
  versions récentes ; `ssl_stapling` retiré (Let's Encrypt a arrêté OCSP) ;
  HSTS `preload` devient optionnel (`HSTS_PRELOAD=false`).

### Changé — conception

- `CPUQuota=80%` (80 % d'**un** cœur) devient `SVC_CPU_QUOTA=auto`
  (nproc × 80 %).
- Le shaping `tc` n'utilise plus TBF (burst trop petit, et il remplaçait le
  `fq` dont BBR a besoin) : `cake` ou `fq maxrate` (`TC_QDISC`).
- `ALLOWED_METHODS` pilote NGINX et le CRS : `OPTIONS` (CORS) n'est plus
  bloqué, et `PUT PATCH DELETE` s'activent pour une API REST ou WebDAV.
- fail2ban reçoit `ignoreip` avec `ADMIN_NETS` : plus d'auto-bannissement.
- `config.env` est refusé s'il n'appartient pas à root avec les droits `600`.
- Valeurs par défaut centralisées dans `scripts/lib/defaults.sh` (elles étaient
  copiées dans quatre fichiers).

### Ajouté

- `EXTRA_TCP_PORTS` / `EXTRA_UDP_PORTS`, liste blanche `ALLOWLIST4/6` (avant
  limites et bans), limite de connexions simultanées par IP
  (`NFT_HTTP_CONN_LIMIT`, `ct count`).
- Listes de réputation (`REPUTATION_LISTS` : Spamhaus DROP, FireHOL level1…)
  rafraîchies par `fluxgate-lists.timer`.
- `CDN_MODE=cloudflare` : HTTP/HTTPS réservés aux plages Cloudflare, vraie IP
  restaurée dans NGINX.
- **Bouclier** (`shield on --for 30m`) : seuils resserrés, site joignable,
  retour automatique. `emergency-drop-all --for 15m` revient aussi seul.
- **Profil Caddy** (`caddy/`) : snippets d'en-têtes, méthodes et journal JSON
  pour le Caddy des dépôts, Coraza + OWASP CRS et caddy-ratelimit quand le
  binaire les contient (`caddy/build-caddy.sh`), collection CrowdSec
  `crowdsecurity/caddy`. Le Caddyfile de l'utilisateur n'est pas modifié.
- **Exporteur FluxGate** (textfile collector, chaque minute) : compteurs par
  règle nftables, IP bannies, réputation, bouclier, urgence, XDP, fail2ban,
  CrowdSec, 429 NGINX et blocages WAF. Nouvelles alertes de protection et
  **Alertmanager vers Discord**.
- **Commande `fluxgate`** (`/usr/local/sbin/fluxgate`) avec menu
  gum / whiptail / texte.
- `deploy.sh --dry-run`, `--diff` et `--yes`.
- Persistance : bans sauvegardés et restaurés avec leur durée restante, XDP
  rechargé au boot (`fluxgate-xdp.service`).
- `validate.sh` teste en réel : injection SQL → 403, rafale → 429
  (`--no-active` pour s'en passer).
- `migrate-config.sh` complète un ancien `config.env` sans écraser de valeur.
- logrotate pour `/var/log/fluxgate` et les journaux ModSecurity.
- `tests/test-runtime.sh` et job CI `runtime` : ruleset chargé dans des
  espaces de noms réseau avec trafic réel par veth (HTTP, SSH strict, ban,
  urgence), nft-manage, exporteur et CLI, `nginx -t` des rendus HTTP/HTTPS,
  `fail2ban-regex`, `caddy validate`, `check-config.sh`.

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
