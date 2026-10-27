# 🛡️ BRCloud FluxGate

> Stack anti-DDoS multi-couche pour serveur Linux single-host.
> Filtrage en profondeur, du pilote réseau (XDP/eBPF) jusqu'aux limites de ressources applicatives.

[![CI](https://github.com/FIlox77250/BRcloud-FluxGate/actions/workflows/ci.yml/badge.svg)](https://github.com/FIlox77250/BRcloud-FluxGate/actions/workflows/ci.yml)

---

## Architecture

```
Paquet entrant
      │
      ├─ [1] XDP / eBPF          DROP ultra-rapide (dizaines de Mpps)
      ├─ [2] Kernel Tuning       SYN cookies, backlogs, conntrack, BBR/fq
      ├─ [3] nftables L3/L4      Table inet fluxgate, limites par IP (/64 en IPv6),
      │                          réputation, bouclier, SYNPROXY (opt.)
      ├─ [4] systemd             Limites CPU/RAM/FD, connexions max par IP source
      ├─ [5] Nginx / Apache / Caddy  Leaky bucket, anti-slowloris, 429
      ├─ [6] WAF ModSecurity     OWASP CRS (Coraza en profil Caddy) — SQLi & XSS
      └─ [7] Application         Isolation cgroups (CPU, RAM max)
```

---

## Pré-requis

| Élément       | Requis                                                        |
|---------------|---------------------------------------------------------------|
| **OS**        | Debian 12/13, Ubuntu 22.04/24.04, ou RHEL 9+ / Fedora / Rocky  |
| **Kernel**    | `>= 5.10` (BBR, sets dynamiques nftables, XDP natif)          |
| **nftables**  | `>= 0.9.8`                                                    |
| **Accès**     | `root` complet (`sudo`)                                       |
| **Réseau**    | Carte compatible XDP (fallback auto en mode générique `skb`)  |

> Le noyau `>= 4.4` reste techniquement supporté, mais sans BBR ni SYNPROXY :
> le déploiement bascule automatiquement sur `cubic` et saute ces options.

---

## Installation

### 1. Cloner le repo sur le serveur

```bash
git clone https://github.com/FIlox77250/BRcloud-FluxGate.git
cd BRcloud-FluxGate
```

### 2. Configurer

```bash
cp scripts/config.env.example scripts/config.env
nano scripts/config.env
bash scripts/check-config.sh      # valide avant de toucher au serveur
```

> ⚠️ **À adapter impérativement :**
> - `IFACE` — interface réseau publique (ex : `eth0`, `ens33`, `enp1s0`)
> - `SSH_PORT` — port SSH actuel (critique pour éviter le lockout)
> - `ADMIN_NETS` / `ADMIN_NETS6` — vos réseaux d'administration, **dans les deux familles**

`check-config.sh` refuse les placeholders, les ports incohérents et les valeurs
hors bornes, et vous prévient si rien n'écoute sur le `SSH_PORT` déclaré.
Il est relancé automatiquement au début de `deploy.sh`.

### 3. Installer les dépendances

```bash
sudo bash scripts/install.sh
```

Détecte l'OS, répare le gestionnaire de paquets si besoin, et propose un menu
interactif (serveur web + modules de monitoring). Option *Premium* : installe
`figlet`, `gum` et `glow` via les dépôts Charm.sh.

### 4. Déployer

```bash
sudo bash scripts/deploy.sh
```

> 🔒 **Anti-lockout SSH** — le script détecte l'IP de ta session active (IPv4 **ou**
> IPv6) et propose de l'injecter à chaud dans le bon set admin si elle n'est pas
> whitelistée. Après le chargement du pare-feu, il affiche un jeton et attend
> **120 s** qu'une **nouvelle** session SSH l'écrive
> (`echo <jeton> | sudo tee /run/fluxgate/confirm`). La session en cours ne
> prouve rien : déjà établie, elle survit à presque toutes les erreurs de règle.
> Sans confirmation (ou touche `r`), l'ancien pare-feu est restauré ; le job
> `at` de 5 min reste le dernier filet si le script lui-même est coupé.

Options de `deploy.sh` :

| Option      | Effet |
|-------------|-------|
| `--dry-run` | rend le pare-feu et les sysctl dans un répertoire temporaire et vérifie le ruleset (`nft -c`), sans rien modifier |
| `--diff`    | comme `--dry-run`, avec le diff par rapport aux fichiers installés |
| `--yes`     | aucune question (Ansible, cloud-init) : `config.env` fait foi, et la confirmation SSH est remplacée par une auto-vérification (port SSH accepté, IP de session ni bannie ni hors `ADMIN_NETS` en mode strict) |

### 5. Valider

```bash
sudo bash scripts/validate.sh
```

Diagnostic complet : sysctl, congestion BBR, nftables (dont parité IPv6 et
cohérence SYNPROXY), persistance au reboot, WAF, jails fail2ban, seuils conntrack.
Il teste aussi **en réel** : une injection SQL envoyée à NGINX doit recevoir un
403 du WAF, et une rafale de requêtes doit déclencher des 429. `--no-active`
saute ces requêtes.

---

## Mettre à jour un serveur déjà déployé

```bash
cd ~/BRcloud-FluxGate

# 1. Récupérer la nouvelle version
git pull

# 2. Compléter config.env sans perdre vos réglages
bash scripts/migrate-config.sh

# 3. Relire les clés ajoutées, surtout ADMIN_NETS / ADMIN_NETS6
nano scripts/config.env
bash scripts/check-config.sh

# 4. Redéployer (les dépendances sont déjà installées)
sudo bash scripts/deploy.sh

# 5. Vérifier
sudo bash scripts/validate.sh
```

`migrate-config.sh` ajoute uniquement les clés manquantes, avec leur commentaire
d'origine, après avoir sauvegardé votre fichier. **Vos valeurs actuelles ne sont
jamais écrasées.** Le script est idempotent : le relancer ne fait rien de plus.
`--dry-run` montre ce qui serait ajouté sans écrire.

> Si vous aviez cloné depuis un zip plutôt qu'avec git, remplacez l'étape 1 par
> un `git clone` dans un répertoire neuf, puis recopiez-y votre ancien
> `scripts/config.env` avant l'étape 2.

### Ce que la mise à jour change sur le serveur

| Élément | Effet |
|---|---|
| **OWASP CRS** | passe de la version installée à `CRS_VERSION` ; les anciennes règles sont déplacées en `rules.bak-<date>` |
| **`crs-setup.conf`** | **conservé** — vos réglages (paranoia level, exclusions) ne sont pas touchés |
| **Ruleset nftables** | FluxGate vit désormais dans sa propre table `inet fluxgate`, supprimée puis recréée : les tables de Docker, du bouncer CrowdSec, de wg-quick ou de Proxmox ne sont plus effacées. L'ancienne table `inet filter` de FluxGate ≤ 2.0 est retirée. Les bans sont relevés puis réinjectés |
| **fail2ban** | les jails basculent sur `banaction = fluxgate-nft` ; les bans de l'ancienne table `f2b` sont perdus au redémarrage du service |
| **Limites systemd** | désormais appliquées à `SVC_NAME` ; **actives seulement après `systemctl restart <service>`** |
| **sysctl** | ajout de BBR/fq, repli automatique en `cubic` si indisponible |

L'ancien dossier `/etc/systemd/system/fluxgate-web.service.d/` peut subsister
sans effet (il ne correspondait à aucun service réel). Le supprimer est sans
risque :

```bash
sudo rm -rf /etc/systemd/system/fluxgate-web.service.d
sudo systemctl daemon-reload
```

### Filet de sécurité

Le redéploiement conserve les protections déjà en place :

- sauvegarde du ruleset courant dans `/etc/nftables.conf.bak`, **rejouable tel quel**
- confirmation obligatoire depuis une nouvelle session SSH (voir *Déployer*),
  et rollback `at` à 5 minutes en dernier recours
- interruption immédiate si la nouvelle configuration nftables est invalide,
  règles courantes intactes
- `--dry-run` / `--diff` pour voir les changements avant de les appliquer

Garder une seconde session SSH ouverte pendant l'opération : elle sert à la
confirmation.

---

## Configuration centralisée

Toutes les valeurs de `scripts/config.env` sont **réellement appliquées** par
`deploy.sh` : ports, réseaux admin, seuils de rate limiting, conntrack, timeouts
Apache, seuils fail2ban HTTP, limites systemd, version du WAF.

> Ce n'était pas le cas avant la v2.0 : une bonne moitié du fichier n'était
> câblée nulle part et donnait l'illusion d'un réglage. Voir le [CHANGELOG](CHANGELOG.md).

La substitution dans `nftables.conf` passe par `scripts/lib/nft-template.sh`, et
`tests/test-templating.sh` vérifie que chaque valeur atterrit à sa place. Si vous
reformulez une règle du modèle, lancez les tests : une ancre cassée fait
désormais **échouer** le déploiement au lieu de partir en silence sur les défauts.

```bash
bash tests/test-templating.sh
```

Les valeurs par défaut sont définies **une seule fois**, dans
`scripts/lib/defaults.sh`, et partagées par tous les scripts. `config.env` est
exécuté en root : les scripts refusent de le charger s'il n'appartient pas à
root avec les droits `600` (`sudo chown root: scripts/config.env && sudo chmod 600 scripts/config.env`).

### Toutes les limites sont par IP

| Variable              | Portée                         | Défaut      |
|-----------------------|--------------------------------|-------------|
| `NFT_SYN_RATE`        | SYN tous ports, par IP         | 100/s       |
| `NFT_HTTP_SYN_RATE`   | nouvelles connexions HTTP(S)   | 50/s        |
| `NFT_SSH_RATE`        | nouvelles connexions SSH       | 5/min       |
| `NFT_HTTP_CONN_LIMIT` | connexions HTTP(S) simultanées | 256 (`ct count`) |

Une limite **globale** se retourne contre le serveur : 50 SYN usurpés par
seconde suffisaient à couper le site pour tout le monde, et le bruit des
scanners à empêcher l'accès SSH. Chaque limite est donc tenue par IP source,
et par **préfixe /64 en IPv6** (un attaquant dispose d'au moins un /64 et peut
changer d'adresse à l'infini). Même agrégation dans NGINX et fail2ban.

En ICMPv6, Neighbor Discovery, Router Advertisement et Packet Too Big passent
sans limite : seul `echo-request` est limité. Un ping flood ne coupe plus l'IPv6.

### Ports, liste blanche, réputation

| Variable                              | Rôle |
|---------------------------------------|------|
| `EXTRA_TCP_PORTS` / `EXTRA_UDP_PORTS` | ports ouverts en plus (mail, WireGuard, jeux…), ex. `"25 465 587 993"` |
| `ALLOWLIST4` / `ALLOWLIST6`           | IP ou réseaux qui passent **avant** les limites et les bans (monitoring, autres serveurs, VPN) |
| `REPUTATION_LISTS`                    | `spamhaus-drop`, `spamhaus-drop6`, `firehol-level1` ou URL https, chargées dans un set et rafraîchies chaque jour (`fluxgate-lists.timer`) |
| `NFT_FORWARD_POLICY`                  | `auto` (accept si Docker, libvirt, LXC ou `ip_forward=1`), `drop` ou `accept` |
| `ALLOWED_METHODS`                     | méthodes HTTP acceptées par NGINX **et** le CRS (`PUT PATCH DELETE` pour une API REST ou WebDAV) |
| `CROWDSEC_LAPI_PORT`                  | 8081 par défaut : 8080 entrait en conflit avec `NGINX_UPSTREAM_PORT` |

---

## Exploitation

### Commande `fluxgate`

`deploy.sh` installe `/usr/local/sbin/fluxgate`, point d'entrée unique vers les
scripts. Sans argument, dans un terminal, elle ouvre un menu (gum, sinon
whiptail, sinon menu texte ; `FLUXGATE_UI=gum|whiptail|plain` pour forcer).

```bash
fluxgate status -w                    # tableau de bord temps réel
sudo fluxgate validate                # vérification complète
sudo fluxgate ban 203.0.113.50 2h     # IPv4, IPv6, ou un /64 entier
sudo fluxgate ban 2001:db8:1::/64 1d
sudo fluxgate unban 203.0.113.50
sudo fluxgate bans                    # manuels + fail2ban + CrowdSec
sudo fluxgate xdp-ban 198.51.100.7 1h # drop avant la pile réseau
sudo fluxgate metrics                 # ce qui part vers Prometheus
fluxgate logs nginx                   # nftables | nginx | waf | fail2ban | crowdsec
sudo fluxgate deploy --diff
```

`fluxgate help` liste tout. Les scripts restent utilisables directement
(`nftables/nft-manage.sh`, `scripts/status.sh`…).

### Niveaux de protection

| Niveau     | Commande                                  | Effet |
|------------|-------------------------------------------|-------|
| normal     | —                                         | seuils de `config.env` |
| bouclier   | `sudo fluxgate shield on --for 30m`       | seuils resserrés (`SHIELD_*`), **site joignable** ; retour automatique |
| urgence    | `sudo fluxgate emergency on --for 15m`    | drop de tout sauf SSH depuis `ADMIN_NETS` : **site coupé** |

`shield off` et `emergency off` reviennent à la normale avant l'échéance. Sans
`--for`, le bouclier dure `SHIELD_DURATION` (0 = jusqu'à `shield off`) et
l'urgence jusqu'à `emergency off`. Le retour automatique passe par un timer
`systemd-run`, il survit donc à la fermeture de la session.

### Persistance

Les bans manuels et ceux de fail2ban sont sauvegardés toutes les 5 minutes et à
l'arrêt (`fluxgate-state-save.timer`, `fluxgate-state.service`), puis réinjectés
au démarrage avec leur durée restante. Le programme XDP est rechargé au boot par
`fluxgate-xdp.service` quand `XDP_ENABLED=true`.

### Bans unifiés

fail2ban bannit directement dans les sets FluxGate (`blocklist4` / `blocklist6`)
via l'action `fail2ban/action.d/fluxgate-nft.conf`. Conséquence : un seul endroit
à consulter (`list-blocked`), et l'expiration est gérée par le timeout du set.

Pour revenir à l'action nftables standard : `F2B_USE_FLUXGATE_SETS=false`.

---

## SYNPROXY (optionnel, avancé)

SYNPROXY délègue le handshake TCP au noyau : les connexions ne remontent à
l'application qu'une fois le 3-way handshake validé par cookie. Très efficace
contre les SYN floods, mais **mal configuré, il rend le service web injoignable**.

```bash
# Dans config.env
SYNPROXY_ENABLED=true
SYNPROXY_MSS=1460
SYNPROXY_WSCALE=7
```

`deploy.sh` redemande confirmation avant de l'activer, même si le flag est à
`true`, et le rollback automatique de 5 minutes reste armé pendant l'opération.

**À valider hors production avant tout usage réel.** Deux points de vigilance :

1. `mss` et `wscale` doivent correspondre à ce que sert réellement votre backend.
2. Les deux moitiés de la règle (chaîne `prerouting` avec `notrack` **et** règle
   `synproxy` dans `input`) doivent être présentes. `validate.sh` échoue
   explicitement si une seule des deux l'est.

Prérequis noyau (déjà fournis par `sysctl/99-fluxgate-hardening.conf`) :
`nf_conntrack_tcp_loose=0`, `tcp_syncookies=1`, `tcp_timestamps=1`.

---

## Derrière un CDN (Cloudflare…)

Sans réglage, le rate-limiting L7 viserait les IP du CDN et bloquerait tous les
visiteurs d'un coup.

```bash
# Dans config.env
CDN_MODE=cloudflare
```

`deploy.sh` récupère alors les plages Cloudflare (rafraîchies chaque jour par
`fluxgate-lists.timer`) et :

- n'ouvre HTTP/HTTPS **qu'à ces plages** dans nftables : impossible de
  contourner le CDN en visant l'IP d'origine ;
- génère `fluxgate-realip.conf` (`set_real_ip_from` + `CF-Connecting-IP`) pour
  que NGINX, fail2ban et CrowdSec voient la vraie IP du visiteur ;
- en profil Caddy, utilise `CF-Connecting-IP` comme clé de limite de débit.

---

## Utilisation avec un reverse proxy (Caddy, Nginx, Traefik…)

Les ports `HTTP_PORT` / `HTTPS_PORT` sont ouverts par le ruleset quel que soit
le serveur web. Si le reverse proxy ne répond pas après déploiement, recharger
**la configuration installée**, qui contient tes valeurs :

```bash
sudo fluxgate apply            # recharge /etc/nftables.conf, bans conservés
sudo nft list chain inet fluxgate input | grep -E 'dport'
```

> ⚠️ Ne **jamais** copier `nftables/nftables.conf` du dépôt vers
> `/etc/nftables.conf` : c'est un modèle, avec le port SSH 22 et les
> `ADMIN_NETS` d'exemple. Si ton SSH écoute ailleurs, tu es bloqué dehors.
> Seul `deploy.sh` produit le fichier rendu.

### Profil Caddy

Quand Caddy est installé et NGINX absent, `deploy.sh` installe des snippets dans
`/etc/caddy/fluxgate.caddy` **sans toucher à ton Caddyfile** :

```caddy
import /etc/caddy/fluxgate.caddy

exemple.fr {
    import fluxgate
    reverse_proxy 127.0.0.1:8080
}
```

| Snippet         | Contenu | Prérequis |
|-----------------|---------|-----------|
| `fluxgate_base` | en-têtes de sécurité, HSTS, 10 Mo max, `ALLOWED_METHODS` (405 sinon), journal JSON | Caddy des dépôts |
| `fluxgate_waf`  | Coraza + OWASP CRS, limite de débit `NGINX_REQ_PER_SEC × 10 + NGINX_BURST` par 10 s | modules coraza-caddy et caddy-ratelimit |
| `fluxgate`      | les deux | — |

Le Caddy des dépôts n'a ni WAF ni limite de débit : `deploy.sh` le détecte et
réduit alors `fluxgate` à la partie de base. Pour compiler un binaire complet
(Go ≥ 1.22, versions figées dans le script, retour arrière par
`update-alternatives`) :

```bash
sudo bash caddy/build-caddy.sh
sudo fluxgate deploy
```

Le profil est validé par `caddy validate` avant installation. Si CrowdSec est
présent, la collection `crowdsecurity/caddy` est installée et le journal
`/var/log/caddy/access.log` ajouté aux sources.

---

## Monitoring et alertes

| Élément | Rôle |
|---------|------|
| `monitoring/exporter/fluxgate-exporter.sh` | lancé chaque minute (`fluxgate-exporter.timer`), écrit `fluxgate.prom` pour le textfile collector de node_exporter |
| `monitoring/prometheus/fluxgate-alerts.yml` | alertes système + protection (pare-feu absent, urgence active, pic de bans, taux de 429, blocages WAF, exporteur muet) |
| `monitoring/alertmanager/alertmanager.yml` | routage vers **Discord** |

Métriques exposées : paquets/octets par règle nftables commentée, IP bannies
par set, entrées de réputation, état du bouclier et de l'urgence, bans XDP,
fail2ban et CrowdSec, total des 429 NGINX et des blocages ModSecurity. Elles
arrivent par le job `node` existant : rien à ajouter côté Prometheus.

```bash
sudo fluxgate metrics                                  # aperçu
sudo install -m 640 -o root -g prometheus /dev/null /etc/prometheus/discord-webhook
echo 'https://discord.com/api/webhooks/...' | sudo tee /etc/prometheus/discord-webhook >/dev/null
sudo cp monitoring/alertmanager/alertmanager.yml /etc/prometheus/alertmanager.yml
amtool check-config /etc/prometheus/alertmanager.yml
```

`FLUXGATE_EXPORTER_ENABLED=false` désactive l'exporteur. L'URL du webhook est un
secret : elle reste hors du fichier de configuration. Les étapes complètes et le
repli pour les Alertmanager anciens sont en tête de `alertmanager.yml`.

---

## Rollback complet

```bash
sudo fluxgate rollback        # ou : sudo bash scripts/rollback.sh
sudo reboot
```

Supprime toutes les configs (sysctl, modprobe, nginx, apache, caddy, fail2ban,
action FluxGate, drop-in systemd, timers, commande `fluxgate`, logrotate),
détache XDP et supprime les tables FluxGate. Les fichiers système modifiés
(dont `/etc/nftables.conf`) sont remis dans leur version d'avant FluxGate : le
pare-feu ne revient plus au reboot. Les tables des autres outils ne sont pas
touchées.

---

## Sécurité de la chaîne d'approvisionnement

Les composants tiers ne sont plus récupérés « à l'aveugle » :

| Composant   | Méthode                                                              |
|-------------|----------------------------------------------------------------------|
| OWASP CRS   | version épinglée + **sha256 vérifié** + **signature GPG** contrôlée   |
| CrowdSec    | dépôt packagecloud signé (plus de `curl \| bash` exécuté en root)     |
| Grafana     | dépôt officiel signé (`signed-by`)                                    |
| Charm.sh    | dépôt officiel signé (`signed-by`)                                    |

La clé de signature du CRS est épinglée par empreinte dans `config.env`
(`36006F0E0BA167832158821138EEACA1AB8A6E72`, *OWASP Core Rule Set
&lt;security@coreruleset.org&gt;*). Une archive dont le sha256 ou la signature ne
correspond pas est **rejetée sans être extraite**.

Pour monter le CRS de version : récupérer le tag et le sha256 de l'asset
`coreruleset-<version>-minimal.tar.gz` sur la
[page des releases](https://github.com/coreruleset/coreruleset/releases), puis
mettre à jour `CRS_VERSION` / `CRS_SHA256` dans `config.env`.

---

## Structure

```
BRcloud-FluxGate/
├── scripts/
│   ├── install.sh          # Prérequis + outils de design
│   ├── deploy.sh           # Déploiement + anti-lockout SSH
│   ├── check-config.sh     # Validation de config.env
│   ├── validate.sh         # Validation de chaque couche
│   ├── rollback.sh         # Restauration de l'état d'origine
│   ├── status.sh           # Dashboard temps réel (-w)
│   ├── migrate-config.sh   # Ajoute à config.env les clés manquantes
│   ├── progress_bar.sh     # Barre de chargement native
│   ├── config.env          # Configuration centralisée (non versionnée)
│   └── lib/
│       ├── defaults.sh     # Valeurs par défaut + chargement sûr de config.env
│       ├── crs.sh          # Installation vérifiée de l'OWASP CRS
│       └── nft-template.sh # Application de config.env dans nftables.conf
├── cli/
│   └── fluxgate            # Commande unique + menu gum/whiptail
├── nftables/
│   ├── nftables.conf       # Table inet fluxgate, dual-stack, SYNPROXY optionnel
│   ├── nft-manage.sh       # ban / bouclier / urgence / restore
│   ├── fluxgate-lists.sh   # Listes de réputation + plages CDN
│   └── fluxgate-state.sh   # Sauvegarde / restauration des bans
├── nginx/
│   ├── nginx-global.conf
│   └── nginx-fluxgate.conf
├── caddy/
│   ├── fluxgate.caddy      # Snippets (base + Coraza/ratelimit)
│   └── build-caddy.sh      # Compilation xcaddy avec les modules
├── apache/
│   └── security-hardening.conf
├── sysctl/
│   └── 99-fluxgate-hardening.conf
├── systemd/                # Socket, limites, XDP, état, listes, exporteur
├── fail2ban/
│   ├── action.d/fluxgate-nft.conf   # Ban dans les sets FluxGate
│   ├── filter.d/
│   └── jail.d/
├── waf/modsecurity/
├── crowdsec/
├── logrotate/
│   └── fluxgate            # /var/log/fluxgate + journaux ModSecurity
├── monitoring/
│   ├── exporter/           # fluxgate-exporter.sh (textfile collector)
│   ├── prometheus/         # Config + règles d'alerte
│   ├── alertmanager/       # Routage vers Discord
│   └── grafana/            # Dashboard + provisioning
├── xdp/
│   ├── xdp-manage.sh       # Gestion filtres eBPF
│   └── xdp-auto-block.sh   # Auto-ban via conntrack (TTL, liste blanche)
├── tc/
│   └── tc-shape.sh         # fq maxrate / cake
├── tests/
│   ├── test-templating.sh  # Tests du rendu nftables
│   └── test-runtime.sh     # netns + trafic, nginx -t, fail2ban-regex, caddy
└── docs/
    ├── architecture.md
    ├── documentation-complete.md
    └── references.md
```

---

## Développement

```bash
bash tests/test-templating.sh                  # tests de rendu
sudo bash tests/test-runtime.sh                # tests d'exécution (root)
shellcheck --severity=warning scripts/*.sh     # analyse statique
sudo nft -c -f nftables/nftables.conf          # syntaxe du pare-feu
```

`test-runtime.sh` ne modifie pas le pare-feu de la machine. Il charge le
ruleset dans des espaces de noms réseau isolés, relie un « client » et un
« serveur » par une paire veth, puis vérifie le trafic réel : HTTP passe, SSH
est refusé hors `ADMIN_NETS` en mode strict et accepté depuis `ADMIN_NETS`, une
IP bannie est coupée, l'urgence coupe et `restore` rouvre. Il teste aussi
nft-manage, l'exporteur et la commande `fluxgate`, fait un `nginx -t` des
rendus HTTP et HTTPS, passe les filtres fail2ban dans `fail2ban-regex`, valide
le profil Caddy et vérifie `check-config.sh`. Un outil absent fait sauter sa
section ; `FLUXGATE_TEST_STRICT=1` (utilisé en CI) en fait un échec.

Depuis un poste Windows, WSL suffit pour tout sauf SYNPROXY :

```bash
wsl -d Debian -u root -- bash -c 'cd /mnt/c/chemin/vers/BRcloud-FluxGate && \
  nft -c -f nftables/nftables.conf && bash tests/test-templating.sh && \
  bash tests/test-runtime.sh'
```

> Le noyau WSL2 ne fournit pas le module `nft_synproxy` : un rendu avec
> SYNPROXY y échoue sur `Could not process rule: No such file or directory`,
> y compris pour l'exemple officiel du wiki nftables. C'est une limite de
> l'environnement, pas de la configuration — valider cette option sur une
> vraie machine.

La CI GitHub Actions rejoue tout cela à chaque push, plus une vérification que
les fins de ligne restent en **LF** — un `.sh` en CRLF ne démarre pas sur Linux,
et le projet est édité depuis Windows (`.gitattributes` verrouille le comportement).

---

## Licence & références

- **ANSSI** — inspiré du Guide des Essentiels DDoS v2.0
- **Licence** — [MIT](LICENSE) (open-source, réutilisable en production)
