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
      ├─ [3] nftables L3/L4      Sets dynamiques, rate limit SYN, SYNPROXY (opt.)
      ├─ [4] systemd             Limites CPU/RAM/FD, connexions max par IP source
      ├─ [5] Nginx / Apache      Leaky bucket, anti-slowloris, 429
      ├─ [6] WAF ModSecurity     OWASP CRS — filtrage SQLi & XSS
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
> whitelistée. Un rollback automatique de 5 min (`at`) réinitialise le pare-feu
> si la connexion coupe.

### 5. Valider

```bash
sudo bash scripts/validate.sh
```

Diagnostic complet : sysctl, congestion BBR, nftables (dont parité IPv6 et
cohérence SYNPROXY), persistance au reboot, WAF, jails fail2ban, seuils conntrack.

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

### Deux seuils à ne pas confondre

| Variable                 | Portée                    | Effet si trop bas                     |
|--------------------------|---------------------------|---------------------------------------|
| `NFT_SYN_RATE`           | **par IP source**         | bloque un attaquant ciblé             |
| `NFT_HTTP_SYN_RATE`      | **global, toutes IP**     | jette des visiteurs légitimes en pic  |

Le défaut de `NFT_HTTP_SYN_RATE` (50/s) convient à un petit site. Sur un site
fréquenté, montez à 500–2000, ou passez par un CDN.

---

## Exploitation

### Tableau de bord temps réel

```bash
sudo bash scripts/status.sh -w        # mode watch
sudo bash scripts/status.sh -w -n 1   # rafraîchissement 1s
```

### Gestion à chaud du pare-feu

```bash
# Bloquer une IP 2 heures (IPv4 ou IPv6, détection automatique)
sudo bash nftables/nft-manage.sh block 203.0.113.50 2h
sudo bash nftables/nft-manage.sh block 2001:db8::1 30m

# Débloquer
sudo bash nftables/nft-manage.sh unblock 203.0.113.50

# Lister les IPs bloquées (manuel + fail2ban + CrowdSec, tout au même endroit)
sudo bash nftables/nft-manage.sh list-blocked

# Mode urgence : tout bloquer sauf SSH depuis ADMIN_NETS
sudo bash nftables/nft-manage.sh emergency-drop-all

# Revenir à l'état d'avant l'urgence
sudo bash nftables/nft-manage.sh restore
```

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

Le rate-limiting L7 ciblerait les IP du CDN et bloquerait tous les visiteurs d'un coup.

1. Whitelister les plages IP du CDN dans nftables.
2. Décommenter la section **OPTION CDN** dans `nginx/nginx-fluxgate.conf` :

```nginx
set_real_ip_from 103.21.244.0/22;
real_ip_header CF-Connecting-IP;
real_ip_recursive on;
```

---

## Utilisation avec un reverse proxy (Caddy, Nginx, Traefik…)

Si tu utilises un reverse proxy comme Caddy sur le même hôte, les ports 80 et 443
doivent être explicitement autorisés dans nftables — FluxGate applique un `policy drop`
par défaut sur toutes les entrées.

La config `nftables/nftables.conf` inclut déjà les règles HTTP/HTTPS, mais si tu
constates que le reverse proxy ne répond pas après déploiement, c'est probablement
que l'ancienne config `/etc/nftables.conf` n'a pas été mise à jour.

**Solution :**

```bash
sudo cp ~/BRcloud-FluxGate/nftables/nftables.conf /etc/nftables.conf
sudo nft -f /etc/nftables.conf

# Vérifier que les ports sont bien ouverts
sudo nft list ruleset | grep -E "80|443"

# Persister au reboot
sudo systemctl enable nftables
```

> ⚠️ Ne pas oublier d'activer `systemctl enable nftables` pour que les règles
> survivent à un redémarrage du serveur. `validate.sh` le vérifie désormais.

---

## Rollback complet

```bash
sudo bash scripts/rollback.sh
sudo reboot
```

Supprime toutes les configs (sysctl, modprobe, nginx, apache, fail2ban, action
FluxGate, drop-in systemd), détache XDP, libère nftables.

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
│   ├── progress_bar.sh     # Barre de chargement native
│   ├── config.env          # Configuration centralisée (non versionnée)
│   └── lib/
│       ├── crs.sh          # Installation vérifiée de l'OWASP CRS
│       └── nft-template.sh # Application de config.env dans nftables.conf
├── nftables/
│   ├── nftables.conf       # Règles dual-stack IPv4/IPv6 + SYNPROXY optionnel
│   └── nft-manage.sh       # block / unblock / urgence / restore
├── nginx/
│   ├── nginx-global.conf
│   └── nginx-fluxgate.conf
├── apache/
│   └── security-hardening.conf
├── sysctl/
│   └── 99-fluxgate-hardening.conf
├── systemd/
│   ├── fluxgate-app.socket
│   ├── fluxgate-web.service.d/resource-limits.conf
│   └── fluxgate-xdp-autoblock.service
├── fail2ban/
│   ├── action.d/fluxgate-nft.conf   # Ban dans les sets FluxGate
│   ├── filter.d/
│   └── jail.d/
├── waf/modsecurity/
├── crowdsec/
├── monitoring/
│   ├── prometheus/         # Config + règles d'alerte
│   └── grafana/            # Dashboard + provisioning
├── xdp/
│   ├── xdp-manage.sh       # Gestion filtres eBPF
│   └── xdp-auto-block.sh   # Auto-ban via conntrack
├── tc/
│   └── tc-shape.sh         # Traffic shaping
├── tests/
│   └── test-templating.sh  # Tests du rendu nftables
└── docs/
    ├── architecture.md
    ├── documentation-complete.md
    └── references.md
```

---

## Développement

```bash
bash tests/test-templating.sh                  # tests de rendu
shellcheck --severity=warning scripts/*.sh     # analyse statique
sudo nft -c -f nftables/nftables.conf          # syntaxe du pare-feu
```

Depuis un poste Windows, WSL suffit pour tout sauf SYNPROXY :

```bash
wsl -d Debian -u root -- bash -c 'cd /mnt/c/chemin/vers/BRcloud-FluxGate && \
  nft -c -f nftables/nftables.conf && bash tests/test-templating.sh'
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
