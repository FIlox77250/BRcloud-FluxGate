# BRCloud FluxGate - Documentation Complete

> Stack anti-DDoS open-source pour serveur Linux (Debian/Ubuntu, RHEL/Fedora).
> Version : 1.0 | Derniere mise a jour : 2026-02-14

---

## Table des matieres

1. [Presentation generale](#1-presentation-generale)
2. [Architecture et flux d'un paquet](#2-architecture-et-flux-dun-paquet)
3. [Arborescence du projet](#3-arborescence-du-projet)
4. [Prerequis et installation (install.sh)](#4-prerequis-et-installation-installsh)
5. [Configuration (config.env)](#5-configuration-configenv)
6. [Deploiement (deploy.sh)](#6-deploiement-deploysh)
7. [Couche 1 - Kernel tuning (sysctl)](#7-couche-1---kernel-tuning-sysctl)
8. [Couche 2 - Pare-feu nftables](#8-couche-2---pare-feu-nftables)
9. [Couche 3 - XDP/eBPF (optionnel)](#9-couche-3---xdpebpf-optionnel)
10. [Couche 4 - Reverse proxy (NGINX)](#10-couche-4---reverse-proxy-nginx)
11. [Couche 4 bis - Reverse proxy (Apache)](#11-couche-4-bis---reverse-proxy-apache)
12. [Couche 5 - WAF ModSecurity + CRS](#12-couche-5---waf-modsecurity--crs)
13. [Couche 6 - fail2ban](#13-couche-6---fail2ban)
14. [Couche 7 - CrowdSec](#14-couche-7---crowdsec)
15. [Couche 8 - Traffic shaping (tc)](#15-couche-8---traffic-shaping-tc)
16. [Couche 9 - systemd (sockets et cgroups)](#16-couche-9---systemd-sockets-et-cgroups)
17. [Monitoring (Prometheus + Grafana)](#17-monitoring-prometheus--grafana)
18. [Scripts utilitaires](#18-scripts-utilitaires)
19. [Problemes connus et pieges classiques](#19-problemes-connus-et-pieges-classiques)
20. [Retour d'experience - Premier deploiement (Debian 13)](#20-retour-dexperience---premier-deploiement-debian-13)
21. [Procedures d'urgence](#21-procedures-durgence)
22. [Glossaire](#22-glossaire)
23. [References](#23-references)

---

## 1. Presentation generale

### Qu'est-ce que FluxGate ?

FluxGate est une **stack de protection anti-DDoS** composee de plusieurs couches de defense qui fonctionnent ensemble sur un serveur Linux. Le principe fondamental est la **defense en profondeur** : chaque couche filtre un type d'attaque different, de sorte que si une couche est contournee, la suivante prend le relais.

### Pourquoi plusieurs couches ?

Une attaque DDoS peut viser differents niveaux du modele reseau :

| Type d'attaque | Couche OSI | Exemple | Defense FluxGate |
|----------------|-----------|---------|------------------|
| Volumetrique | L3/L4 | SYN flood, UDP flood | XDP, nftables, sysctl |
| Protocole | L4 | Paquets invalides, fragmentation | nftables (ct state invalid) |
| Applicative | L7 | HTTP flood, slowloris | NGINX rate limit, ModSecurity |
| Brute force | L7 | SSH brute force, login spray | fail2ban, CrowdSec |
| Amplification | L3 | DNS amplification sortante | tc shaping, drop UDP |

### Principe de la defense en profondeur

```
Paquet entrant
    |
    v
[XDP/eBPF] ---- Drop ultra-rapide (avant la pile noyau, millions de pps)
    |
    v
[Pile noyau] --- SYN cookies, backlog, conntrack (sysctl)
    |
    v
[nftables] ----- Drop IP bloquees, rate limit SYN, paquets invalides
    |
    v
[systemd socket]- Limite connexions par IP source
    |
    v
[NGINX/Apache] - Rate limit HTTP, timeouts anti-slow, 429
    |
    v
[ModSecurity] -- WAF : injections SQL/XSS, abus applicatifs
    |
    v
[Application] -- Votre code
```

Plus le filtrage est fait **tot** (haut dans le schema), moins il consomme de ressources. Un paquet droppe par XDP ne touche jamais la pile TCP. Un paquet droppe par nftables ne touche jamais NGINX.

---

## 2. Architecture et flux d'un paquet

### Trajet complet d'un paquet

1. **Le paquet arrive sur la carte reseau (NIC)**
   - Le driver de la carte reseau recoit les donnees brutes dans un buffer RX (ring buffer).

2. **XDP (optionnel) - Decision avant la pile noyau**
   - Si un programme XDP est attache a l'interface, il s'execute **dans le driver** ou juste apres.
   - Decisions possibles : `XDP_DROP` (drop immediat), `XDP_PASS` (continuer), `XDP_TX` (renvoyer).
   - Avantage : zero allocation memoire noyau, zero copie. Capacite : 10-20 millions de paquets/seconde par coeur CPU.

3. **Pile noyau Linux**
   - Le paquet est converti en structure `sk_buff` (SKB).
   - Les parametres sysctl s'appliquent : SYN cookies, backlog TCP, conntrack.
   - Si la table conntrack est pleine, les nouvelles connexions sont droppees silencieusement.

4. **nftables (netfilter hooks)**
   - Le paquet traverse les chains nftables (input, forward, output).
   - Les sets dynamiques (blocklist4/blocklist6) sont consultes.
   - Les rules de rate limiting s'appliquent (SYN/seconde, connexions/IP).
   - Les paquets invalides (`ct state invalid`) sont droppes.

5. **systemd socket**
   - Si le service utilise l'activation par socket, systemd applique ses limites :
     - `MaxConnectionsPerSource` : max connexions simultanees depuis une meme IP.
     - `Backlog` : taille de la file d'attente accept().

6. **Reverse proxy (NGINX ou Apache)**
   - Rate limiting HTTP (`limit_req`, `limit_conn`).
   - Timeouts anti-slow (headers, body).
   - Proxy vers l'application backend.
   - Reponse 429 Too Many Requests si la limite est depassee.

7. **WAF ModSecurity + OWASP CRS**
   - Analyse le contenu de la requete HTTP (headers, body, URI).
   - Detecte les injections SQL, XSS, traversee de chemin, etc.
   - Score d'anomalie : si le score depasse le seuil, la requete est bloquee (403).

8. **Application**
   - Votre code recoit la requete.
   - Les cgroups systemd limitent CPU/RAM/FD pour eviter l'epuisement.

### Reactions automatiques

En parallele du flux de paquets, des systemes **reactifs** analysent les logs :

- **fail2ban** : lit les logs (SSH, NGINX, Apache), detecte les patterns d'abus, ajoute les IP dans les sets nftables.
- **CrowdSec** : meme principe mais avec une base de reputation communautaire. Partage les IP malveillantes entre tous les utilisateurs CrowdSec.
- **XDP auto-block** : surveille conntrack, bloque automatiquement les IP depassant un seuil de connexions via XDP.

---

## 3. Arborescence du projet

```
BRCloud FluxGate/
|
|-- scripts/
|   |-- install.sh          # Installe tous les prerequis (packages)
|   |-- deploy.sh           # Deploie la stack (copie configs, applique regles)
|   |-- validate.sh         # Verifie que tout fonctionne
|   |-- rollback.sh         # Revient a l'etat initial
|   |-- status.sh           # Dashboard CLI temps reel
|   +-- config.env          # Configuration centralisee
|
|-- nftables/
|   |-- nftables.conf       # Regles pare-feu L3/L4
|   +-- nft-manage.sh       # Outil de gestion (block/unblock/urgence)
|
|-- xdp/
|   |-- xdp-manage.sh       # Gestion XDP (load/unload/block)
|   +-- xdp-auto-block.sh   # Daemon de blocage automatique
|
|-- tc/
|   +-- tc-shape.sh         # Traffic shaping sortant (TBF)
|
|-- nginx/
|   |-- nginx-global.conf   # Config globale NGINX
|   +-- nginx-fluxgate.conf # Rate limiting, proxy, headers securite
|
|-- apache/
|   +-- security-hardening.conf  # Timeouts, headers, limites Apache
|
|-- waf/modsecurity/
|   |-- modsecurity.conf         # Config moteur ModSecurity v3
|   +-- crs-setup-override.conf  # Tuning OWASP CRS
|
|-- fail2ban/
|   |-- jail.d/
|   |   |-- fluxgate-nginx.conf  # Jails NGINX (4xx, rate limit, bots)
|   |   |-- fluxgate-apache.conf # Jails Apache (4xx, auth, bots)
|   |   +-- fluxgate-sshd.conf   # Jail SSH brute force
|   +-- filter.d/
|       |-- nginx-4xx.conf       # Filtre regex NGINX
|       +-- apache-4xx.conf      # Filtre regex Apache
|
|-- crowdsec/
|   |-- acquis.yaml              # Sources de logs pour CrowdSec
|   +-- crowdsec-firewall-bouncer.yaml  # Config bouncer nftables
|
|-- systemd/
|   |-- fluxgate-app.socket      # Socket avec limites anti-DDoS
|   |-- fluxgate-xdp-autoblock.service  # Service daemon XDP
|   +-- fluxgate-web.service.d/
|       +-- resource-limits.conf # Cgroups CPU/RAM/FD
|
|-- monitoring/
|   |-- prometheus/
|   |   |-- prometheus.yml       # Config Prometheus (scrape targets)
|   |   +-- fluxgate-alerts.yml  # Regles d'alerte
|   +-- grafana/
|       |-- provisioning-dashboards.yml
|       |-- provisioning-datasources.yml
|       +-- dashboards/
|           +-- fluxgate-ddos-overview.json
|
|-- sysctl/
|   +-- 99-fluxgate-hardening.conf  # Parametres kernel
|
+-- docs/
    |-- architecture.md
    |-- references.md
    +-- documentation-complete.md   # CE FICHIER
```

---

## 4. Prerequis et installation (install.sh)

### Fichier : `scripts/install.sh`

Ce script installe **tous les packages necessaires** avant de lancer `deploy.sh`. Sans lui, `deploy.sh` ignore silencieusement les etapes si les commandes sont absentes (par exemple, si `nft` n'est pas installe, nftables n'est pas deploye et aucune erreur n'est affichee).

### Utilisation

```bash
sudo bash scripts/install.sh
```

### Ce que fait le script

#### Verifications initiales
- **Root requis** : le script refuse de s'executer sans `sudo`.
- **Detection OS** : detecte automatiquement Debian/Ubuntu (apt) ou RHEL/Fedora (dnf/yum) et adapte les noms de packages.
- **Kernel >= 4.4** : nftables et XDP necessitent un kernel recent. Le script verifie la version.
- **Charge config.env** : lit les options (`XDP_ENABLED`, `IFACE`, etc.) pour savoir quoi installer.

#### Composants installes

| Composant | Packages Debian | Packages RHEL | Condition |
|-----------|----------------|---------------|-----------|
| Base | nftables, conntrack, iproute2, ethtool, curl, wget, gnupg, lsb-release | nftables, conntrack-tools, iproute, ethtool, curl, wget, gnupg2 | Toujours |
| NGINX | nginx | nginx | Choix utilisateur |
| Apache | apache2, libapache2-mod-security2 | httpd, mod_security | Choix utilisateur |
| fail2ban | fail2ban | fail2ban | Toujours |
| CrowdSec | crowdsec, crowdsec-firewall-bouncer-nftables | idem | Optionnel (choix) |
| XDP | xdp-tools, bpftool, linux-headers-$(uname -r) | xdp-tools, bpftool, kernel-headers-$(uname -r) | Si `XDP_ENABLED=true` |
| Prometheus | prometheus, prometheus-node-exporter | prometheus, node_exporter | Optionnel (choix) |
| Grafana | grafana (depot officiel ajoute) | grafana (depot officiel ajoute) | Optionnel (choix) |

#### Post-installation
- Active et demarre chaque service systemd (`systemctl enable --now`).
- Cree `/var/log/fluxgate/` et `/opt/fluxgate/`.
- Copie les configs Prometheus et Grafana dans les bons repertoires.
- Affiche un resume colore : composants installes, ignores, echoues.

### Ordre d'execution

```
1. sudo bash scripts/install.sh    <-- Installe les packages
2. Editer scripts/config.env       <-- Adapter a votre serveur
3. sudo bash scripts/deploy.sh     <-- Deploie les configs
4. sudo bash scripts/validate.sh   <-- Verifie que tout marche
```

---

## 5. Configuration (config.env)

### Fichier : `scripts/config.env`

C'est le **fichier central** de configuration. Tous les scripts le chargent (`source config.env`). Chaque variable controle un aspect de la stack.

### Variables expliquees une par une

#### Interface reseau

```bash
IFACE="eth0"
```
- **Quoi** : le nom de l'interface reseau principale de votre serveur.
- **Comment trouver** : `ip link show` ou `ip a`. C'est l'interface qui a votre IP publique.
- **Exemples** : `eth0`, `ens3`, `enp1s0`, `eno1`.
- **Impact** : XDP, tc shaping, et les stats reseau utilisent cette valeur.

#### Ports exposes

```bash
SSH_PORT=22
HTTP_PORT=80
HTTPS_PORT=443
```
- **Quoi** : les ports que le pare-feu nftables va autoriser en entree.
- **ATTENTION** : si vous changez le port SSH (par exemple `2222`), vous DEVEZ mettre a jour `SSH_PORT` **avant** de deployer, sinon nftables bloquera votre connexion SSH.
- **Impact** : nftables `$SSH_PORT`, `$HTTP_PORT`, `$HTTPS_PORT` dans les regles.

#### Rate limiting nftables

```bash
NFT_SYN_RATE=50
NFT_SYN_BURST=100
```
- **Quoi** : nombre max de paquets SYN (nouvelles connexions TCP) par seconde autorises sur HTTP/HTTPS.
- **`NFT_SYN_RATE=50`** : 50 nouvelles connexions/seconde en regime normal.
- **`NFT_SYN_BURST=100`** : tolerance temporaire jusqu'a 100 SYN en rafale (pics).
- **Si trop bas** : les clients legitimes sont refuses pendant les pics de trafic.
- **Si trop haut** : le pare-feu laisse passer un flood SYN.
- **Valeur recommandee** : mesurer votre trafic normal avec `ss -s` et multiplier par 2-3.

#### Conntrack

```bash
CONNTRACK_MAX=262144
CONNTRACK_BUCKETS=65536
```
- **Quoi** : conntrack est le systeme du noyau Linux qui suit chaque connexion TCP/UDP active.
- **`CONNTRACK_MAX`** : nombre maximum de connexions suivies simultanement. Chaque entree consomme ~300 octets de RAM. 262144 entrees = ~75 Mo de RAM.
- **`CONNTRACK_BUCKETS`** : nombre de buckets de la table de hachage. Idealement `CONNTRACK_MAX / 4`.
- **Si trop bas** : quand la table est pleine, les nouvelles connexions sont **droppees silencieusement**. C'est l'un des problemes les plus courants en cas de DDoS : le serveur refuse les connexions sans aucun log visible.
- **Comment surveiller** : `cat /proc/sys/net/netfilter/nf_conntrack_count` vs `nf_conntrack_max`.

#### Backlog TCP

```bash
SOMAXCONN=4096
TCP_MAX_SYN_BACKLOG=8192
```
- **`SOMAXCONN`** : taille max de la file d'attente `accept()` d'un socket en ecoute. Quand un programme appelle `listen()`, les connexions completees (3-way handshake fini) attendent dans cette file.
- **`TCP_MAX_SYN_BACKLOG`** : taille de la file des connexions en etat `SYN_RECV` (handshake en cours, pas encore fini).
- **Si trop bas** : les connexions sont droppees quand la file est pleine (le client voit un timeout).
- **Les SYN cookies** contournent ce probleme en ne creant pas d'etat pour les SYN, mais au prix de la perte de certaines options TCP (window scaling, SACK).

#### NGINX rate limiting

```bash
NGINX_REQ_PER_SEC=30
NGINX_BURST=50
NGINX_MAX_CONN_PER_IP=50
NGINX_UPSTREAM_PORT=8080
```
- **`NGINX_REQ_PER_SEC=30`** : chaque IP peut faire 30 requetes HTTP par seconde. Methode : leaky bucket (seau percant).
- **`NGINX_BURST=50`** : en rafale, jusqu'a 50 requetes sont acceptees avant de commencer a refuser. Les requetes excedentaires recevoivent un `429 Too Many Requests`.
- **`NGINX_MAX_CONN_PER_IP=50`** : max 50 connexions TCP simultanees depuis une meme IP.
- **`NGINX_UPSTREAM_PORT=8080`** : le port de votre application backend. NGINX proxie les requetes vers `127.0.0.1:8080`.
- **Si trop bas** : les utilisateurs derriere un meme NAT (bureaux, universites) sont penalises car ils partagent la meme IP publique.

#### Apache timeouts

```bash
APACHE_HEADER_TIMEOUT_MIN=10
APACHE_HEADER_TIMEOUT_MAX=40
APACHE_HEADER_MIN_RATE=500
APACHE_BODY_TIMEOUT_MIN=10
APACHE_BODY_TIMEOUT_MAX=60
APACHE_BODY_MIN_RATE=500
```
- Protection contre les attaques **slow HTTP** (Slowloris, Slow POST).
- **Principe** : un client doit envoyer ses headers en 10 a 40 secondes, avec au moins 500 octets/seconde. Sinon, la connexion est fermee.
- **Attaque Slowloris** : un attaquant ouvre des milliers de connexions et envoie les headers HTTP tres lentement (1 octet/seconde) pour bloquer tous les threads du serveur sans jamais terminer la requete.

#### fail2ban

```bash
F2B_SSH_MAXRETRY=5
F2B_SSH_FINDTIME=600
F2B_SSH_BANTIME=3600
F2B_HTTP_MAXRETRY=100
F2B_HTTP_FINDTIME=60
F2B_HTTP_BANTIME=600
```
- **SSH** : 5 tentatives en 600 secondes (10 min) = ban 3600 secondes (1h).
- **HTTP** : 100 erreurs 4xx en 60 secondes = ban 600 secondes (10 min).
- **Comment ca marche** : fail2ban lit les fichiers de log (auth.log, access.log), applique des regex pour trouver des patterns d'abus, et ajoute l'IP fautive dans un set nftables.

#### systemd resource control

```bash
SVC_CPU_QUOTA=80%
SVC_MEMORY_MAX=2G
SVC_LIMIT_NOFILE=65536
SVC_MAX_CONN_PER_SOURCE=50
SVC_BACKLOG=4096
```
- **`SVC_CPU_QUOTA=80%`** : le service web ne peut pas utiliser plus de 80% d'un coeur CPU. `200%` = 2 coeurs.
- **`SVC_MEMORY_MAX=2G`** : si le service depasse 2 Go de RAM, il est tue par l'OOM killer.
- **`SVC_LIMIT_NOFILE=65536`** : nombre max de fichiers ouverts (inclut les sockets).
- **Pourquoi** : empeche un service sous attaque de consommer toutes les ressources du serveur et de rendre le SSH inaccessible.

#### Traffic shaping

```bash
TC_RATE="1gbit"
TC_BURST="32kbit"
TC_LATENCY="50ms"
```
- **Quoi** : limite le debit **sortant** avec un Token Bucket Filter (TBF).
- **Pourquoi** : empeche votre serveur d'etre utilise comme amplificateur (attaque par reflexion DNS, NTP, etc.).
- **`TC_RATE`** : debit max sortant. Mettre la capacite de votre lien (ex: `1gbit`, `500mbit`).
- **`TC_BURST`** : quantite de donnees envoyables instantanement avant throttling.
- **`TC_LATENCY`** : latence max acceptable dans la file d'attente.

#### XDP

```bash
XDP_ENABLED=false
```
- **`false`** : XDP n'est pas active, les scripts XDP sont ignores.
- **`true`** : `install.sh` installe xdp-tools et bpftool, `deploy.sh` attache xdp-filter sur l'interface.
- **Quand activer** : si vous subissez des attaques volumetriques a haut debit de paquets (>100k pps) et que nftables ne suffit pas.
- **Prerequis** : driver NIC compatible XDP (la plupart des drivers modernes : ixgbe, i40e, mlx5, virtio-net).

#### Monitoring

```bash
PROMETHEUS_PORT=9090
NODE_EXPORTER_PORT=9100
GRAFANA_PORT=3000
```
- **Prometheus** : collecte des metriques toutes les 15 secondes.
- **Node Exporter** : expose les metriques systeme (CPU, RAM, reseau, FD, conntrack).
- **Grafana** : affiche les dashboards avec les graphes.
- **IMPORTANT** : ces ports ne sont **pas** exposes dans nftables par defaut. Ils ne sont accessibles que depuis localhost ou via un tunnel SSH.

---

## 6. Deploiement (deploy.sh)

### Fichier : `scripts/deploy.sh`

Ce script **deploie** la stack en copiant les fichiers de configuration et en appliquant les regles. Il ne fait PAS l'installation des packages (c'est le role de `install.sh`).

### Ce que fait chaque etape

#### Etape 1/8 : Copie des fichiers
- Copie tout le projet dans `/opt/fluxgate/`.
- Rend les scripts executables (`chmod +x`).

#### Etape 2/8 : Kernel tuning (sysctl)
- Copie `99-fluxgate-hardening.conf` dans `/etc/sysctl.d/`.
- Applique avec `sysctl --system`.
- Active SYN cookies, augmente le backlog, configure conntrack, durcit le reseau.

#### Etape 3/8 : nftables
- Copie `nftables.conf` dans `/etc/nftables.conf`.
- Remplace les ports SSH/HTTP/HTTPS par les valeurs de config.env.
- Charge les regles avec `nft -f`.
- **ATTENTION** : `flush ruleset` (premiere ligne de nftables.conf) supprime TOUTES les regles existantes d'un coup. Cela inclut les regles qui permettent votre session SSH actuelle. Voir la section [Problemes connus](#19-problemes-connus-et-pieges-classiques).

#### Etape 4/8 : NGINX
- Copie la config FluxGate dans `/etc/nginx/conf.d/fluxgate.conf`.
- Substitue les valeurs de rate limiting, burst, upstream port.
- Teste la config (`nginx -t`) et recharge NGINX.

#### Etape 5/8 : Apache (alternatif)
- Deploy uniquement si Apache est installe ET que NGINX est absent.
- Copie `security-hardening.conf` et active les modules necessaires.

#### Etape 6/8 : fail2ban
- Copie les jails et les filtres dans `/etc/fail2ban/`.
- Adapte les valeurs SSH (maxretry, findtime, bantime) depuis config.env.
- Redemarre fail2ban.

#### Etape 7/8 : CrowdSec
- Copie la config d'acquisition de logs.
- Redemarre CrowdSec.
- **IMPORTANT** : la cle API du bouncer doit etre configuree manuellement avec `cscli bouncers add`.

#### Etape 8/8 : systemd resource control
- Copie les templates (socket, service override, daemon XDP).
- Reload systemd.

#### Option XDP
- Si `XDP_ENABLED=true`, attache xdp-filter sur l'interface.

---

## 7. Couche 1 - Kernel tuning (sysctl)

### Fichier : `sysctl/99-fluxgate-hardening.conf`

Les parametres sysctl modifient le comportement du noyau Linux au niveau le plus bas. Ils s'appliquent **avant** nftables.

### SYN Cookies

```
net.ipv4.tcp_syncookies = 1
```

**Probleme resolu** : SYN flood.

**Comment ca marche normalement (sans SYN cookies)** :
1. Le client envoie un SYN.
2. Le serveur cree un etat dans la file SYN_RECV et repond SYN/ACK.
3. Le client repond ACK, la connexion est etablie.

Un attaquant envoie des millions de SYN sans jamais repondre ACK. La file SYN_RECV se remplit, plus aucune connexion n'est possible.

**Comment ca marche avec SYN cookies** :
1. Le client envoie un SYN.
2. Le serveur **ne cree pas d'etat**. Il encode les parametres de connexion dans le numero de sequence du SYN/ACK (cookie cryptographique).
3. Si le client repond avec un ACK valide, le serveur decode le cookie et cree la connexion.
4. Si l'attaquant ne repond pas, aucune ressource n'est gaspillee.

**Inconvenient** : les SYN cookies desactivent TCP window scaling et SACK (options negociees dans le handshake). Les performances TCP sont reduites pour les connexions longue distance.

**Recommandation** : toujours activer. C'est un mecanisme de **dernier recours** qui s'active automatiquement quand le backlog est plein.

### Backlog TCP

```
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 4096
```

- **`tcp_max_syn_backlog`** : file des connexions en cours de handshake (SYN_RECV). Plus la file est grande, plus le serveur peut absorber un pic de SYN avant d'activer les SYN cookies.
- **`somaxconn`** : file des connexions completees en attente d'`accept()` par l'application. Si l'application est lente a faire `accept()`, les connexions s'accumulent ici.

### Conntrack (suivi de connexions)

```
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 30
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
net.netfilter.nf_conntrack_tcp_loose = 0
```

**Conntrack, c'est quoi ?**

C'est le module noyau qui suit l'etat de chaque connexion. Sans conntrack, nftables ne pourrait pas utiliser `ct state established,related accept` car il ne saurait pas si un paquet fait partie d'une connexion existante.

**Table conntrack** : une table de hachage en memoire avec une entree par connexion.

**Probleme critique** : quand la table est pleine (`nf_conntrack_count = nf_conntrack_max`), les nouvelles connexions sont **droppees silencieusement**. Pas de log, pas d'erreur. Le serveur semble "down" mais il est juste en saturation conntrack.

**Comment diagnostiquer** :
```bash
# Voir le remplissage
cat /proc/sys/net/netfilter/nf_conntrack_count   # actuel
cat /proc/sys/net/netfilter/nf_conntrack_max     # max

# Voir les stats (drops = probleme)
conntrack -S

# Message dans dmesg si le noyau drope
dmesg | grep conntrack
# "nf_conntrack: table full, dropping packet"
```

**Timeouts reduits** : les timeouts par defaut du noyau sont tres longs (5 jours pour established !). En cas d'attaque, la table se remplit de connexions fantomes. Les timeouts reduits liberent les entrees plus vite :
- established : 86400s (1 jour au lieu de 5)
- syn_sent/recv : 30s (au lieu de 120s)
- fin_wait/time_wait : 30s (au lieu de 120s)
- close_wait : 15s

**`nf_conntrack_tcp_loose = 0`** : en mode "strict", les paquets qui ne correspondent pas a un handshake TCP valide sont droppes. Empeche les attaquants d'injecter des paquets dans des connexions existantes.

### Anti-spoofing

```
net.ipv4.conf.all.rp_filter = 1
```

**Reverse Path Filtering** : quand un paquet arrive sur l'interface, le noyau verifie que l'adresse source du paquet est routable via cette meme interface. Si un paquet pretend venir de 10.0.0.1 mais arrive sur l'interface publique, il est droppe.

Empeche le **spoofing** : un attaquant forge des paquets avec de fausses adresses sources.

### Redirections et routes sources

```
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
```

- **ICMP redirects** : un routeur peut demander a votre serveur de changer sa table de routage. Desactiver pour eviter les attaques de redirection.
- **Source routing** : un paquet peut specifier le chemin qu'il doit suivre. Desactiver car c'est un vecteur d'attaque.

### Paquets martiens

```
net.ipv4.conf.all.log_martians = 1
```

Log les paquets avec des adresses sources impossibles (0.0.0.0, 127.0.0.0/8 sur l'interface publique, etc.). Utile pour detecter du spoofing.

### Buffers reseau

```
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.core.netdev_max_backlog = 16384
```

- **rmem/wmem** : buffers de reception/emission par socket. Des buffers plus grands = meilleur debit sur les connexions longue distance (produit bandwidth-delay).
- **netdev_max_backlog** : file d'attente globale entre le driver NIC et la pile IP. Si le noyau ne peut pas traiter les paquets assez vite, ils s'accumulent ici. 16384 permet d'absorber des rafales.

### TCP hardening

```
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_max_orphans = 32768
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
```

- **synack_retries = 2** : le serveur renvoie un SYN/ACK 2 fois (au lieu de 5) si le client ne repond pas. Libere plus vite les entrees SYN_RECV sous flood.
- **tw_reuse = 1** : reutilise les sockets en TIME_WAIT pour de nouvelles connexions. Important sous forte charge (des milliers de connexions courtes).
- **keepalive_time = 600** : envoie un probe keepalive apres 10 minutes (au lieu de 2 heures) pour detecter les connexions mortes.
- **tcp_timestamps = 1** : LAISSER ACTIVE. Les timestamps TCP sont necessaires pour PAWS (Protection Against Wrapped Sequence numbers) et permettent un meilleur calcul du RTT.
- **tcp_sack = 1** : Selective Acknowledgment. Permet de retransmettre uniquement les segments perdus au lieu de tout retransmettre.

---

## 8. Couche 2 - Pare-feu nftables

### Fichier : `nftables/nftables.conf`

nftables est le pare-feu du noyau Linux (successeur d'iptables). Il filtre les paquets au niveau L3/L4 (IP, TCP, UDP, ICMP).

### Structure des regles

```
table inet filter {          <-- inet = IPv4 + IPv6
    set blocklist4 { ... }   <-- set dynamique IPv4
    set blocklist6 { ... }   <-- set dynamique IPv6
    set ratelimit4 { ... }   <-- compteurs par IP

    chain input {             <-- paquets entrants
        type filter hook input priority 0;
        policy drop;          <-- TOUT est bloque par defaut
        ...regles d'autorisation...
    }

    chain forward { policy drop; }  <-- pas de routage
    chain output { policy accept; } <-- sortant autorise
}

table inet rate_limit {       <-- table separee pour le rate limiting avance
    chain prerouting { ... }
}
```

### Regles expliquees une par une

#### `flush ruleset`
**Supprime TOUTES les regles nftables existantes**. C'est la premiere ligne du fichier. Cela garantit un etat propre mais **coupe toutes les connexions en cours**, y compris SSH. Voir [Problemes connus](#19-problemes-connus-et-pieges-classiques).

#### `policy drop`
**Politique par defaut : tout bloquer**. Seul ce qui est explicitement autorise passe. C'est le principe du "default deny", recommande par l'ANSSI.

#### Loopback
```
iif "lo" accept
```
Autorise tout le trafic sur l'interface loopback (127.0.0.1). Necessaire pour que les services locaux communiquent entre eux (NGINX vers app backend, Prometheus vers node exporter, etc.).

#### Paquets invalides
```
ct state invalid counter drop
```
Drop les paquets qui ne correspondent a aucune connexion connue et dont l'etat TCP est incoherent. Exemples :
- Un ACK sans SYN precedent.
- Un RST pour une connexion inexistante.
- Des paquets avec des flags TCP impossibles (SYN+FIN).

#### Blocklists dynamiques
```
ip  saddr @blocklist4 counter drop
ip6 saddr @blocklist6 counter drop
```
**Sets nftables** : ce sont des listes d'IP avec un timeout d'expiration automatique (1h par defaut). fail2ban, CrowdSec, et le script `nft-manage.sh` ajoutent des IP dans ces sets. Quand une IP est dans le set, TOUS ses paquets sont droppes.

Ajouter une IP manuellement :
```bash
nft add element inet filter blocklist4 '{ 203.0.113.50 timeout 2h }'
```

#### Connexions etablies
```
ct state established,related accept
```
**Regle la plus importante**. Autorise les paquets qui font partie d'une connexion deja etablie (le handshake TCP est termine) ou d'une connexion liee (par exemple, les reponses ICMP a une connexion TCP). Sans cette regle, les reponses a vos requetes sortantes seraient bloquees.

#### ICMP
```
ip protocol icmp icmp type { echo-request, echo-reply, ... }
    limit rate 10/second burst 20 packets accept
```
Autorise le ping et les messages ICMP essentiels (destination-unreachable, time-exceeded) avec une limite de 10/seconde. Sans cette limite, un attaquant pourrait flood en ICMP.

**Ne jamais bloquer completement ICMP** : `destination-unreachable` est necessaire pour le Path MTU Discovery. Le bloquer cause des problemes de fragmentation ("trou noir PMTU").

#### SSH
```
tcp dport $SSH_PORT ip saddr $ADMIN_NETS ct state new accept
tcp dport $SSH_PORT ct state new limit rate 5/minute burst 10 packets accept
```

**Deux regles SSH** :
1. Depuis les reseaux admin (`ADMIN_NETS`) : acces illimite.
2. Depuis partout : limite a 5 nouvelles connexions par minute (anti brute force au niveau firewall).

**PIEGE MAJEUR** : `ADMIN_NETS` est defini comme `{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }` (reseaux prives RFC 1918). Si vous vous connectez en SSH depuis une IP publique, vous n'etes PAS dans `ADMIN_NETS`. Vous dependez uniquement de la deuxieme regle (5/minute). Voir [Problemes connus](#19-problemes-connus-et-pieges-classiques).

#### HTTP/HTTPS SYN rate limit
```
tcp dport { $HTTP_PORT, $HTTPS_PORT } tcp flags syn ct state new
    limit rate 50/second burst 100 packets accept

tcp dport { $HTTP_PORT, $HTTPS_PORT } tcp flags syn ct state new
    counter drop
```

**Deux regles en cascade** :
1. Autorise jusqu'a 50 SYN/seconde (nouvelles connexions) avec un burst de 100.
2. Drop tous les SYN excedentaires.

**Pourquoi limiter les SYN ?** : un SYN flood envoie des millions de paquets SYN par seconde. Chaque SYN cree une entree conntrack et un etat SYN_RECV. Limiter les SYN au niveau nftables empeche la saturation.

#### UDP bloque par defaut
```
# udp dport 53 accept comment "DNS"
```
Tout UDP est bloque par defaut (policy drop). Decommenter si vous avez besoin de DNS ou d'autres services UDP. L'UDP est le vecteur principal des attaques par amplification (DNS, NTP, memcached).

### Rate limiting avance (table rate_limit)

```
tcp flags syn meter syn_flood { ip saddr limit rate over 100/second burst 150 packets }
    counter drop
```
**Meter** = compteur par IP. Chaque IP source est traquee individuellement. Si une seule IP envoie plus de 100 SYN/seconde, elle est droppee. Ceci est different de la limite globale dans la table filter (qui est un total pour toutes les IP confondues).

```
tcp flags syn ct state new meter conn_abuse { ip saddr ct count over 200 }
    counter drop
```
**ct count** = nombre de connexions simultanees par IP. Si une IP a plus de 200 connexions ouvertes, les nouvelles sont droppees. Equivalent de l'ancien `connlimit` d'iptables.

### Script de gestion : `nftables/nft-manage.sh`

```bash
# Bloquer une IP pour 2 heures
sudo bash nft-manage.sh block 203.0.113.50 2h

# Debloquer une IP
sudo bash nft-manage.sh unblock 203.0.113.50

# Voir les IPs bloquees
sudo bash nft-manage.sh list-blocked

# Voir les compteurs de drop
sudo bash nft-manage.sh counters

# Voir les stats conntrack
sudo bash nft-manage.sh conntrack-stats

# Afficher toutes les regles
sudo bash nft-manage.sh show

# MODE URGENCE : drop tout sauf SSH
sudo bash nft-manage.sh emergency-drop-all
```

**Mode urgence** : si votre serveur est sous attaque massive, cette commande flush toutes les regles et n'autorise plus que le SSH (sur le port configure). Vous pouvez ensuite diagnostiquer et appliquer des regles ciblees.

---

## 9. Couche 3 - XDP/eBPF (optionnel)

### Fichiers : `xdp/xdp-manage.sh`, `xdp/xdp-auto-block.sh`

### Qu'est-ce que XDP ?

XDP (eXpress Data Path) est une technologie Linux qui permet d'executer des programmes eBPF **directement dans le driver de la carte reseau**, avant meme que le paquet n'entre dans la pile noyau.

**Pourquoi c'est plus rapide que nftables** :
- nftables traite les paquets apres la creation d'un `sk_buff` (allocation memoire noyau).
- XDP traite le paquet brut dans le buffer du driver. Pas d'allocation, pas de copie.
- Performance : **10-20 millions de paquets/seconde** par coeur CPU (vs ~1-5 M pour nftables).

**Modes XDP** :
- **Native (driver)** : le programme s'execute dans le driver NIC. Necessite un driver compatible (ixgbe, i40e, mlx5, virtio-net, etc.). Performance maximale.
- **Generic (SKB)** : le programme s'execute apres la creation du SKB. Compatible avec tous les drivers. Performance intermediaire (mieux que nftables mais pas autant que le mode natif).
- Le script `xdp-manage.sh` essaie le mode natif d'abord, puis tombe en mode generic si le driver ne supporte pas.

### xdp-manage.sh

```bash
# Attacher xdp-filter sur l'interface
sudo bash xdp-manage.sh load

# Bloquer une IP pour 30 minutes
sudo bash xdp-manage.sh block-ip 203.0.113.50 30m

# Debloquer une IP
sudo bash xdp-manage.sh unblock-ip 203.0.113.50

# Bloquer un port (ex: UDP 53)
sudo bash xdp-manage.sh block-port 53 udp

# Lister les regles actives
sudo bash xdp-manage.sh list

# Voir le statut XDP
sudo bash xdp-manage.sh status

# Stats (avec bpftool)
sudo bash xdp-manage.sh stats

# Detacher XDP (rollback)
sudo bash xdp-manage.sh unload
```

### xdp-auto-block.sh (daemon)

Ce script tourne en boucle et surveille la table conntrack. Si une IP depasse un seuil de connexions (`XDP_CONN_THRESHOLD`, defaut 10000), elle est automatiquement bloquee via XDP.

**Fonctionnement** :
1. Lire la table conntrack (`conntrack -L`).
2. Compter le nombre d'entrees par IP source.
3. Si une IP depasse le seuil, la bloquer via `xdp-filter ip add`.
4. Attendre `XDP_SAMPLE_INTERVAL` secondes (defaut 5s).
5. Boucler.

**Service systemd** : `fluxgate-xdp-autoblock.service` execute ce script en daemon.

### Quand utiliser XDP vs nftables

| Situation | Recommandation |
|-----------|---------------|
| Trafic normal, quelques abus | nftables suffit |
| >100k paquets/seconde d'attaque | Activer XDP |
| Attaque volumetrique saturant le CPU | XDP en mode natif |
| VPS avec interface virtio | XDP mode generic (gain modeste) |
| Serveur dedie avec NIC Intel/Mellanox | XDP mode natif (gain maximum) |

---

## 10. Couche 4 - Reverse proxy (NGINX)

### Fichiers : `nginx/nginx-global.conf`, `nginx/nginx-fluxgate.conf`

### Pourquoi un reverse proxy ?

NGINX se place **devant** votre application et filtre les requetes au niveau HTTP (L7). Il peut :
- Limiter le nombre de requetes par IP (rate limiting).
- Limiter le nombre de connexions par IP.
- Fermer les connexions lentes (anti-slowloris).
- Renvoyer des 429 Too Many Requests au lieu de saturer votre app.
- Cacher les details de votre backend (IP, port, technologie).

### Configuration globale (nginx-global.conf)

```
worker_processes auto;          # 1 worker par coeur CPU
worker_rlimit_nofile 65536;     # Max fichiers ouverts par worker
```
- **`worker_processes auto`** : NGINX cree un processus par coeur CPU. Chaque processus gere des milliers de connexions grace au modele evenementiel (epoll).

```
events {
    worker_connections 4096;    # Max connexions par worker
    use epoll;                  # Modele I/O Linux haute performance
    multi_accept on;            # Accepter plusieurs connexions par boucle
}
```
- **Capacite totale** : `worker_processes * worker_connections` = 4 coeurs * 4096 = 16384 connexions simultanees.

```
keepalive_timeout 30s;          # Fermer les connexions inactives apres 30s
keepalive_requests 1000;        # Max 1000 requetes par connexion keepalive
reset_timedout_connection on;   # RST au lieu de FIN pour les timeouts
server_tokens off;              # Masquer la version de NGINX
```
- **`reset_timedout_connection on`** : envoie un RST au lieu de FIN pour les connexions en timeout. Un FIN attend un FIN/ACK (4-way handshake), un RST ferme instantanement. Libere les file descriptors plus vite sous attaque.

### Configuration FluxGate (nginx-fluxgate.conf)

#### Zones de rate limiting

```
limit_req_zone $binary_remote_addr zone=req_per_ip:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;
limit_conn_zone $server_name zone=conn_total:10m;
```

- **`limit_req_zone`** : cree une zone memoire partagee de 10 Mo (~160 000 IP) qui compte les requetes par IP.
- **`$binary_remote_addr`** : adresse IP du client en binaire (4 octets IPv4). Plus compact que la version texte.
- **`rate=30r/s`** : 30 requetes par seconde par IP.
- **Algorithme leaky bucket** : les requetes arrivent dans un seau qui se vide a un debit constant (30/s). Le seau peut deborder temporairement (burst).

#### Rate limit status et logging

```
limit_req_status 429;           # HTTP 429 au lieu de 503
limit_conn_status 429;
limit_req_log_level warn;       # Log les rate limits
```
- **429 vs 503** : 429 (Too Many Requests) est le code correct selon RFC 6585. 503 (Service Unavailable) est le defaut NGINX mais induit en erreur.

#### Detection des bots suspects

```
map $http_user_agent $bad_bot {
    default 0;
    ""             1;    # pas de User-Agent
    "~*python"     1;    # scripts Python (requests, urllib)
    "~*Go-http"    1;    # scripts Go
    "~*java"       1;    # scripts Java
}
```
- Bloque les requetes sans User-Agent ou avec des User-Agents de scripts automatises.
- **Attention** : certains outils legitimes (monitoring, CI/CD) utilisent ces User-Agents. Adapter si necessaire.

#### Upstream et keepalive

```
upstream app_backend {
    server 127.0.0.1:8080;
    keepalive 64;
}
```
- **`keepalive 64`** : maintient 64 connexions persistantes vers le backend. Evite le cout du handshake TCP pour chaque requete.

#### Timeouts anti-slow

```
client_header_timeout 10s;      # Max 10s pour envoyer les headers
client_body_timeout 10s;        # Max 10s pour envoyer le body
send_timeout 10s;               # Max 10s entre deux ecritures au client
```
- **Slowloris** : un attaquant envoie les headers HTTP un octet a la fois, pendant des heures. Chaque connexion bloque un worker. Avec `client_header_timeout 10s`, la connexion est fermee si les headers ne sont pas recus en 10s.

#### Buffers client

```
client_header_buffer_size 1k;
large_client_header_buffers 4 8k;
client_body_buffer_size 16k;
client_max_body_size 10m;
```
- Limiter la memoire consommee par requete empeche l'epuisement de RAM par un grand nombre de requetes avec des headers/body enormes.

#### Headers de securite

```
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```
- **`X-Content-Type-Options: nosniff`** : empeche le navigateur de deviner le type MIME (MIME sniffing attack).
- **`X-Frame-Options: SAMEORIGIN`** : empeche l'inclusion de votre site dans un iframe (clickjacking).
- **`Referrer-Policy`** : controle les informations de referer envoyees lors de la navigation.

#### Rate limit strict sur les endpoints sensibles

```
location /api/login {
    limit_req zone=req_per_ip burst=5 nodelay;
    ...
}
```
- Le endpoint de login est limite a 5 requetes en burst (bien plus strict que les 50 du reste). Empeche le brute force de mots de passe.

#### Pages d'erreur personnalisees

```
error_page 429 /429.html;
error_page 502 503 504 /50x.html;
```
- Affiche une page HTML propre au lieu du message d'erreur brut de NGINX.

### Bloc HTTPS (commente)

Le bloc HTTPS est commente dans le fichier. Pour l'activer :
1. Obtenir un certificat TLS (Let's Encrypt : `certbot --nginx`).
2. Decommenter le bloc `server { listen 443 ssl http2; ... }`.
3. Adapter les chemins des certificats.

---

## 11. Couche 4 bis - Reverse proxy (Apache)

### Fichier : `apache/security-hardening.conf`

Alternative a NGINX si vous utilisez Apache.

### mod_reqtimeout (anti-slow HTTP)

```
RequestReadTimeout header=10-40,MinRate=500 body=10-60,MinRate=500
```
- **header=10-40** : le client a entre 10 et 40 secondes pour envoyer tous les headers.
- **MinRate=500** : le timeout augmente si le client envoie au moins 500 octets/seconde (tolerance pour les connexions lentes).
- **body=10-60** : meme logique pour le body de la requete.

### MPM Event tuning

```
MaxRequestWorkers 256           # Max requetes simultanees
ThreadsPerChild 25              # Threads par processus
StartServers 4                  # Processus au demarrage
MaxConnectionsPerChild 10000    # Recyclage des processus
```
- **`MaxRequestWorkers`** : le nombre total de requetes simultanees que Apache peut traiter. Au-dela, les requetes sont mises en file d'attente.
- **`MaxConnectionsPerChild 10000`** : chaque processus est recycle apres 10000 connexions. Evite les fuites memoire.

### Methodes HTTP restreintes

```
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
```
- Seuls GET, POST et HEAD sont autorises. PUT, DELETE, TRACE, OPTIONS sont bloques.
- **TRACE** est particulierement dangereux (Cross-Site Tracing).

---

## 12. Couche 5 - WAF ModSecurity + CRS

### Fichiers : `waf/modsecurity/modsecurity.conf`, `waf/modsecurity/crs-setup-override.conf`

### Qu'est-ce qu'un WAF ?

Un WAF (Web Application Firewall) analyse le contenu des requetes HTTP pour detecter les attaques applicatives. Contrairement a nftables (qui ne voit que les IP/ports), le WAF comprend le HTTP et peut detecter :
- Injections SQL (`' OR 1=1 --`)
- Cross-Site Scripting (XSS) (`<script>alert(1)</script>`)
- Traversee de repertoire (`../../etc/passwd`)
- Command injection (`` `; cat /etc/passwd` ``)
- Et des centaines d'autres patterns via l'OWASP CRS.

### ModSecurity v3

ModSecurity est le moteur WAF. Il peut fonctionner avec NGINX (via le connecteur modsecurity-nginx) ou Apache (via mod_security2).

```
SecRuleEngine On
```
- **On** : bloquer les requetes matchees (mode production).
- **DetectionOnly** : logger sans bloquer (mode test/tuning).
- **Recommandation** : commencer en `DetectionOnly` pendant 1-2 semaines, analyser les logs, exclure les faux positifs, puis passer en `On`.

### Regles personnalisees

```
SecRule REQUEST_HEADERS:Host "^$"
    "id:10001,phase:1,deny,status:400,msg:'Missing Host header'"
```
- Bloque les requetes sans header `Host`. Les requetes HTTP valides ont toujours un header Host. Les scanners et bots en ont souvent pas.

```
SecRule REQUEST_METHOD "^(TRACE|TRACK|OPTIONS)"
    "id:10002,phase:1,deny,status:405,msg:'Method not allowed'"
```
- Bloque TRACE/TRACK/OPTIONS au niveau WAF (en plus de la restriction Apache).

### OWASP Core Rule Set (CRS)

Le CRS est un ensemble de plus de 1000 regles maintenues par l'OWASP. Il utilise un systeme de **scoring d'anomalie** :
- Chaque regle qui matche ajoute des points au score d'anomalie.
- Si le score depasse le seuil, la requete est bloquee.

#### Paranoia Level

```
SecAction "id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=1"
SecAction "id:900001,phase:1,pass,nolog,setvar:tx.detection_paranoia_level=2"
```

| Niveau | Description | Faux positifs |
|--------|-------------|---------------|
| 1 | Regles de base, attaques evidentes | Tres peu |
| 2 | Regles supplementaires, patterns moins courants | Quelques-uns |
| 3 | Regles strictes, patterns rarissimes | Beaucoup |
| 4 | Ultra-paranoiaque | Enormement |

- **`blocking_paranoia_level=1`** : bloque avec les regles de niveau 1.
- **`detection_paranoia_level=2`** : detecte (log) avec les regles de niveau 2 sans bloquer.
- Cela permet de voir dans les logs ce que le niveau 2 aurait bloque, sans impacter les utilisateurs.

#### Seuil d'anomalie

```
SecAction "id:900110,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=5"
```
- Score de 5 = une seule regle critique matchee suffit pour bloquer.
- Augmenter a 10-15 si vous avez des faux positifs.

#### Exclusions

```
SecRule REQUEST_URI "@beginsWith /health"
    "id:900200,phase:1,pass,nolog,ctl:ruleEngine=Off"
```
- Desactive le WAF pour les endpoints de health check et monitoring. Ces endpoints sont appeles en boucle par les outils internes et n'ont pas besoin d'etre filtres.

### Rate limiting WAF

```
SecAction "id:900301,phase:1,pass,nolog,setvar:ip.request_count=+1"
SecAction "id:900302,phase:1,pass,nolog,expirevar:ip.request_count=60"
SecRule IP:REQUEST_COUNT "@gt 100"
    "id:900303,phase:1,deny,status:429,msg:'WAF rate limit exceeded'"
```
- Compteur par IP qui s'incremente a chaque requete et se remet a zero toutes les 60 secondes.
- Si une IP depasse 100 requetes en 60 secondes, elle recoit un 429.
- C'est un **complement** au rate limiting NGINX/nftables, pas un remplacement.

---

## 13. Couche 6 - fail2ban

### Fichiers : `fail2ban/jail.d/`, `fail2ban/filter.d/`

### Comment fonctionne fail2ban

1. fail2ban lit les fichiers de log en continu.
2. Il applique des expressions regulieres (regex) pour trouver des patterns d'abus.
3. Si une IP declenche plus de `maxretry` fois en `findtime` secondes, elle est bannie.
4. Le ban consiste a ajouter l'IP dans un set nftables (via `banaction = nftables[type=allports]`).
5. L'IP est debannie automatiquement apres `bantime` secondes.

### Jails configurees

#### SSH (fluxgate-sshd.conf)

```
[sshd]
enabled  = true
port     = ssh
filter   = sshd           # regex built-in de fail2ban
logpath  = /var/log/auth.log
           /var/log/secure
maxretry = 5              # 5 tentatives
findtime = 600            # en 10 minutes
bantime  = 3600           # ban 1 heure
banaction = nftables[type=allports]
```
- Detecte les echecs d'authentification SSH (mot de passe incorrect, cle refusee).
- `type=allports` : bloque l'IP sur TOUS les ports, pas seulement SSH. Un attaquant qui brute force SSH est probablement malveillant sur tous les ports.

#### NGINX 4xx (fluxgate-nginx.conf)

```
[nginx-4xx]
filter   = nginx-4xx
logpath  = /var/log/nginx/access.log
maxretry = 100
findtime = 60
bantime  = 600
```
- Detecte les IP qui generent beaucoup d'erreurs 4xx (400, 401, 403, 404, 405, 408, 429).
- 100 erreurs en 1 minute = ban 10 minutes.
- **Usage** : detecte les scanners de vulnerabilites (essaient des milliers d'URLs inexistantes).

#### NGINX rate limit (fluxgate-nginx.conf)

```
[nginx-limit-req]
filter   = nginx-limit-req    # regex built-in
logpath  = /var/log/nginx/error.log
maxretry = 30
findtime = 60
bantime  = 1800
```
- Detecte les IP qui se font rate-limiter par NGINX (429 Too Many Requests).
- 30 occurrences en 1 minute = ban 30 minutes.
- **Logique** : si une IP ignore les 429 et continue a envoyer des requetes, c'est un bot.

#### NGINX botsearch

```
[nginx-botsearch]
filter   = nginx-botsearch     # regex built-in
logpath  = /var/log/nginx/access.log
maxretry = 20
findtime = 120
bantime  = 3600
```
- Detecte les bots qui scannent des chemins suspects (`.env`, `wp-admin`, `phpMyAdmin`, etc.).
- 20 occurrences en 2 minutes = ban 1 heure.

#### Apache (fluxgate-apache.conf)

Memes principes que NGINX, adapte pour les logs Apache :
- **apache-4xx** : erreurs 4xx.
- **apache-auth** : echecs d'authentification.
- **apache-botsearch** : scans de bots.

### Filtres regex

#### nginx-4xx.conf

```
failregex = ^<HOST> - .* "(GET|POST|HEAD|PUT|DELETE|PATCH) .* HTTP/.*" (400|401|403|404|405|408|429) .*$
ignoreregex = ^<HOST> - .* "(GET|POST) /health.*"
              ^<HOST> - .* "(GET) /favicon.ico.*"
```
- **`<HOST>`** : pattern special fail2ban qui capture l'adresse IP.
- **`ignoreregex`** : exclut les endpoints de health check et favicon des compteurs (evite les faux positifs).

### Commandes utiles

```bash
# Voir le statut de toutes les jails
sudo fail2ban-client status

# Voir les IPs bannies d'une jail
sudo fail2ban-client status sshd

# Debannir une IP
sudo fail2ban-client set sshd unbanip 203.0.113.50

# Tester un filtre sur un log
sudo fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/nginx-4xx.conf
```

---

## 14. Couche 7 - CrowdSec

### Fichiers : `crowdsec/acquis.yaml`, `crowdsec/crowdsec-firewall-bouncer.yaml`

### Difference avec fail2ban

| | fail2ban | CrowdSec |
|--|---------|----------|
| Analyse | Regex sur les logs | Parsers + scenarios (YAML) |
| Intelligence | Locale uniquement | **Base communautaire** |
| Partage | Non | Oui (envoi/reception d'IP malveillantes) |
| Performance | Bonne | Meilleure (Go vs Python) |
| Bouncer | Action directe (nftables) | Bouncer separe (modulaire) |

**Avantage majeur de CrowdSec** : quand un utilisateur CrowdSec detecte une attaque, l'IP est partagee avec tous les autres utilisateurs. Votre serveur peut bloquer une IP **avant** qu'elle ne l'attaque.

### Configuration d'acquisition (acquis.yaml)

```yaml
filenames:
  - /var/log/auth.log
  - /var/log/syslog
labels:
  type: syslog
---
filenames:
  - /var/log/nginx/access.log
  - /var/log/nginx/error.log
labels:
  type: nginx
```
- Definit les sources de logs que CrowdSec doit analyser.
- Le `type` indique a CrowdSec quel parser utiliser (syslog, nginx, apache2, nftables, modsecurity).

### Bouncer firewall (crowdsec-firewall-bouncer.yaml)

```yaml
mode: nftables
api_url: http://127.0.0.1:8080/
api_key: <CROWDSEC_BOUNCER_API_KEY>
update_frequency: 10s
```
- Le bouncer interroge l'API locale de CrowdSec toutes les 10 secondes.
- Il recupere les decisions (ban, captcha) et les applique dans nftables.
- Les sets crees par CrowdSec sont **separes** de ceux de FluxGate (table `crowdsec` vs `filter`).

### Installation et configuration

```bash
# Installer (via install.sh ou manuellement)
sudo apt install crowdsec crowdsec-firewall-bouncer-nftables

# Enregistrer le bouncer (genere une cle API)
sudo cscli bouncers add fluxgate-bouncer
# Copier la cle generee dans crowdsec-firewall-bouncer.yaml

# Installer des collections de regles
sudo cscli collections install crowdsecurity/linux
sudo cscli collections install crowdsecurity/nginx
sudo cscli collections install crowdsecurity/sshd

# Verifier les decisions actives
sudo cscli decisions list

# Voir les metriques
sudo cscli metrics
```

---

## 15. Couche 8 - Traffic shaping (tc)

### Fichier : `tc/tc-shape.sh`

### Qu'est-ce que le traffic shaping ?

`tc` (traffic control) est l'outil Linux pour controler le trafic **sortant**. FluxGate utilise un **Token Bucket Filter (TBF)** pour plafonner le debit sortant.

### Pourquoi limiter le trafic sortant ?

1. **Anti-amplification** : votre serveur peut etre utilise comme reflecteur dans une attaque par amplification (DNS, NTP, memcached). Limiter le sortant reduit l'impact.
2. **Protection des voisins** : en hebergement partage (VPS), un trafic sortant excessif peut affecter les autres clients.
3. **Stabilite** : evite que le serveur sature sa propre bande passante.

### Comment fonctionne TBF

Le Token Bucket Filter est un algorithme simple :
1. Un seau se remplit de "tokens" a un debit constant (`rate`).
2. Chaque paquet consomme des tokens proportionnellement a sa taille.
3. Si le seau est plein, les tokens excedentaires sont perdus (`burst` = taille du seau).
4. Si le seau est vide, les paquets sont mis en file d'attente (jusqu'a `latency`).
5. Si la file est pleine, les paquets sont droppes.

### Utilisation

```bash
# Appliquer le shaping (1 Gbps, burst 32k, latence max 50ms)
sudo bash tc-shape.sh apply

# Appliquer avec des parametres personnalises
sudo bash tc-shape.sh apply -r 500mbit -b 64kbit

# Voir les stats
sudo bash tc-shape.sh status

# Monitoring temps reel
sudo bash tc-shape.sh monitor

# Supprimer le shaping
sudo bash tc-shape.sh remove
```

---

## 16. Couche 9 - systemd (sockets et cgroups)

### Fichiers : `systemd/fluxgate-app.socket`, `systemd/fluxgate-web.service.d/resource-limits.conf`

### Socket activation (fluxgate-app.socket)

```ini
[Socket]
ListenStream=8080
MaxConnectionsPerSource=50      # Max connexions par IP
Backlog=4096                    # File d'attente accept()
MaxConnections=1024             # Max connexions totales
KeepAlive=true
NoDelay=true
```

**Comment ca marche** :
1. systemd cree le socket et ecoute sur le port 8080.
2. Quand une connexion arrive, systemd la transmet au service associe.
3. Si une IP a deja 50 connexions ouvertes, les nouvelles sont refusees.
4. C'est une protection **au niveau du noyau**, avant meme que l'application ne soit sollicitee.

### Resource control (resource-limits.conf)

```ini
[Service]
CPUQuota=80%
MemoryMax=2G
MemoryHigh=1800M
LimitNOFILE=65536
LimitNPROC=4096
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
```

**Cgroups v2** : systemd utilise les cgroups du noyau Linux pour isoler les ressources de chaque service.

- **`CPUQuota=80%`** : le service ne peut pas monopoliser le CPU. Meme sous attaque, SSH et les autres services restent accessibles.
- **`MemoryMax=2G`** : si le service fuit en memoire (fuite, attaque), il est tue a 2 Go. Empeche l'OOM killer de tuer des processus aleatoires.
- **`MemoryHigh=1800M`** : a partir de 1.8 Go, le noyau commence a reclamer agressivement la memoire du service (pression memoire).
- **`NoNewPrivileges=true`** : le service ne peut pas obtenir de privileges supplementaires (meme avec suid). Securite contre l'escalade de privileges.
- **`ProtectSystem=strict`** : le systeme de fichiers est en lecture seule sauf `/dev`, `/proc`, `/sys`, et les repertoires explicitement autorises.
- **`PrivateTmp=true`** : le service a son propre `/tmp` isole. Empeche les attaques via des fichiers temporaires partages.

### Service XDP auto-block (fluxgate-xdp-autoblock.service)

```ini
[Service]
Type=simple
ExecStart=/opt/fluxgate/xdp/xdp-auto-block.sh
Restart=on-failure
RestartSec=10s
CPUQuota=10%
MemoryMax=256M
```
- Execute le daemon de blocage automatique XDP.
- Limite a 10% CPU et 256 Mo RAM pour eviter que le daemon lui-meme ne consomme trop de ressources.

---

## 17. Monitoring (Prometheus + Grafana)

### Fichiers : `monitoring/prometheus/`, `monitoring/grafana/`

### Architecture du monitoring

```
[Node Exporter] --metriques--> [Prometheus] --requetes--> [Grafana]
    :9100              scrape 15s     :9090                     :3000
                                        |
                                   [Alertes]
                                   fluxgate-alerts.yml
```

### Prometheus (prometheus.yml)

Prometheus collecte des metriques en "scraping" des endpoints HTTP toutes les 15 secondes.

**Targets configures** :
- **`prometheus:9090`** : Prometheus lui-meme (meta-monitoring).
- **`node:9100`** : Node Exporter (metriques systeme).
- **`crowdsec-bouncer:60601`** : metriques du bouncer CrowdSec.

### Alertes (fluxgate-alerts.yml)

Les alertes sont evaluees toutes les 15 secondes. Quand une condition est vraie pendant la duree specifiee (`for`), l'alerte se declenche.

#### Alertes DDoS

| Alerte | Condition | Severite | Signification |
|--------|-----------|----------|---------------|
| HighSoftIRQ | softirq CPU > 30% pendant 2m | warning | Le CPU passe trop de temps a traiter les interruptions reseau. Signe de flood. |
| HighPacketRate | > 100k pps pendant 2m | warning | Trafic reseau anormalement eleve. |
| NetworkRXDrops | > 100 drops/sec pendant 1m | warning | Le noyau ne peut pas traiter les paquets assez vite. |
| ConntrackNearMax | conntrack > 80% pendant 1m | **critical** | La table conntrack va etre pleine. Nouvelles connexions bientot droppees. |
| HighTimeWait | > 10000 TIME_WAIT pendant 2m | warning | Beaucoup de connexions courtes. Possible flood ou mauvais keepalive. |
| HighInboundBandwidth | > 800 Mbps pendant 2m | **critical** | Bande passante saturee. Attaque volumetrique probable. |

#### Alertes ressources

| Alerte | Condition | Severite | Signification |
|--------|-----------|----------|---------------|
| FileDescriptorsHigh | FD > 80% du max pendant 2m | warning | Trop de fichiers/sockets ouverts. |
| MemoryLow | RAM disponible < 10% pendant 2m | **critical** | Risque d'OOM killer. |
| HighCPUUsage | CPU > 90% pendant 5m | warning | Serveur surcharge. |
| ServiceDown | Target unreachable pendant 1m | **critical** | Un service est tombe. |

### Grafana

Le dashboard `fluxgate-ddos-overview.json` est provisionne automatiquement. Il affiche :
- Trafic reseau (pps, Mbps).
- Remplissage conntrack.
- CPU softirq.
- Sockets par etat (ESTABLISHED, SYN_RECV, TIME_WAIT).
- IPs bannies (fail2ban, CrowdSec).

**Acces** : `http://localhost:3000` (login par defaut : admin/admin).

**Depuis l'exterieur** : creer un tunnel SSH pour acceder a Grafana sans l'exposer sur Internet :
```bash
ssh -L 3000:127.0.0.1:3000 user@serveur
# Puis ouvrir http://localhost:3000 dans votre navigateur
```

---

## 18. Scripts utilitaires

### validate.sh - Validation post-deploiement

```bash
sudo bash scripts/validate.sh
```

Verifie que tous les composants fonctionnent :
- SYN cookies actifs, backlog correct, rp_filter actif.
- nftables charge avec chain input, blocklist, rate limiting.
- Conntrack en-dessous de 80%.
- Services actifs (nftables, nginx, fail2ban, crowdsec).
- Config NGINX valide, rate limiting present.
- Jails fail2ban actives.
- XDP attache ou non.
- Ports en ecoute.
- Ressources systeme (RAM, CPU, FD, load average).

**Resume** : affiche PASS (vert), FAIL (rouge), WARN (jaune) avec un total.

### status.sh - Dashboard CLI temps reel

```bash
sudo bash scripts/status.sh
```

Affiche un dashboard complet en une commande :
- Systeme : hostname, uptime, load, memoire, FD.
- Reseau : RX/TX bytes, drops, errors sur l'interface.
- XDP : actif ou inactif.
- Conntrack : remplissage avec code couleur (vert < 50%, jaune < 80%, rouge >= 80%).
- nftables : chains actives, compteur de drops, IPs bloquees.
- Services : etat de chaque service.
- fail2ban : jails et nombre de bans.
- Sockets TCP : par etat (ESTABLISHED, SYN_RECV, TIME_WAIT, CLOSE_WAIT, LISTEN).

### rollback.sh - Retour a l'etat initial

```bash
sudo bash scripts/rollback.sh
```

**ATTENTION : ce script supprime toutes les protections FluxGate.**

Ce qu'il fait :
1. Detache XDP.
2. Flush toutes les regles nftables (le serveur est **ouvert** apres ca).
3. Supprime le shaping tc.
4. Retire le sysctl FluxGate (reboot recommande).
5. Supprime les configs NGINX/Apache FluxGate.
6. Supprime les jails fail2ban FluxGate.
7. Supprime les overrides systemd FluxGate.
8. Reload systemd.

**Usage** : en cas de probleme grave cause par FluxGate, utiliser le rollback pour revenir a un etat propre. Un reboot est recommande ensuite.

---

## 19. Problemes connus et pieges classiques

### PIEGE 1 : Perte d'acces SSH apres deploiement nftables

**C'est le probleme le plus courant et le plus grave.**

**Cause** : `nftables.conf` commence par `flush ruleset` qui supprime **toutes** les regles. Pendant un instant, il n'y a aucune regle et aucune connexion n'est autorisee. Les nouvelles regles sont ensuite chargees, mais :

1. La variable `ADMIN_NETS` est definie comme `{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }` (reseaux prives).
2. Si vous vous connectez en SSH depuis une IP **publique**, vous n'etes PAS dans `ADMIN_NETS`.
3. Votre session SSH existante utilise `ct state established,related accept` pour rester ouverte. Mais le `flush ruleset` detruit la table conntrack associee aux anciennes regles.
4. Resultat : **votre session SSH est coupee** et vous ne pouvez plus vous reconnecter (rate limited a 5/minute, et si le handshake tombe pendant le flush, la connexion echoue).

**Solutions** :

1. **Avant le deploiement** : ajouter votre IP publique dans `ADMIN_NETS` :
   ```
   define ADMIN_NETS = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, VOTRE_IP/32 }
   ```

2. **Cron de securite** : avant d'appliquer les regles, programmer un cron qui flush les regles dans 5 minutes :
   ```bash
   echo "nft flush ruleset" | at now + 5 minutes
   ```
   Si tout va bien, annuler le cron (`atrm <job_id>`). Si vous perdez l'acces, les regles sont supprimees automatiquement apres 5 minutes.

3. **Recuperation** : acceder au serveur via la **console KVM/VNC** de votre hebergeur (OVH Manager, Hetzner Robot, Scaleway Console, etc.) et executer `nft flush ruleset`.

### PIEGE 2 : Conntrack full = drop silencieux

**Symptome** : le serveur semble down, mais SSH fonctionne (parce que les sessions SSH existantes sont dans `ct state established`). Les nouvelles connexions HTTP echouent.

**Diagnostic** :
```bash
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max
dmesg | grep "table full"
```

**Solution immediate** : augmenter `nf_conntrack_max` :
```bash
sysctl -w net.netfilter.nf_conntrack_max=524288
```

**Solution long terme** : reduire les timeouts, activer le rate limiting, ajouter XDP pour dropper le trafic malveillant avant qu'il ne cree des entrees conntrack.

### PIEGE 3 : fail2ban se ban lui-meme

Si votre serveur de monitoring interroge l'application depuis la meme machine et genere des 4xx, fail2ban peut bannir 127.0.0.1.

**Solution** : ajouter `ignoreip = 127.0.0.1/8 ::1` dans les jails.

### PIEGE 4 : SYN cookies + Window Scaling

Quand les SYN cookies sont actifs (backlog plein), les options TCP negociees dans le SYN (window scaling, SACK, timestamps) sont perdues. Les connexions TCP fonctionnent mais avec des performances reduites (petite fenetre TCP = debit limite).

**Ce n'est PAS un bug** : les SYN cookies sont un mecanisme de dernier recours. Dimensionner le backlog correctement pour que les SYN cookies ne s'activent que sous attaque.

### PIEGE 5 : Rate limit NGINX trop agressif

Les utilisateurs derriere un NAT (entreprise, universite, hotspot WiFi) partagent la meme IP publique. Un rate limit de 30 req/s par IP peut etre trop bas pour 100 utilisateurs derriere un meme NAT.

**Solutions** :
- Augmenter `NGINX_REQ_PER_SEC` et `NGINX_BURST`.
- Utiliser `X-Forwarded-For` si vous etes derriere un autre proxy/CDN.
- Whitelister les IP des proxies connus.

### PIEGE 6 : ModSecurity faux positifs

Le CRS est tres strict et peut bloquer des requetes legitimes (caracteres speciaux dans les formulaires, requetes API avec du JSON complexe).

**Solution** :
1. Commencer en `SecRuleEngine DetectionOnly`.
2. Analyser les logs : `grep "id:" /var/log/modsecurity/modsec_audit.log`.
3. Exclure les regles problematiques pour les chemins concernes :
   ```
   SecRuleUpdateTargetById 942100 "!ARGS:mon_parametre"
   ```
4. Passer en `SecRuleEngine On` quand le tuning est fait.

### PIEGE 7 : CrowdSec bouncer "access forbidden" / "bouncer stream halted"

Le bouncer refuse de demarrer avec l'erreur `process terminated with error: bouncer stream halted`. Dans les logs (`/var/log/crowdsec-firewall-bouncer.log`), on trouve `API error: access forbidden`.

**Causes possibles** :
1. La cle API est encore le placeholder `<CROWDSEC_BOUNCER_API_KEY>`.
2. La cle API ne correspond pas a un bouncer enregistre dans CrowdSec.
3. Plusieurs bouncers ont ete enregistres et la cle utilisee correspond a un ancien bouncer supprime.
4. Le package `crowdsec-firewall-bouncer-nftables` est reste en etat **partiellement installe** dans dpkg, ce qui bloque TOUTES les operations `apt-get install` (chaque `apt install` echoue avec `E: Sub-process /usr/bin/dpkg returned an error code (1)`).

**Diagnostic** :
```bash
# Voir l'erreur exacte
tail -10 /var/log/crowdsec-firewall-bouncer.log

# Verifier la cle dans la config
grep api_key /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml

# Lister les bouncers enregistres
sudo cscli bouncers list
```

**Solution complete (etape par etape)** :

```bash
# 1. Supprimer TOUS les bouncers existants
sudo cscli bouncers list
# Pour chaque bouncer affiche :
sudo cscli bouncers delete <nom-du-bouncer>

# 2. Redemarrer CrowdSec (nettoyer l'etat)
sudo systemctl restart crowdsec

# 3. Creer un nouveau bouncer avec une cle explicite
sudo cscli bouncers add crowdsec-firewall-bouncer -k "maclesecrete123"

# 4. Mettre cette cle dans la config
sudo sed -i 's/^api_key:.*/api_key: maclesecrete123/' /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml

# 5. Redemarrer le bouncer
sudo systemctl restart crowdsec-firewall-bouncer

# 6. Verifier que ca marche
tail -5 /var/log/crowdsec-firewall-bouncer.log
# Doit afficher : "Processing new and deleted decisions . . ."

# 7. Finaliser le package dpkg bloque
sudo dpkg --configure crowdsec-firewall-bouncer-nftables
sudo apt-get install -f
```

**Point cle** : le script post-install du package essaie de demarrer le service. Si le service echoue (cle invalide), dpkg considere que l'installation a echoue et le package reste en etat "partiellement installe". Cela bloque ensuite TOUTES les operations apt. Il faut d'abord corriger le service (cle API valide), PUIS finaliser dpkg.

**Astuce** : utiliser `-k "cle"` avec `cscli bouncers add` permet de choisir sa propre cle au lieu d'en generer une aleatoire. C'est plus facile a copier sans erreur.

### PIEGE 8 : XDP incompatible avec le driver NIC

Certains drivers NIC (surtout les anciens) ne supportent pas XDP en mode natif.

**Symptome** : `xdp-filter load` echoue.
**Solution** : le script utilise automatiquement le mode generic (`--mode skb`). Les performances sont moindres mais ca fonctionne.

### PIEGE 9 : deploy.sh ne fait rien si les packages manquent

`deploy.sh` verifie `command -v nft` / `command -v nginx` / etc. Si le package n'est pas installe, l'etape est **ignoree silencieusement** avec un warning.

**Solution** : executer `install.sh` AVANT `deploy.sh`.

### PIEGE 10 : Ports monitoring exposes / Grafana inaccessible en LAN

Prometheus (9090), Node Exporter (9100), et Grafana (3000) ne sont PAS dans les regles nftables par defaut. Ils ne sont accessibles que depuis localhost (`127.0.0.1`). En consequence, `http://localhost:3000` fonctionne sur le serveur mais `http://192.168.0.X:3000` depuis un autre PC du LAN est **bloque par nftables** (policy drop).

**Solution 1 (recommandee) : Tunnel SSH**

Pas besoin d'ouvrir de port. Depuis votre PC (PowerShell, terminal, etc.) :
```bash
ssh -L 3000:127.0.0.1:3000 user@192.168.0.X
```
Puis ouvrir `http://localhost:3000` dans le navigateur. Le trafic passe par le tunnel SSH chiffre. Meme chose pour Prometheus :
```bash
ssh -L 9090:127.0.0.1:9090 user@192.168.0.X
# Puis http://localhost:9090
```

**Solution 2 : Ouvrir le port en LAN uniquement**

Ajouter une regle nftables temporaire (perdue au reboot) :
```bash
# Grafana depuis le LAN uniquement
sudo nft add rule inet filter input ip saddr 192.168.0.0/24 tcp dport 3000 accept

# Prometheus depuis le LAN uniquement (optionnel)
sudo nft add rule inet filter input ip saddr 192.168.0.0/24 tcp dport 9090 accept
```

Pour rendre la regle permanente, ajouter dans `nftables/nftables.conf` avant le compteur final de la chain input :
```
# --- Monitoring : acces LAN uniquement ---
tcp dport { 3000, 9090, 9100 } ip saddr 192.168.0.0/24 accept comment "Monitoring LAN only"
```

**IMPORTANT** : ne JAMAIS exposer ces ports sur Internet. N'importe qui pourrait voir vos metriques systeme (CPU, RAM, reseau, IPs bannies, etc.). Toujours restreindre a `ADMIN_NETS` ou au LAN.

### PIEGE 11 : NGINX "duplicate default server"

Apres le deploiement, NGINX refuse de recharger avec l'erreur :
```
a duplicate default server for 0.0.0.0:80 in /etc/nginx/sites-enabled/default:22
```

**Cause** : Debian/Ubuntu installe un fichier `/etc/nginx/sites-enabled/default` qui ecoute sur le port 80. La config FluxGate (`/etc/nginx/conf.d/fluxgate.conf`) ecoute aussi sur le port 80 avec `listen 80 default_server`. Deux blocs `default_server` sur le meme port = erreur.

**Solution** :
```bash
sudo rm /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

Le fichier original reste dans `/etc/nginx/sites-available/default` si vous en avez besoin plus tard.

### PIEGE 12 : validate.sh affiche PASS puis FAIL pour la meme valeur

**Cause** : un bug dans le script original ou `((PASS++))` retourne un code d'erreur quand `PASS=0` (bash considere 0 comme "faux"). La syntaxe `[[ ... ]] && check_pass || check_fail` n'est pas un vrai if/else : si `check_pass` retourne un code non-zero, le `||` s'execute aussi.

**Solution** : le bug est corrige dans la version actuelle de `validate.sh`. Si vous avez une ancienne version, recopier depuis le projet :
```bash
sudo cp scripts/validate.sh /opt/fluxgate/scripts/validate.sh
```

### PIEGE 13 : ADMIN_NETS trop large (/16 au lieu de /24)

La config par defaut contient `192.168.0.0/16` dans `ADMIN_NETS`, ce qui autorise le SSH admin depuis **tout** le range `192.168.0.0` - `192.168.255.255` (65534 IPs). Si votre LAN est un simple `/24` (ex: `192.168.0.1` - `192.168.0.254`), c'est trop permissif.

**Solution** : restreindre `ADMIN_NETS` a votre sous-reseau reel :
```
define ADMIN_NETS = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/24 }
```

Meme logique pour les autres ranges : si vous n'utilisez pas `10.x.x.x` ou `172.16.x.x`, retirez-les.

### PIEGE 14 : Prometheus ne trouve pas le fichier d'alertes

Apres `install.sh`, Prometheus refuse de demarrer ou n'a pas d'alertes. `promtool check config` affiche :
```
FAILED: "/etc/prometheus/rules/fluxgate-alerts.yml" does not point to an existing file
```

**Cause** : une ancienne version de `install.sh` copiait le fichier d'alertes dans `/etc/prometheus/fluxgate-alerts.yml` au lieu de `/etc/prometheus/rules/fluxgate-alerts.yml` (le sous-dossier `rules/` n'etait pas cree).

**Solution** :
```bash
sudo mkdir -p /etc/prometheus/rules
sudo cp monitoring/prometheus/fluxgate-alerts.yml /etc/prometheus/rules/fluxgate-alerts.yml
sudo chown -R prometheus:prometheus /etc/prometheus/
sudo systemctl restart prometheus
```

Le bug est corrige dans la version actuelle de `install.sh`.

### PIEGE 15 : deploy.sh lance depuis le mauvais repertoire

```bash
root@debian:/home/test/BRCloud FluxGate/scripts# sudo bash scripts/deploy.sh
bash: scripts/deploy.sh: Aucun fichier ou dossier de ce nom
```

**Cause** : vous etes deja dans le dossier `scripts/` et le script cherche `scripts/deploy.sh` relativement au repertoire courant (donc `scripts/scripts/deploy.sh`).

**Solutions** :
```bash
# Option 1 : depuis le dossier scripts/
./deploy.sh

# Option 2 : depuis la racine du projet
cd /home/test/BRCloud\ FluxGate
sudo bash scripts/deploy.sh
```

---

## 20. Retour d'experience - Premier deploiement (Debian 13)

Cette section documente les problemes reellement rencontres lors du premier deploiement sur un serveur Debian 13 (Trixie), kernel 6.12, dans l'ordre chronologique. Chaque probleme renvoie vers le piege correspondant.

### Etape 1 : Installation (install.sh)

**Resultat** : tous les packages s'installent correctement (nftables, conntrack, fail2ban, crowdsec, prometheus, grafana), MAIS chaque etape affiche "Echec" a cause du package `crowdsec-firewall-bouncer-nftables` bloque.

**Probleme** : le bouncer CrowdSec n'a pas de cle API valide. Son script post-install essaie de demarrer le service, il echoue, et dpkg reste en etat "partiellement installe". A chaque appel `apt-get install`, dpkg re-tente de configurer ce package et echoue, ce qui fait echouer toute la commande meme si les autres packages sont bien installes.

**Solution** : voir [PIEGE 7](#piege-7--crowdsec-bouncer-access-forbidden--bouncer-stream-halted). Configurer la cle API du bouncer puis `dpkg --configure`.

### Etape 2 : Deploiement (deploy.sh)

**Probleme 1 - Perte d'acces SSH** : apres l'application des regles nftables, la session SSH est coupee. L'acces est recupere en modifiant `ADMIN_NETS` de `/16` a `/24` via la console KVM.

**Solution** : voir [PIEGE 1](#piege-1--perte-dacces-ssh-apres-deploiement-nftables) et [PIEGE 13](#piege-13--admin_nets-trop-large-16-au-lieu-de-24).

**Probleme 2 - NGINX duplicate default server** : l'erreur `a duplicate default server for 0.0.0.0:80` empeche NGINX de recharger.

**Solution** : voir [PIEGE 11](#piege-11--nginx-duplicate-default-server). Supprimer `/etc/nginx/sites-enabled/default`.

### Etape 3 : CrowdSec bouncer

**Probleme** : malgre la generation de cles API (via `cscli bouncers add`), le bouncer affiche toujours `API error: access forbidden` et `bouncer stream halted`.

**Causes identifiees** :
1. Trois bouncers differents etaient enregistres (`cs-firewall-bouncer-1771100405`, `fluxgate-bouncer`, `crowdsec-firewall-bouncer`).
2. La cle dans le fichier YAML ne correspondait pas au bon bouncer.
3. Les cles generees automatiquement sont longues et contiennent des caracteres speciaux (ex: `+`, `/`), ce qui peut causer des erreurs de copie.

**Solution qui a fonctionne** :
```bash
# Supprimer TOUS les bouncers
sudo cscli bouncers delete cs-firewall-bouncer-1771100405
sudo cscli bouncers delete fluxgate-bouncer
sudo cscli bouncers delete crowdsec-firewall-bouncer

# Redemarrer CrowdSec
sudo systemctl restart crowdsec

# Creer un bouncer avec une cle simple et explicite
sudo cscli bouncers add crowdsec-firewall-bouncer -k testkey123

# Mettre cette cle dans la config
sudo sed -i 's/^api_key:.*/api_key: testkey123/' /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml

# Redemarrer le bouncer
sudo systemctl restart crowdsec-firewall-bouncer

# Verifier
tail -5 /var/log/crowdsec-firewall-bouncer.log
# -> "Processing new and deleted decisions . . ." = OK

# Finaliser dpkg
sudo dpkg --configure crowdsec-firewall-bouncer-nftables
sudo apt-get install -f
```

**Lecon** : utiliser `-k "cle"` pour choisir sa propre cle evite les problemes de copie de cles aleatoires.

### Etape 4 : Validation (validate.sh)

**Probleme** : le script affiche `[PASS] SYN cookies actifs` suivi immediatement de `[FAIL] SYN cookies inactifs (1)` pour la meme valeur, puis se termine.

**Solution** : voir [PIEGE 12](#piege-12--validatesh-affiche-pass-puis-fail-pour-la-meme-valeur). Bug bash corrige dans `validate.sh` (`PASS=$((PASS+1))` au lieu de `((PASS++))`).

### Etape 5 : Monitoring

**Probleme 1** : Prometheus ne demarre pas car le fichier d'alertes est au mauvais chemin.

**Solution** : voir [PIEGE 14](#piege-14--prometheus-ne-trouve-pas-le-fichier-dalertes). Creer `/etc/prometheus/rules/` et y copier le fichier.

**Probleme 2** : Grafana fonctionne en `localhost:3000` sur le serveur mais est inaccessible depuis un autre PC du LAN.

**Solution** : voir [PIEGE 10](#piege-10--ports-monitoring-exposes--grafana-inaccessible-en-lan). Soit un tunnel SSH, soit ouvrir le port en LAN dans nftables.

### Checklist post-deploiement corrigee

Apres avoir rencontre tous ces problemes, voici l'ordre de deploiement recommande :

```bash
# 1. AVANT TOUT : adapter config.env
nano scripts/config.env
# - IFACE=enp2s0 (ou votre interface)
# - ADMIN_NETS : ajouter votre IP/sous-reseau

# 2. AVANT TOUT : adapter ADMIN_NETS dans nftables.conf
nano nftables/nftables.conf
# define ADMIN_NETS = { ..., 192.168.0.0/24, VOTRE_IP_PUBLIQUE/32 }

# 3. Installer les prerequis
sudo bash scripts/install.sh

# 4. Si CrowdSec selectionne : configurer le bouncer AVANT deploy
sudo cscli bouncers add crowdsec-firewall-bouncer -k "votre-cle-secrete"
sudo sed -i 's/^api_key:.*/api_key: votre-cle-secrete/' /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
sudo systemctl restart crowdsec-firewall-bouncer
sudo dpkg --configure -a

# 5. Supprimer le default NGINX si vous utilisez NGINX
sudo rm -f /etc/nginx/sites-enabled/default

# 6. Programmer un cron de securite (filet anti-lockout SSH)
echo "nft flush ruleset" | at now + 5 minutes

# 7. Deployer
sudo bash scripts/deploy.sh

# 8. Si SSH fonctionne toujours, annuler le cron
atrm $(atq | awk '{print $1}')

# 9. Valider
sudo bash scripts/validate.sh

# 10. Verifier le monitoring
curl -s http://127.0.0.1:9090/api/v1/targets | python3 -m json.tool | head -20
curl -s http://127.0.0.1:3000/api/health
```

---

## 21. Procedures d'urgence

### Attaque DDoS en cours

1. **Diagnostiquer** :
   ```bash
   sudo bash scripts/status.sh
   ```

2. **Identifier les IPs sources** :
   ```bash
   # Top IPs dans conntrack
   conntrack -L 2>/dev/null | grep -oP 'src=\K[0-9.]+' | sort | uniq -c | sort -rn | head 20

   # Top IPs dans les logs NGINX
   awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head 20

   # Taux de paquets par seconde
   watch -n1 'cat /proc/net/dev | grep eth0'
   ```

3. **Bloquer les IPs** :
   ```bash
   # Via nftables (rapide)
   sudo bash nftables/nft-manage.sh block 203.0.113.50 2h

   # Via XDP (tres rapide, si active)
   sudo bash xdp/xdp-manage.sh block-ip 203.0.113.50 2h
   ```

4. **Si surcharge massive** :
   ```bash
   # Mode urgence : drop TOUT sauf SSH
   sudo bash nftables/nft-manage.sh emergency-drop-all
   ```

5. **Si la bande passante FAI est saturee** :
   - Contacter votre hebergeur pour demander un blackholing ou un scrubbing center.
   - FluxGate ne peut rien faire si les paquets n'arrivent pas jusqu'au serveur.

### Perte d'acces SSH

1. Se connecter via la **console KVM/VNC** de l'hebergeur.
2. Flush les regles : `nft flush ruleset`.
3. Diagnostiquer pourquoi SSH est bloque (`nft list ruleset`, `fail2ban-client status sshd`).
4. Corriger et re-deployer.

### Rollback complet

```bash
sudo bash scripts/rollback.sh
# Puis reboot recommande
sudo reboot
```

### Service tue par OOM

Si un service est tue par `MemoryMax` :
```bash
# Voir les logs OOM
journalctl -u monservice --since "1 hour ago" | grep -i "oom\|kill\|memory"

# Augmenter la limite temporairement
systemctl set-property monservice MemoryMax=4G --runtime
systemctl restart monservice
```

---

## 22. Glossaire

| Terme | Definition |
|-------|-----------|
| **ACK** | Acknowledgment. Paquet TCP qui confirme la reception de donnees. |
| **Backlog** | File d'attente des connexions en attente d'etre acceptees par l'application. |
| **BCP 38** | Best Current Practice 38 (RFC 2827). Recommandation de filtrer les paquets avec des adresses source falsifiees a la peripherie du reseau. |
| **Bouncer** | Composant CrowdSec qui applique les decisions (ban/captcha) sur un service (firewall, NGINX, etc.). |
| **cgroups** | Control Groups. Mecanisme Linux pour limiter les ressources (CPU, RAM, I/O) d'un groupe de processus. |
| **Conntrack** | Connection Tracking. Module noyau qui suit l'etat de chaque connexion pour le filtrage stateful. |
| **CRS** | Core Rule Set. Ensemble de regles OWASP pour ModSecurity. |
| **ct state** | L'etat de suivi conntrack d'un paquet : new, established, related, invalid. |
| **DDoS** | Distributed Denial of Service. Attaque par deni de service distribuee depuis de nombreuses sources. |
| **eBPF** | Extended Berkeley Packet Filter. Technologie permettant d'executer du code sandboxe dans le noyau Linux. |
| **epoll** | Mecanisme Linux d'I/O evenementiel haute performance utilise par NGINX. |
| **FD** | File Descriptor. Reference numerique a un fichier, socket, pipe, etc. ouvert par un processus. |
| **Flush ruleset** | Commande nftables qui supprime toutes les regles de toutes les tables. |
| **Handshake TCP** | Echange en 3 temps (SYN, SYN/ACK, ACK) pour etablir une connexion TCP. |
| **inet** | Famille nftables qui combine IPv4 et IPv6 dans les memes regles. |
| **Jail** | Unite de configuration fail2ban : un filtre + une action + des parametres (maxretry, bantime). |
| **Keepalive** | Connexion persistante reutilisee pour plusieurs requetes HTTP. |
| **Leaky bucket** | Algorithme de rate limiting : les requetes s'accumulent dans un seau qui se vide a debit constant. |
| **Martien** | Paquet avec une adresse IP source invalide ou impossible (loopback sur une interface publique, etc.). |
| **Meter** | Compteur nftables par IP source, permettant un rate limiting individuel. |
| **NIC** | Network Interface Card. Carte reseau physique ou virtuelle. |
| **OOM** | Out of Memory. Le noyau tue un processus pour liberer de la memoire. |
| **PAWS** | Protection Against Wrapped Sequence numbers. Necessite TCP timestamps. |
| **pps** | Packets per second. Nombre de paquets par seconde (mesure de debit). |
| **rp_filter** | Reverse Path Filtering. Anti-spoofing : verifie que l'adresse source est routable via l'interface d'arrivee. |
| **SACK** | Selective Acknowledgment. Option TCP pour retransmettre uniquement les segments perdus. |
| **Set** | Structure de donnees nftables contenant des elements (IP, ports) avec lookup rapide O(1). |
| **sk_buff / SKB** | Structure noyau Linux representant un paquet reseau en memoire. |
| **Slowloris** | Attaque qui ouvre de nombreuses connexions HTTP et envoie les headers lentement pour epuiser les threads. |
| **SYN cookie** | Mecanisme anti-SYN-flood : le serveur encode les parametres TCP dans le numero de sequence sans creer d'etat. |
| **SYN flood** | Attaque qui envoie des millions de paquets SYN sans jamais completer le handshake TCP. |
| **TBF** | Token Bucket Filter. Algorithme de controle de debit utilise par tc. |
| **TIME_WAIT** | Etat TCP apres la fermeture d'une connexion. Dure 2*MSL (60-120 secondes). Empeche les vieux paquets de corrompre de nouvelles connexions. |
| **WAF** | Web Application Firewall. Filtre au niveau applicatif (HTTP). |
| **XDP** | eXpress Data Path. Framework Linux pour le traitement de paquets a ultra haute performance dans le driver NIC. |
| **XDP_DROP** | Verdict XDP : dropper le paquet immediatement dans le driver. |
| **XDP_PASS** | Verdict XDP : passer le paquet a la pile noyau normale. |

---

## 23. References

### Guides et standards
- ANSSI - Essentiels DDoS v2.0
- RFC 2827 (BCP 38) - Network Ingress Filtering (anti-spoofing)
- RFC 4987 - TCP SYN Flooding Attacks and Common Mitigations
- RFC 6585 - HTTP 429 Too Many Requests

### Documentation noyau
- IP sysctl : https://docs.kernel.org/networking/ip-sysctl.html
- nf_conntrack sysctl : https://docs.kernel.org/networking/nf_conntrack-sysctl.html

### Netfilter / nftables
- nftables manpage : https://www.netfilter.org/projects/nftables/manpage.html

### XDP / eBPF
- xdp-filter manpage : https://man.archlinux.org/man/extra/xdp-tools/xdp-filter.8.en
- bpftool manpage : https://man.archlinux.org/man/bpftool.8.en

### Serveurs web
- NGINX limit_req : https://nginx.org/en/docs/http/ngx_http_limit_req_module.html
- NGINX limit_conn : https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html
- Apache mod_reqtimeout : https://httpd.apache.org/docs/current/mod/mod_reqtimeout.html

### WAF
- ModSecurity v3 : https://github.com/owasp-modsecurity/ModSecurity
- OWASP CRS : https://owasp.org/www-project-modsecurity-core-rule-set/

### Detection / Reaction
- fail2ban : https://github.com/fail2ban/fail2ban
- CrowdSec : https://docs.crowdsec.net/

### Monitoring
- Prometheus : https://prometheus.io/
- Grafana : https://grafana.com/grafana/download?edition=oss
- Node Exporter : https://github.com/prometheus/node_exporter
