# 🛡️ BRCloud FluxGate - Single-Host Anti-DDoS Protection Stack

**FluxGate** est une stack de protection anti-DDoS open-source et multi-couche conçue pour blinder un serveur Linux unique (Single-Host). Elle met en œuvre le principe fondamental de **défense en profondeur**, filtrant les paquets suspects au niveau le plus bas possible (pilote de carte réseau) jusqu'aux limites de ressources applicatives du système.

```
                  Paquet entrant
                        |
                        v
     [Couche 1]    [XDP/eBPF] ---------> DROP ultra-rapide (dizaines de Mpps)
                        |
     [Couche 2]    [Kernel Tuning] ----> SYN cookies, backlogs, conntrack tuning
                        |
     [Couche 3]    [nftables L3/L4] ----> Sets dynamiques, rate limiting SYN, SYNPROXY
                        |
     [Couche 4]    [systemd socket] ----> Connexions max par IP source au niveau noyau
                        |
     [Couche 5]    [NGINX / Apache] ----> Leaky bucket rate limits, anti-slowloris, 429
                        |
     [Couche 6]    [WAF ModSecurity] ---> OWL / OWASP CRS SQLi & XSS WAF filtering
                        |
     [Couche 7]    [Application] -------> Isolation par cgroups (CPU, RAM max)
```

---

## 🎨 Glamour Upgrade - Une interface moderne

Cette stack intègre une interface CLI haut de gamme avec **dégradation élégante** (les outils s'adaptent si les dépendances graphiques ne sont pas installées) :
*   **Barre de progression native** : Une barre dynamique pure Bash (`progress_bar.sh`) anime en temps réel l'avancement pas-à-pas de l'installation et du déploiement.
*   **Menus interactifs (Gum)** : Choix de composants à cocher au clavier/souris d'une grande fluidité.
*   **Logo ASCII géant (Figlet)** : Un affichage de démarrage stylisé.
*   **Supervision temps réel (`status.sh -w`)** : Un tableau de bord dynamique et coloré pour monitorer en direct l'activité réseau, les drops nftables et la table conntrack sous attaque.

---

## 📂 Structure du Projet

```
BRCloud FluxGate/
├── scripts/
│   ├── install.sh          # Installe tous les prérequis et outils de design
│   ├── deploy.sh           # Déploie la stack avec sécurité anti-lockout SSH
│   ├── validate.sh         # Valide l'état de chaque couche système
│   ├── rollback.sh         # Restaure l'état d'origine du serveur
│   ├── status.sh           # Tableau de bord dynamique temps réel (status.sh -w)
│   ├── progress_bar.sh     # Utilitaire de barre de chargement native
│   └── config.env          # Configuration centralisée de la stack
├── nftables/
│   ├── nftables.conf       # Règles pare-feu dual-stack (IPv4/IPv6)
│   └── nft-manage.sh       # Utilitaire (block, unblock, mode urgence)
├── xdp/
│   ├── xdp-manage.sh       # Gestion des filtres eBPF (load, unload)
│   └── xdp-auto-block.sh   # Démon d'auto-ban IPv4/IPv6 via conntrack
├── nginx/
│   ├── nginx-global.conf   # Config de base Nginx
│   └── nginx-fluxgate.conf # Limites L7 et intégration CDN / real_ip
├── sysctl/
│   └── 99-fluxgate-hardening.conf  # Hardening noyau (Anti-SYN, Rogue RA)
└── ...
```

---

## ⚙️ Pré-requis

*   **OS** : Debian / Ubuntu (famille `apt`) ou RHEL / Fedora / CentOS (famille `dnf`/`yum`).
*   **Kernel** : `>= 4.4` (idéalement `>= 5.x` ou supérieur pour XDP en mode natif).
*   **Accès** : Privilèges `root` complets (`sudo`).
*   **Carte réseau** : Compatible XDP (le script rétrograde automatiquement en mode générique `skb` si non supporté).

---

## 🚀 Guide de Déploiement Étape par Étape

### Étape 1 : Préparation & Configuration

Clonez ou téléchargez le projet sur votre serveur, accédez à la racine du répertoire et créez votre fichier de configuration global :

```bash
# 1. Copier le fichier d'exemple
cp scripts/config.env.example scripts/config.env

# 2. Configurer les variables clés
nano scripts/config.env
```
> [!IMPORTANT]
> Veillez à adapter les variables suivantes dans `scripts/config.env` :
> *   `IFACE` : Renseignez le nom exact de votre interface réseau publique (ex: `eth0`, `ens3`, `enp1s0`).
> *   `SSH_PORT` : Spécifiez le port d'écoute SSH actuel de votre serveur (très important pour éviter tout lockout).

---

### Étape 2 : Installation des Dépendances (`install.sh`)

Lancez le script d'installation pour préparer la machine et télécharger les packages nécessaires :

```bash
sudo bash scripts/install.sh
```

*   Le script détecte automatiquement votre OS et répare l'installateur de paquets en cas de dysfonctionnement.
*   **Interface Premium** : Si vous choisissez d'installer les *Outils graphiques Premium*, le script configure les dépôts officiels Charm.sh pour installer dynamiquement `figlet`, `gum` et `glow`.
*   Un menu interactif à cocher (si `gum` est installé) s'affiche pour choisir votre serveur web (Nginx/Apache) et vos modules de monitoring.

---

### Étape 3 : Déploiement Sécurisé (`deploy.sh`)

Appliquez l'ensemble de la stack anti-DDoS et durcissez votre système :

```bash
sudo bash scripts/deploy.sh
```

> [!TIP]
> **Sécurité Anti-Lockout SSH Active**
> Lors de l'application de nftables, le script `deploy.sh` intercepte automatiquement l'IP active de votre session d'administration SSH. Si cette IP n'est pas whitelistée dans `ADMIN_NETS` dans `nftables.conf`, **le script propose de l'injecter dynamiquement à chaud** pour vous éviter une coupure définitive de session.

Le script applique également un rollback automatique temporaire de 5 minutes avec l'utilitaire `at` ; si la connexion coupe malgré tout, le pare-feu se réinitialise de lui-même pour vous redonner l'accès.

---

### Étape 4 : Validation du Système (`validate.sh`)

Vérifiez que chaque brique logicielle et noyau fonctionne parfaitement :

```bash
sudo bash scripts/validate.sh
```
Ce script effectue un diagnostic complet de vos paramètres sysctl, du pare-feu nftables, du socket systemd, de l'état des ports et des seuils d'occupation conntrack.

---

## 📈 Exploitation & Monitoring temps réel

### Tableau de bord dynamique
Vous pouvez suivre en direct l'évolution de la charge de votre serveur et des paquets bloqués par le pare-feu en lançant le dashboard en mode interactif :

```bash
sudo bash scripts/status.sh --watch
# ou simplement
sudo bash scripts/status.sh -w -n 1
```
*(Le paramètre `-n` règle la vitesse de rafraîchissement en secondes)*

### Gestion à chaud de nftables
Utilisez l'utilitaire de gestion rapide du pare-feu :
```bash
# Bloquer une IP manuellement pour 2 heures
sudo bash nftables/nft-manage.sh block 203.0.113.50 2h

# Débloquer une IP
sudo bash nftables/nft-manage.sh unblock 203.0.113.50

# Mode URGENCE absolue (Bloquer TOUT le trafic entrant sauf le SSH d'administration)
sudo bash nftables/nft-manage.sh emergency-drop-all
```

---

## ⚠️ Cas Particulier : Utilisation derrière un CDN (Cloudflare...)

Si votre site web est positionné derrière Cloudflare ou un autre proxy inverse, le rate-limiting applicatif L7 va cibler les IP du CDN et bloquer tous les visiteurs d'un coup.

**Solution** : 
1.  Whitelister les plages IP de votre CDN dans votre pare-feu nftables.
2.  Accéder au fichier `nginx/nginx-fluxgate.conf` et décommenter la section **OPTION CDN** en spécifiant le header d'IP réelle et les adresses autorisées :
    ```nginx
    set_real_ip_from 103.21.244.0/22;
    real_ip_header CF-Connecting-IP;
    real_ip_recursive on;
    ```

---

## ↩️ Rollback Complet

En cas de problème majeur, vous pouvez restaurer l'état initial complet de votre serveur en exécutant le script de retour arrière :

```bash
sudo bash scripts/rollback.sh
sudo reboot
```
Ce script supprime l'intégralité des configurations sysctl, nginx, apache, fail2ban, détache XDP et libère le pare-feu nftables.

---

## 📝 Licence & Références
*   **ANSSI** : Inspiré par le Guide des Essentiels DDoS v2.0.
*   **Licence** : Open-Source (MIT). Réutilisable en toute sécurité pour vos serveurs de production.