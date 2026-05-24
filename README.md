# 🛡️ BRCloud FluxGate

> Stack anti-DDoS multi-couche pour serveur Linux single-host.
> Filtrage en profondeur, du pilote réseau (XDP/eBPF) jusqu'aux limites de ressources applicatives.

---

## Architecture

```
Paquet entrant
      │
      ├─ [1] XDP / eBPF          DROP ultra-rapide (dizaines de Mpps)
      ├─ [2] Kernel Tuning       SYN cookies, backlogs, conntrack
      ├─ [3] nftables L3/L4      Sets dynamiques, rate limit SYN, SYNPROXY
      ├─ [4] systemd socket      Connexions max par IP source (noyau)
      ├─ [5] Nginx / Apache      Leaky bucket, anti-slowloris, 429
      ├─ [6] WAF ModSecurity     OWASP CRS — filtrage SQLi & XSS
      └─ [7] Application         Isolation cgroups (CPU, RAM max)
```

---

## Pré-requis

| Élément       | Requis                                                        |
|---------------|---------------------------------------------------------------|
| **OS**        | Debian / Ubuntu (`apt`) ou RHEL / Fedora / CentOS (`dnf`)     |
| **Kernel**    | `>= 4.4` (idéalement `>= 5.x` pour XDP natif)                 |
| **Accès**     | `root` complet (`sudo`)                                       |
| **Réseau**    | Carte compatible XDP (fallback auto en mode générique `skb`)  |

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
```

> ⚠️ **À adapter impérativement :**
> - `IFACE` — interface réseau publique (ex : `eth0`, `ens3`, `enp1s0`)
> - `SSH_PORT` — port SSH actuel (critique pour éviter le lockout)

### 3. Installer les dépendances

```bash
sudo bash scripts/install.sh
```

Détecte l'OS, répare le gestionnaire de paquets si besoin, et propose un menu interactif (serveur web + modules de monitoring). Option *Premium* : installe `figlet`, `gum` et `glow` via les dépôts Charm.sh.

### 4. Déployer

```bash
sudo bash scripts/deploy.sh
```

> 🔒 **Anti-lockout SSH** — le script détecte l'IP de ta session active et propose de l'injecter à chaud dans `ADMIN_NETS` si elle n'est pas whitelistée. Un rollback automatique de 5 min (`at`) réinitialise le pare-feu si la connexion coupe.

### 5. Valider

```bash
sudo bash scripts/validate.sh
```

Diagnostic complet : sysctl, nftables, socket systemd, état des ports, seuils conntrack.

---

## Exploitation

### Tableau de bord temps réel

```bash
sudo bash scripts/status.sh -w        # mode watch
sudo bash scripts/status.sh -w -n 1   # rafraîchissement 1s
```

### Gestion à chaud du pare-feu

```bash
# Bloquer une IP 2 heures
sudo bash nftables/nft-manage.sh block 203.0.113.50 2h

# Débloquer
sudo bash nftables/nft-manage.sh unblock 203.0.113.50

# Mode urgence : tout bloquer sauf SSH admin
sudo bash nftables/nft-manage.sh emergency-drop-all
```

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

## Rollback complet

```bash
sudo bash scripts/rollback.sh
sudo reboot
```

Supprime toutes les configs (sysctl, nginx, apache, fail2ban), détache XDP, libère nftables.

---

## Structure

```
BRcloud-FluxGate/
├── scripts/
│   ├── install.sh        # Prérequis + outils de design
│   ├── deploy.sh         # Déploiement + anti-lockout SSH
│   ├── validate.sh       # Validation de chaque couche
│   ├── rollback.sh       # Restauration de l'état d'origine
│   ├── status.sh         # Dashboard temps réel (-w)
│   ├── progress_bar.sh   # Barre de chargement native
│   └── config.env        # Configuration centralisée
├── nftables/
│   ├── nftables.conf     # Règles dual-stack IPv4/IPv6
│   └── nft-manage.sh     # block / unblock / urgence
├── xdp/
│   ├── xdp-manage.sh     # Gestion filtres eBPF
│   └── xdp-auto-block.sh # Auto-ban via conntrack
├── nginx/
│   ├── nginx-global.conf
│   └── nginx-fluxgate.conf
└── sysctl/
    └── 99-fluxgate-hardening.conf
```

---

## Licence & références

- **ANSSI** — inspiré du Guide des Essentiels DDoS v2.0
- **Licence** — MIT (open-source, réutilisable en production)