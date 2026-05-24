# BRCloud FluxGate - Architecture Anti-DDoS

## Diagramme de flux (defense en profondeur)

```mermaid
flowchart TB
  Internet((Internet)) --> NIC[NIC / Driver RX]

  NIC -->|optionnel| XDP[XDP/eBPF - xdp-filter]
  XDP --> NetStack[Linux network stack]
  NIC --> NetStack

  NetStack --> NF[nftables L3/L4]
  NF --> SOCK[systemd.socket limites]
  SOCK --> RP[Reverse proxy - NGINX ou Apache]
  RP --> WAF[WAF - ModSecurity/CRS]
  WAF --> APP[Application]
  APP --> DATA[(Stockage/DB)]

  subgraph ControlPlane[Controle et Reaction]
    F2B[fail2ban] --> NF
    CS[CrowdSec + bouncer firewall] --> NF
    SYS[sysctl / kernel tuning + conntrack] --> NetStack
    CG[cgroups / systemd resource control] --> APP
  end

  subgraph Observability[Supervision locale]
    M1[ss / nstat / conntrack / iptraf-ng] --> NetStack
    M2[bpftool / bpftrace / xdp-tools] --> XDP
    PROM[Prometheus + node_exporter] --> GRAF[Grafana dashboards]
  end
```

## Sequence de traitement d'un paquet

```mermaid
sequenceDiagram
  participant P as Paquet entrant
  participant D as Driver/NIC RX
  participant X as XDP (optionnel)
  participant K as Pile noyau
  participant F as nftables
  participant S as Socket/systemd
  participant R as Reverse proxy
  participant A as Application

  P->>D: Arrivee sur interface
  alt XDP active
    D->>X: Executer programme XDP
    alt Match regle drop
      X-->>D: XDP_DROP (tres tot)
    else PASS
      X->>K: XDP_PASS vers pile noyau
    end
  else XDP absent
    D->>K: Paquet vers pile noyau
  end

  K->>F: Hook netfilter
  alt Filtre (set/rate limit/invalid)
    F-->>K: DROP
  else Autorise
    F->>S: Livraison socket
    S->>R: Accept + limites connexions
    R->>A: Proxy / traitement
    alt Surcharge
      A-->>R: Refus rapide / 429 / 503
    else OK
      A-->>R: Reponse normale
    end
  end
```

## Matrice des couches de protection

| Couche | Technologie | Vecteurs couverts | Fichier config |
|--------|-------------|-------------------|----------------|
| L2/L3 (driver) | XDP/eBPF | Volumetrique (pps), IP blocklist | `xdp/xdp-manage.sh` |
| L3/L4 (noyau) | nftables + sets | SYN flood, rate limit, invalid | `nftables/nftables.conf` |
| L4 (noyau) | sysctl tuning | SYN cookies, backlog, conntrack | `sysctl/99-fluxgate-hardening.conf` |
| L4 (systemd) | socket limits | Connexions/IP, backlog | `systemd/fluxgate-app.socket` |
| L7 (proxy) | NGINX/Apache | HTTP flood, slow requests, 429 | `nginx/nginx-fluxgate.conf` |
| L7 (WAF) | ModSecurity+CRS | Injections, abus applicatifs | `waf/modsecurity/modsecurity.conf` |
| Reactif | fail2ban/CrowdSec | Brute force, scans, abus repetes | `fail2ban/`, `crowdsec/` |
| Ressources | systemd cgroups | Epuisement CPU/RAM/FD | `systemd/resource-limits.conf` |
| Sortant | tc/tbf | Amplification sortante | `tc/tc-shape.sh` |

## Limites structurelles

1. **Saturation upstream** : si la bande passante FAI/hebergeur est saturee,
   le serveur ne voit pas tout le trafic. Solution : contacter l'operateur
   (blackholing, scrubbing center, service anti-DDoS cloud).

2. **DDoS massivement distribue** : des milliers d'IP changeantes rendent le
   filtrage IP moins efficace. BCP 38 (anti-spoofing) est hors controle local.

3. **Attaques L7 indiscernables** : requetes valides mais couteuses necessitent
   du backpressure applicatif, du caching, et potentiellement un WAF avec
   regles metier.

## Checklist de deploiement

1. Inventorier l'exposition reseau (`ss -lntu`)
2. Mesurer un baseline (trafic, connexions, latences, conntrack)
3. Fixer des SLO degrades (quels endpoints survivent, comportement 429/503)
4. Activer SYN cookies + backlog (`sysctl`)
5. Deployer nftables (default deny, sets, rate limit, drop UDP inutile)
6. Tuner conntrack (monitoring, timeouts, mode degrade)
7. Deployer reverse proxy (limit_req, limit_conn, timeouts)
8. Durcir contre slow requests (mod_reqtimeout / timeouts NGINX)
9. Ajouter fail2ban / CrowdSec
10. Confiner les ressources (systemd cgroups)
11. Activer XDP si besoin haute performance
12. Deployer monitoring (Prometheus + Grafana)
13. Tests reguliers et exercices de procedure
