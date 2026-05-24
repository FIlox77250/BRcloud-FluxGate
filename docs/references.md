# BRCloud FluxGate - References

## Guides et standards

- ANSSI - Essentiels DDoS v2.0 (04/24)
  https://messervices.cyber.gouv.fr/documents-guides/anssi_essentiels_denis-de-service-distribues_v2.0.pdf

- ANSSI - Comprendre et anticiper les attaques DDoS
  https://www.cybermalveillance.gouv.fr/medias/2019/11/NP_Guide_DDoS.pdf

- RFC 2827 (BCP 38) - Network Ingress Filtering (anti-spoofing)
  https://www.rfc-editor.org/rfc/rfc2827.html

- RFC 4987 - TCP SYN Flooding Attacks and Common Mitigations
  https://datatracker.ietf.org/doc/html/rfc4987

- RFC 6585 - HTTP 429 Too Many Requests
  https://datatracker.ietf.org/doc/html/rfc6585

## Documentation noyau Linux

- IP sysctl (tcp_syncookies, tcp_max_syn_backlog, somaxconn)
  https://docs.kernel.org/networking/ip-sysctl.html

- nf_conntrack sysctl
  https://docs.kernel.org/networking/nf_conntrack-sysctl.html

## Netfilter / nftables / iptables

- nftables manpage (synproxy statement)
  https://www.netfilter.org/projects/nftables/manpage.html

- iptables-extensions (connlimit, hashlimit, SYNPROXY)
  https://man7.org/linux/man-pages/man8/iptables-extensions.8.html

## XDP / eBPF

- xdp-filter manpage
  https://man.archlinux.org/man/extra/xdp-tools/xdp-filter.8.en

- bpftool manpage
  https://man.archlinux.org/man/bpftool.8.en

- tc-bpf manpage
  https://man7.org/linux/man-pages/man8/tc-bpf.8.html

## Serveurs web / Reverse proxy

- NGINX limit_req module
  https://nginx.org/en/docs/http/ngx_http_limit_req_module.html

- NGINX limit_conn module
  https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html

- Apache mod_reqtimeout
  https://httpd.apache.org/docs/current/mod/mod_reqtimeout.html

- Apache event MPM
  https://httpd.apache.org/docs/current/mod/event.html

## WAF

- ModSecurity (v3)
  https://modsecurity.org/
  https://github.com/owasp-modsecurity/ModSecurity

- ModSecurity-nginx connector
  https://github.com/owasp-modsecurity/ModSecurity-nginx

- OWASP Core Rule Set (CRS)
  https://owasp.org/www-project-modsecurity-core-rule-set/

## Detection / Reaction

- fail2ban
  https://manpages.debian.org/testing/fail2ban/fail2ban-client.1.en.html
  https://github.com/fail2ban/fail2ban/releases

- CrowdSec firewall bouncer
  https://docs.crowdsec.net/u/bouncers/firewall
  https://github.com/crowdsecurity/crowdsec/releases

## Monitoring

- Prometheus
  https://prometheus.io/download/

- Node Exporter
  https://github.com/prometheus/node_exporter/releases

- Grafana OSS
  https://grafana.com/grafana/download?edition=oss
