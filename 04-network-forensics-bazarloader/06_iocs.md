# IOC Table — BazarLoader via TA551 (2021-09-10)
**Source:** malware-traffic-analysis.net/2021/09/10
**Analyst:** Himanshu Kumar Modi | **Date:** 2026-03-25

---

## Network IOCs

| Type | Value | Confidence | Description |
|---|---|---|---|
| IP | 194.62.42.206 | High | BazarLoader DLL delivery — HTTP port 80 |
| Domain | simpsonsavingss.com | High | TA551 payload hosting — active campaign |
| URL | http://simpsonsavingss.com/bmdff/BhoHsCtZ/MLdmpfjaX/5uFG3Dz7yt/date1?BNLv65=pAAS | High | Full DLL download URL |
| IP | 167.172.37.9 | High | BazarLoader C2 — HTTPS port 443 |
| IP | 94.158.245.52 | High | BazarLoader C2 — HTTPS port 443 |
| URI pattern | /bmdff/ | High | TA551 campaign signature — hunt historically |

## Host IOCs

| Type | Value | Confidence | Description |
|---|---|---|---|
| SHA256 | eed363fc4af7a9070d69340592dcab7c78db4f90710357de29e3b624aa957cf8 | High | BazarLoader DLL |
| File size | 284,816 bytes | High | 64-bit Windows DLL |
| Hostname | DESKTOP-KKITB6Q | High | Infected host |
| User | hobart.gunnarsson | High | Victim account |
| IP | 10.9.10.102 | High | Victim internal IP |
| MAC | 00:4f:49:b1:e8:c3 | High | Victim NIC |

## Quick Block List

```
# Firewall — block IPs
194.62.42.206
167.172.37.9
94.158.245.52

# DNS sinkhole
simpsonsavingss.com

# Proxy / SIEM hunt — URI pattern
/bmdff/
date1?
date2?
```