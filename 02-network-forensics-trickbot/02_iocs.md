# IOC Table — Trickbot Infostealer (2020-11-09)
**Source PCAP:** malware-traffic-analysis.net/2020/11/09
**Analyst:** Himanshu Kumar Modi | **Date:** 2025-03-21

---

## Network IOCs

| Type | Value | Confidence | Description |
|---|---|---|---|
| IP | 66.85.183.5 | High | Primary C2 — HTTPS port 443 — 462 packets |
| IP | 167.86.123.83 | High | Secondary C2 — HTTPS port 447 — 1484 packets — non-standard port |
| IP | 51.81.112.135 | High | Exfiltration server — HTTP POST /tar2/ — credentials + PII |
| IP | 156.96.128.237 | High | Additional exfiltration — POST /tar2/.../90/ |
| Domain | icanhazip.com | Medium | Public IP check — legitimate site abused by Trickbot |
| URI | /tar2/[BOTID]/81/ | High | Chrome password exfiltration module |
| URI | /tar2/[BOTID]/83/ | High | Form data + billing info module |
| URI | /tar2/[BOTID]/90/ | High | Additional data module |
| Port | 447 outbound | High | Non-standard C2 port — Trickbot evasion |
| User-Agent | Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0...) | High | Spoofed IE7 — impossible on Windows 10 |

## Host IOCs

| Type | Value | Confidence | Description |
|---|---|---|---|
| Hostname | DESKTOP-CANDLES | High | Compromised machine |
| IP | 10.11.9.102 | High | Victim internal IP |
| MAC | 00:08:02:1c:47:ae | High | Victim NIC |
| OS | Windows 10 build 19042 | High | From User-Agent and bot ID |
| Bot ID | DESKTOP-CANDLES_W10019042.1C550D7482EBE49086FC1A7D2100C9E5 | High | Trickbot unique machine fingerprint |

## Compromised Accounts

| Service | Account | Data Exposed |
|---|---|---|
| Google | xavier.f.candles1@gmail.com | Password confirmed |
| Google | xavier.f.candles2@gmail.com | Password confirmed |
| Google | xavier.francis.candles@gmail.com | Password confirmed |
| Facebook | xavier.francis.candles@gmail.com | Password confirmed |
| Yahoo | xavier.f.candles.1982@yahoo.com | Email + PII confirmed |

## Quick Block List

```
# Block at perimeter firewall — IPs
66.85.183.5
167.86.123.83
51.81.112.135
156.96.128.237

# Block outbound port
447/tcp outbound (Trickbot non-standard C2 port)

# Block at DNS
icanhazip.com (if policy allows — frequently abused by malware)

# Hunt in proxy logs — URI pattern
/tar2/
```
