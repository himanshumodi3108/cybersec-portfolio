# IOC Table — Ursnif Infection (2020-02-24)
**Source PCAP:** malware-traffic-analysis.net/2020/02/24
**Analyst:** [Your Name] | **Date:** 2025-03-20

---

## Network IOCs

| Type | Value | Confidence | Description | Context |
|---|---|---|---|---|
| IP | 68.168.123.78 | High | C2 Server | Primary C2 — persistent TLS beaconing to asistenzaonline.xyz — Packets 1215, 1230, 1247, 1271, 1284, 1933–2167 |
| IP | 217.138.205.170 | High | Initial Payload Server | First TLS contact post-macro execution — SNI: fatturapagamentodi.pw — Packet 10 |
| IP | 46.102.153.16 | High | Payload Server | HTTP GET .avi files (chunked DLL segments) — 906 packets, Packets 218–1116 |
| IP | 37.10.71.149 | High | Payload Server | HTTP GET /grabb32.rar + /grabb64.rar — Packets 1299, 1563 |
| Domain | asistenzaonline.xyz | High | C2 Domain | Persistent beaconing — resolves to 68.168.123.78 |
| Domain | fatturapagamentodi.pw | High | Initial Connection | First TLS Client Hello SNI — Packet 10 — resolves to 217.138.205.170 |
| Domain | pizdelko.xyz | Medium | Suspicious Domain | Single TLS Client Hello — Packet 1159 — possible fallback C2 |

## File IOCs

| Type | Value | Confidence | Description | Context |
|---|---|---|---|---|
| File extension | .avi | High | Obfuscated Payload | Ursnif DLL segments disguised as media files — bypasses content-type filtering |
| File | grabb32.rar | High | Malware Payload | 32-bit Ursnif DLL archive — HTTP GET from 37.10.71.149 — Packet 1299 |
| File | grabb64.rar | High | Malware Payload | 64-bit Ursnif DLL archive — HTTP GET from 37.10.71.149 — Packet 1563 |

---

## Quick Block List

```
# Block at perimeter firewall — IPs
68.168.123.78
217.138.205.170
46.102.153.16
37.10.71.149

# Block at DNS sinkholes — Domains
asistenzaonline.xyz
fatturapagamentodi.pw
pizdelko.xyz

# Flag at proxy / content filter — File patterns
*.avi downloads from non-CDN external IPs
*grabb*.rar
*grabb*.zip
```

---

## Victim Host

| Field | Value |
|---|---|
| IP | 10.2.24.101 |
| MAC | 00:08:02:1c:47:ae |
| Role | Compromised endpoint |

---

*Part of Project 01 — Network Forensics Investigation*
*Full report → report.md | Detection rules → detection-queries.md*
