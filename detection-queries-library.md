# Detection Queries Library
**Analyst:** [Your Name]
**Last Updated:** 2025-03-20
**Total Rules:** 5

This file is updated after every lab session. Each rule includes the attack context, MITRE technique, SPL query, and the logic behind it.

---

## Index

| # | Rule Name | MITRE | Source Lab |
|---|---|---|---|
| 1 | TLS connection to suspicious SNI | T1071.003, T1573.001 | Day 1 — Ursnif PCAP |
| 2 | C2 beaconing via regular TLS intervals | T1071.003 | Day 1 — Ursnif PCAP |
| 3 | Media file extension used for payload delivery | T1105, T1027 | Day 1 — Ursnif PCAP |
| 4 | Multiple file downloads from single external IP | T1105 | Day 1 — Ursnif PCAP |
| 5 | Suspicious archive download by name pattern | T1027 | Day 1 — Ursnif PCAP |

---

## Rules

---

### Rule 001 — TLS Connection to Suspicious SNI
**Source:** Day 1 — Ursnif/Gozi infection PCAP (2020-02-24)
**MITRE:** T1071.003 · T1573.001
**What triggered it:** Victim 10.2.24.101 made TLS Client Hello to `fatturapagamentodi.pw`, `asistenzaonline.xyz`, `pizdelko.xyz` — all unknown domains, none legitimate.

```spl
index=network ssl.handshake.type=1
| stats count by src_ip, ssl.handshake.extensions_server_name
| where NOT ssl.handshake.extensions_server_name LIKE "%.google.com"
  AND NOT ssl.handshake.extensions_server_name LIKE "%.microsoft.com"
  AND NOT ssl.handshake.extensions_server_name LIKE "%.cloudflare.com"
  AND NOT ssl.handshake.extensions_server_name LIKE "%.amazonaws.com"
| sort -count
```

**Logic:** Surfaces all TLS Client Hello packets where the SNI does not match known-good providers. Analyst reviews flagged SNIs against threat intel feeds. Tune the exclusion list to your environment.

---

### Rule 002 — C2 Beaconing via Regular TLS Intervals
**Source:** Day 1 — Ursnif/Gozi infection PCAP (2020-02-24)
**MITRE:** T1071.003
**What triggered it:** Repeated TLS handshakes to 68.168.123.78 every ~5–10 minutes across Packets 1215–2167. Low variance = machine behavior, not human.

```spl
index=network ssl.handshake.type=1
| bucket _time span=10m
| stats count by src_ip, dest_ip, _time
| where count >= 2
| streamstats window=6 current=t stdev(count) as regularity by src_ip, dest_ip
| where regularity < 1.5
| table src_ip, dest_ip, count, regularity
```

**Logic:** Low standard deviation in connection count over rolling 6-window = machine-like regularity = beaconing. Threshold of 1.5 is tunable. Human browsing is irregular; malware is a clock.

---

### Rule 003 — Media File Extension Used for Payload Delivery
**Source:** Day 1 — Ursnif/Gozi infection PCAP (2020-02-24)
**MITRE:** T1105 · T1027
**What triggered it:** HTTP GETs to 46.102.153.16 for multiple `.avi` files — confirmed DLL segments, not real media. 906 packets total.

```spl
index=network http.request.method=GET
| rex field=uri "(?<ext>\.[a-z0-9]{2,4})$"
| where ext IN (".avi", ".mp4", ".mp3", ".jpg", ".png")
| eval dest_is_cdn=if(match(dest_ip,"^(151\.101|104\.16|172\.67)"),1,0)
| where dest_is_cdn=0
| stats count by src_ip, dest_ip, uri, ext
| where count > 3
```

**Logic:** Flags repeated GET requests for media-extension files from non-CDN IPs. Legitimate media comes from CDNs. Repeated media GETs from a raw IP = strong Ursnif payload staging indicator.

---

### Rule 004 — Multiple File Downloads from Single External IP
**Source:** Day 1 — Ursnif/Gozi infection PCAP (2020-02-24)
**MITRE:** T1105
**What triggered it:** 46.102.153.16 served 906 packets of chunked payload to victim. Single external IP, many distinct URIs, non-CDN.

```spl
index=network http.request.method=GET
| stats dc(uri) as unique_files, count as total_requests by src_ip, dest_ip
| where unique_files > 3
| eval internal=if(match(dest_ip,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))"),1,0)
| where internal=0
| sort -total_requests
```

**Logic:** An internal host downloading many distinct files from a single external IP is a high-confidence payload staging indicator. Legitimate software updates use CDNs, not raw IPs.

---

### Rule 005 — Suspicious Archive Download by Name Pattern
**Source:** Day 1 — Ursnif/Gozi infection PCAP (2020-02-24)
**MITRE:** T1027
**What triggered it:** HTTP GET `/grabb32.rar` and `/grabb64.rar` from 37.10.71.149 — Packets 1299, 1563. Naming convention is a known Ursnif indicator.

```spl
index=network http.request.method=GET
  (uri="*.rar" OR uri="*.zip" OR uri="*.cab")
| where NOT dest_ip LIKE "192.168.%" AND NOT dest_ip LIKE "10.%"
| stats count by src_ip, dest_ip, uri
| eval suspicious_name=if(match(uri,"(grabb|load|drop|payload|stage|inject)"),1,0)
| where suspicious_name=1 OR count > 2
```

**Logic:** Catches archive downloads from external IPs with suspicious naming conventions. Pattern list (`grabb`, `drop`, `stage`, `inject`) is expandable as new malware families are encountered.

---
