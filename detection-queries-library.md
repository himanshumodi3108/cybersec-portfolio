# Detection Queries Library
**Analyst:** Himanshu Kumar Modi
**Last Updated:** 2025-03-21
**Total Rules:** 10

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
| 6 | Trickbot URI pattern in HTTP POST | T1041 | Day 2 — Trickbot PCAP |
| 7 | Outbound HTTPS on non-standard port | T1571 | Day 2 — Trickbot PCAP |
| 8 | Impossible User-Agent combination (IE7 + Win10) | T1036 | Day 2 — Trickbot PCAP |
| 9 | Public IP lookup by internal host | T1016 | Day 2 — Trickbot PCAP |
| 10 | Large credential POST to external IP | T1555.003, T1041 | Day 2 — Trickbot PCAP |

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

## Rules from Day 2 — Trickbot Infostealer (2020-11-09)

---

### Rule 006 — Trickbot URI Pattern in HTTP POST
**Source:** Day 2 — Trickbot infection PCAP (2020-11-09)
**MITRE:** T1041
**What triggered it:** POST requests to /tar2/DESKTOP-CANDLES_[ID]/81/ and /83/ carrying plaintext credentials.

```spl
index=network http.request.method=POST http.uri="/tar2/*"
| rex field=http.uri "/tar2/(?<bot_id>[^/]+)/(?<module_id>\d+)/"
| stats count by src_ip, dest_ip, bot_id, module_id
```

**Logic:** Matches Trickbot-specific URI structure exactly. Module 81 = passwords, 83 = form data, 90 = additional data. Any match is high-confidence Trickbot — no false positives expected.

---

### Rule 007 — Outbound HTTPS on Non-Standard Port
**Source:** Day 2 — Trickbot infection PCAP (2020-11-09)
**MITRE:** T1571
**What triggered it:** 1,484 packets to 167.86.123.83 on port 447 — evading port-443-only firewall rules.

```spl
index=network dest_port=447 OR dest_port=449 OR dest_port=8082
| stats count by src_ip, dest_ip, dest_port
| where count > 10
| sort -count
```

**Logic:** Legitimate HTTPS is almost always port 443. Sustained traffic to 447, 449, or 8082 from an internal host = Trickbot C2 evasion. Tune port list as new Trickbot variants emerge.

---

### Rule 008 — Impossible User-Agent Combination
**Source:** Day 2 — Trickbot infection PCAP (2020-11-09)
**MITRE:** T1036
**What triggered it:** "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0)" — IE7 cannot run on Windows 10.

```spl
index=network http.user_agent="*MSIE 7.0*" http.user_agent="*Windows NT 10.0*"
| stats count by src_ip, dest_ip, http.user_agent
```

**Logic:** Zero false positives. IE7 on Windows 10 is a technical impossibility — any occurrence is definitively malware masquerading as a browser.

---

### Rule 009 — Public IP Lookup by Internal Host
**Source:** Day 2 — Trickbot infection PCAP (2020-11-09)
**MITRE:** T1016
**What triggered it:** GET icanhazip.com — Trickbot checking victim's public IP post-infection.

```spl
index=network http.request.method=GET
  (http.host="icanhazip.com" OR http.host="api.ipify.org"
   OR http.host="checkip.amazonaws.com" OR http.host="ifconfig.me")
| stats count by src_ip, http.host
| where count > 2
```

**Logic:** Malware routinely checks its public IP to confirm connectivity and geolocation. Repeated requests to IP-check services from one internal host — especially alongside other suspicious traffic — is a reliable lateral indicator.

---

### Rule 010 — Large Credential POST to External IP
**Source:** Day 2 — Trickbot infection PCAP (2020-11-09)
**MITRE:** T1555.003 + T1041
**What triggered it:** 573-byte POST body containing plaintext Chrome passwords and PII sent to 51.81.112.135.

```spl
index=network http.request.method=POST
| eval dest_internal=if(match(dest_ip,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))"),1,0)
| where dest_internal=0
| eval body_size=coalesce(http.content_length,0)
| where body_size > 200
| stats count, max(body_size) as max_body by src_ip, dest_ip, http.uri
| sort -max_body
```

**Logic:** Flags large HTTP POST bodies to external IPs. Credential exfiltration posts are typically 200–2000 bytes. Combine with URI pattern matching (Rule 006) for maximum confidence.

---