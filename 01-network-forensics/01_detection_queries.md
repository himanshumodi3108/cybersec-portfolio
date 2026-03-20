# Detection Queries — Ursnif C2 & Payload Delivery
**Case:** 2020-02-24 Ursnif Infection
**Analyst:** Himanshu Kumar Modi | **Date:** 2025-03-20
**Added to master library:** detection-queries-library.md

---

## Query 1 — TLS to suspicious SNI
**Attack:** C2 over TLS to unknown domain
**MITRE:** T1071.003 + T1573.001
```spl
index=network ssl.handshake.type=1
| stats count by src_ip, ssl.handshake.extensions_server_name
| where NOT ssl.handshake.extensions_server_name LIKE "%.google.com"
  AND NOT ssl.handshake.extensions_server_name LIKE "%.microsoft.com"
  AND NOT ssl.handshake.extensions_server_name LIKE "%.cloudflare.com"
| sort -count
```

---

## Query 2 — C2 beaconing regularity
**Attack:** Regular TLS handshakes to C2 (~5–10 min intervals)
**MITRE:** T1071.003
```spl
index=network ssl.handshake.type=1
| bucket _time span=10m
| stats count by src_ip, dest_ip, _time
| where count >= 2
| streamstats window=6 current=t stdev(count) as regularity by src_ip, dest_ip
| where regularity < 1.5
```

---

## Query 3 — Media extension used for payload
**Attack:** DLL disguised as .avi file
**MITRE:** T1105 + T1027
```spl
index=network http.request.method=GET
| rex field=uri "(?<ext>\.[a-z0-9]{2,4})$"
| where ext IN (".avi",".mp4",".mp3",".jpg",".png")
| eval dest_is_cdn=if(match(dest_ip,"^(151\.101|104\.16|172\.67)"),1,0)
| where dest_is_cdn=0
| stats count by src_ip, dest_ip, uri, ext
| where count > 3
```

---

## Query 4 — Multiple file downloads from single external IP
**Attack:** Chunked payload download (906 packets to 46.102.153.16)
**MITRE:** T1105
```spl
index=network http.request.method=GET
| stats dc(uri) as unique_files, count as total_requests by src_ip, dest_ip
| where unique_files > 3
| eval internal=if(match(dest_ip,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))"),1,0)
| where internal=0
| sort -total_requests
```

---

## Query 5 — Suspicious archive download by name pattern
**Attack:** grabb32.rar / grabb64.rar retrieval
**MITRE:** T1027
```spl
index=network http.request.method=GET
  (uri="*.rar" OR uri="*.zip" OR uri="*.cab")
| where NOT dest_ip LIKE "192.168.%" AND NOT dest_ip LIKE "10.%"
| eval suspicious_name=if(match(uri,"(grabb|load|drop|payload|stage)"),1,0)
| where suspicious_name=1 OR count > 2
| stats count by src_ip, dest_ip, uri
```
