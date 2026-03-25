# Detection Queries — Carnage Room (Emotet + Cobalt Strike)
**Case:** TryHackMe Carnage Room
**Analyst:** Himanshu Kumar Modi | **Date:** 2026-03-24

---

## Query 1 — Cobalt Strike Host Header Masquerading (T1036)
**Observed:** Host header spoofed as `oscp.verisign.com` while actual dest was 185.106.96.158
```spl
index=network http.request.method=GET
| where http.host LIKE "%.verisign.com" OR http.host LIKE "%.microsoft.com"
| eval dest_internal=if(match(dest_ip,"^(10\.|192\.168\.)"),1,0)
| where dest_internal=0
| lookup threat_intel_ips dest_ip OUTPUT is_malicious
| where is_malicious=1
| stats count by src_ip, dest_ip, http.host
```
**Logic:** Flags HTTP traffic where the Host header claims a trusted domain but the actual destination IP is external and flagged as malicious. Classic Cobalt Strike malleable C2 pattern.

---

## Query 2 — TLS SNI to Newly Registered or Suspicious Domains (T1573.001)
**Observed:** TLS Client Hello SNIs to finejewels.com.au, thietbiagt.com, new.americold.com
```spl
index=network ssl.handshake.type=1
| stats count by src_ip, ssl.handshake.extensions_server_name, dest_ip
| eval tld=mvindex(split(ssl.handshake.extensions_server_name,"."), -1)
| where tld IN ("live","xyz","top","pw","online","site","club")
    OR count > 20
| sort -count
```
**Logic:** Surfaces TLS connections to suspicious TLDs commonly used for malware C2 (`.live`, `.xyz`, `.pw` etc.) plus high-frequency connections to the same SNI — a beaconing indicator.

---

## Query 3 — Malspam SMTP Detection (T1071.003)
**Observed:** 1,439 SMTP packets — malspam campaign from infected host
```spl
index=network sourcetype=stream:smtp
| stats count as smtp_count by src_ip
| where smtp_count > 50
| join src_ip [search index=network http.request.method=POST
    | stats count by src_ip]
| where count > 0
| table src_ip, smtp_count, count
```
**Logic:** An internal host sending more than 50 SMTP messages AND making external POST requests is highly suspicious — classic Emotet malspam + C2 combination.

---

## Query 4 — Malicious Office Document Download (T1566.001 + T1105)
**Observed:** documents.zip containing chart-1530076591.xls downloaded via HTTP
```spl
index=network http.request.method=GET
  (uri="*.zip" OR uri="*.xls" OR uri="*.xlsm" OR uri="*.doc" OR uri="*.docm")
| eval dest_internal=if(match(dest_ip,"^(10\.|192\.168\.)"),1,0)
| where dest_internal=0
| eval suspicious_name=if(match(uri,"(\d{10}|\d{13}|invoice|payment|document|chart)"),1,0)
| where suspicious_name=1
| stats count by src_ip, dest_ip, uri
```
**Logic:** Detects downloads of Office documents and zips from external IPs with suspicious naming patterns — long numeric filenames (epoch timestamps like `1530076591`) are a strong Emotet indicator.

---

## Query 5 — IP Check Service Called Post-Infection (T1016)
**Observed:** GET api.ipify.org at 17:00:04 UTC — same pattern as Trickbot Day 2
```spl
index=network http.request.method=GET
  (http.host="api.ipify.org" OR http.host="icanhazip.com"
   OR http.host="checkip.amazonaws.com" OR http.host="ifconfig.me"
   OR http.host="ipinfo.io")
| stats count by src_ip, http.host, _time
| sort _time
```
**Logic:** Identical to Rule 4 from Day 2 Trickbot investigation — confirms this is a cross-family pattern. Seeing the same technique in Trickbot AND Emotet+Cobalt Strike validates this as a reliable detection.
