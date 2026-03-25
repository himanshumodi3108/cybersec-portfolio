# Detection Queries — Trickbot C2 & Credential Exfiltration
**Case:** 2020-11-09 Trickbot Infection
**Analyst:** Himanshu Kumar Modi | **Date:** 2025-03-21

---

## Query 1 — Trickbot URI pattern (T1041)
**Observed:** POST /tar2/[botID]/[moduleID]/ to 51.81.112.135
```spl
index=network http.request.method=POST http.uri="/tar2/*"
| rex field=http.uri "/tar2/(?<bot_id>[^/]+)/(?<module_id>\d+)/"
| stats count by src_ip, dest_ip, bot_id, module_id
```

---

## Query 2 — Non-standard HTTPS port outbound (T1571)
**Observed:** C2 on port 447 — evades port-443-only firewall rules
```spl
index=network dest_port=447 OR dest_port=449 OR dest_port=8082
| stats count by src_ip, dest_ip, dest_port
| where count > 10
```

---

## Query 3 — Impossible User-Agent: IE7 on Windows 10 (T1036)
**Observed:** Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0)
```spl
index=network http.user_agent="*MSIE 7.0*" http.user_agent="*Windows NT 10.0*"
| stats count by src_ip, dest_ip, http.user_agent
```

---

## Query 4 — Public IP lookup by internal host (T1016)
**Observed:** GET api.ipify.org — Trickbot checking victim public IP
```spl
index=network http.request.method=GET
  (http.host="icanhazip.com" OR http.host="api.ipify.org"
   OR http.host="checkip.amazonaws.com" OR http.host="ifconfig.me")
| stats count by src_ip, http.host
| where count > 2
```

---

## Query 5 — Large credential POST to external IP (T1555.003 + T1041)
**Observed:** 573-byte POST body containing plaintext Chrome passwords
```spl
index=network http.request.method=POST
| eval dest_internal=if(match(dest_ip,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))"),1,0)
| where dest_internal=0
| eval body_size=coalesce(http.content_length,0)
| where body_size > 200
| stats count, max(body_size) as max_body by src_ip, dest_ip, http.uri
| sort -max_body
```
