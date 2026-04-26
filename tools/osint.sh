#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  NEXUS — Unified OSINT Engine
#  All 5 sources in one file: VirusTotal · Shodan · Censys ·
#  AbuseIPDB · CVE/NVD
#
#  Usage:
#    bash osint.sh vt      <ip|domain|url|hash>
#    bash osint.sh shodan  <ip|domain|query>
#    bash osint.sh censys  <ip|domain|query>
#    bash osint.sh abuse   <ip>
#    bash osint.sh cve     <CVE-ID|keyword [version]>
#    bash osint.sh all     <ip|domain>          ← runs vt+shodan+censys+abuse
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

SOURCE="${1:-}"
INPUT="${2:-}"

VT_KEY="${VIRUSTOTAL_API_KEY:-}"
SH_KEY="${SHODAN_API_KEY:-}"
CENSYS_ID="${CENSYS_API_ID:-}"
CENSYS_SECRET="${CENSYS_API_SECRET:-}"
AB_KEY="${ABUSEIPDB_API_KEY:-}"

SEP="─────────────────────────────────────────────"
BOLD_SEP="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Shared utilities ───────────────────────────────────────────

is_ip()     { echo "$1" | grep -qP '^\d{1,3}(\.\d{1,3}){3}$'; }
is_hash()   { echo "$1" | grep -qP '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'; }
is_url()    { echo "$1" | grep -qP '^https?://'; }
is_cve()    { echo "$1" | grep -qiP '^CVE-\d{4}-\d+$'; }

require_key() {
  local name="$1" val="$2"
  if [ -z "$val" ]; then
    echo "❌ $name not set in .env"
    exit 1
  fi
}

py() { python3 -c "$@"; }

http_get() {
  # Usage: http_get <url> [header1] [header2] ...
  local url="$1"; shift
  local args=()
  for h in "$@"; do args+=(-H "$h"); done
  curl -sf --max-time 12 "${args[@]}" "$url" 2>/dev/null
}

http_post() {
  local url="$1" data="$2"; shift 2
  local args=()
  for h in "$@"; do args+=(-H "$h"); done
  curl -sf --max-time 12 -X POST "${args[@]}" -d "$data" "$url" 2>/dev/null
}

verdict_line() {
  local mal="$1"
  if   [ "$mal" -gt 10 ] 2>/dev/null; then echo "🔴 HIGH RISK  — $mal engines flagged"
  elif [ "$mal" -gt  5 ] 2>/dev/null; then echo "🟠 MEDIUM RISK — $mal engines flagged"
  elif [ "$mal" -gt  0 ] 2>/dev/null; then echo "🟡 LOW RISK   — $mal engine(s) flagged"
  else echo "🟢 CLEAN"
  fi
}

# ═══════════════════════════════════════════════════════════════
#  1. VIRUSTOTAL
# ═══════════════════════════════════════════════════════════════

vt_detect_type() {
  if   is_ip    "$1"; then echo "ip"
  elif is_hash  "$1"; then echo "hash"
  elif is_url   "$1"; then echo "url"
  else                     echo "domain"
  fi
}

vt_ip() {
  local resp
  resp=$(http_get "https://www.virustotal.com/api/v3/ip_addresses/$1" "x-apikey: $VT_KEY")
  py "
import sys, json
d = json.loads('''$resp''')['data']['attributes']
stats = d['last_analysis_stats']
mal   = stats['malicious']
sus   = stats['suspicious']
harm  = stats['harmless']
rep   = d.get('reputation', 0)
cc    = d.get('country', 'Unknown')
owner = d.get('as_owner', 'Unknown')
asn   = d.get('asn', '?')
print(f'🌍 Country    : {cc}')
print(f'🏢 Owner      : {owner}  (AS{asn})')
print(f'⭐ Reputation : {rep}')
print()
print(f'🛡  Vendor verdicts:')
print(f'   🔴 Malicious  : {mal}')
print(f'   🟡 Suspicious : {sus}')
print(f'   🟢 Harmless   : {harm}')
print()
# Historical whois
nets = d.get('network','?')
print(f'🔗 Network    : {nets}')
"
  local mal
  mal=$(py "import json; d=json.loads('''$resp''')['data']['attributes']; print(d['last_analysis_stats']['malicious'])" 2>/dev/null || echo 0)
  echo ""; verdict_line "$mal"
}

vt_domain() {
  local resp
  resp=$(http_get "https://www.virustotal.com/api/v3/domains/$1" "x-apikey: $VT_KEY")
  py "
import sys, json, datetime
d = json.loads('''$resp''')['data']['attributes']
stats = d['last_analysis_stats']
mal   = stats['malicious']
sus   = stats['suspicious']
cats  = ', '.join(set(d.get('categories',{}).values()))[:80] or 'None'
ts    = d.get('creation_date', 0)
created = datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d') if ts else 'Unknown'
rep   = d.get('reputation', 0)
print(f'📅 Created    : {created}')
print(f'⭐ Reputation : {rep}')
print(f'🏷  Categories : {cats}')
print()
print(f'🛡  Vendor verdicts:')
print(f'   🔴 Malicious  : {mal}')
print(f'   🟡 Suspicious : {sus}')
# Subdomains count
subs = d.get('last_dns_records', [])
print(f'   DNS records  : {len(subs)}')
"
  local mal
  mal=$(py "import json; print(json.loads('''$resp''')['data']['attributes']['last_analysis_stats']['malicious'])" 2>/dev/null || echo 0)
  echo ""; verdict_line "$mal"
}

vt_hash() {
  local resp
  resp=$(http_get "https://www.virustotal.com/api/v3/files/$1" "x-apikey: $VT_KEY")
  py "
import json
d = json.loads('''$resp''')['data']['attributes']
stats = d['last_analysis_stats']
mal   = stats['malicious']
sus   = stats['suspicious']
names = d.get('names', [])
name  = names[0] if names else 'Unknown'
ftype = d.get('type_description', 'Unknown')
size  = d.get('size', '?')
magic = d.get('magic', '')
sig   = d.get('signature_info', {}).get('product', '')
print(f'📄 Name     : {name}')
print(f'🗂  Type     : {ftype}')
print(f'📦 Size     : {size} bytes')
print(f'🔮 Magic    : {magic[:60]}')
print(f'✍️  Signed   : {sig or \"No\"}')
print()
print(f'🛡  Detections: {mal} / 70+ engines malicious, {sus} suspicious')
# Top families
families = d.get('popular_threat_classification', {})
cats = [c['value'] for c in families.get('suggested_threat_label',[]) if isinstance(c,dict)][:3] if isinstance(families.get('suggested_threat_label'), list) else []
if cats: print(f'🦠 Family   : {\", \".join(cats)}')
"
  local mal
  mal=$(py "import json; print(json.loads('''$resp''')['data']['attributes']['last_analysis_stats']['malicious'])" 2>/dev/null || echo 0)
  echo ""; verdict_line "$mal"
}

vt_url() {
  local url_id
  url_id=$(py "import base64, sys; print(base64.urlsafe_b64encode(sys.argv[1].encode()).decode().rstrip('='))" "$1")
  local resp
  resp=$(http_get "https://www.virustotal.com/api/v3/urls/$url_id" "x-apikey: $VT_KEY")
  py "
import json
d = json.loads('''$resp''')['data']['attributes']
stats    = d['last_analysis_stats']
mal      = stats['malicious']
sus      = stats['suspicious']
final    = d.get('last_final_url', 'N/A')
title    = d.get('title', 'N/A')
cats     = ', '.join(d.get('categories', {}).values())[:60] or 'None'
print(f'🌐 Final URL : {final[:80]}')
print(f'📰 Title     : {title[:60]}')
print(f'🏷  Categories: {cats}')
print()
print(f'🛡  Malicious : {mal}  Suspicious: {sus}')
"
  local mal
  mal=$(py "import json; print(json.loads('''$resp''')['data']['attributes']['last_analysis_stats']['malicious'])" 2>/dev/null || echo 0)
  echo ""; verdict_line "$mal"
}

run_vt() {
  require_key "VIRUSTOTAL_API_KEY" "$VT_KEY"
  local type
  type=$(vt_detect_type "$INPUT")
  echo "$BOLD_SEP"
  echo "🔬 VirusTotal — $type: $INPUT"
  echo "$SEP"
  case "$type" in
    ip)     vt_ip     "$INPUT" ;;
    domain) vt_domain "$INPUT" ;;
    hash)   vt_hash   "$INPUT" ;;
    url)    vt_url    "$INPUT" ;;
  esac
  echo "$SEP"
  echo "🔗 https://www.virustotal.com/gui/$type/$INPUT"
}

# ═══════════════════════════════════════════════════════════════
#  2. SHODAN
# ═══════════════════════════════════════════════════════════════

shodan_resolve() {
  # Returns IP for a domain via Shodan DNS
  local resp
  resp=$(http_get "https://api.shodan.io/dns/resolve?hostnames=$1&key=$SH_KEY")
  py "import json; d=json.loads('''$resp'''); print(list(d.values())[0])" 2>/dev/null
}

shodan_host() {
  local ip="$1"
  local resp
  resp=$(http_get "https://api.shodan.io/shodan/host/$ip?key=$SH_KEY")

  local err
  err=$(py "import json; print(json.loads('''$resp''').get('error',''))" 2>/dev/null)
  if [ -n "$err" ]; then echo "❌ Shodan: $err"; return 1; fi

  py "
import json
d     = json.loads('''$resp''')
org   = d.get('org', 'Unknown')
cc    = d.get('country_name', 'Unknown')
city  = d.get('city', 'Unknown')
isp   = d.get('isp', 'Unknown')
os_   = d.get('os', 'Unknown')
tags  = ', '.join(d.get('tags', [])) or 'None'
hns   = ', '.join(d.get('hostnames', [])[:3]) or 'None'
ports = sorted(d.get('ports', []))
vulns = list(d.get('vulns', {}).keys())
svcs  = d.get('data', [])

print(f'🏢 Org       : {org}')
print(f'🌍 Location  : {city}, {cc}')
print(f'📡 ISP       : {isp}')
print(f'💻 OS        : {os_}')
print(f'🏷  Tags      : {tags}')
print(f'🔗 Hostnames : {hns}')
print()
print(f'🔓 Open Ports ({len(ports)}): {\" \".join(str(p) for p in ports[:20])}')

if vulns:
    print()
    print(f'🚨 CVEs ({len(vulns)}):')
    for v in vulns[:8]: print(f'   ⚠️  {v}')
    if len(vulns) > 8: print(f'   ... and {len(vulns)-8} more')

print()
print(f'🛠  Top Services:')
for s in svcs[:6]:
    port = s.get('port','?')
    prod = s.get('product','unknown')
    ver  = s.get('version','')
    data = (s.get('data','')[:50] or '').replace('\n',' ')
    print(f'   [{port}] {prod} {ver}  {data}')
if len(svcs) > 6: print(f'   ... and {len(svcs)-6} more')
"
}

shodan_search() {
  local q
  q=$(py "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$INPUT")
  local resp
  resp=$(http_get "https://api.shodan.io/shodan/host/search?key=$SH_KEY&query=$q&facets=country,port,org")
  py "
import json
d       = json.loads('''$resp''')
total   = d.get('total', 0)
matches = d.get('matches', [])
facets  = d.get('facets', {})

print(f'📊 Total results : {total:,}')

countries = facets.get('country', [])[:5]
if countries:
    print(); print('🌍 Top Countries:')
    for c in countries: print(f'   {c[\"value\"]:20} {c[\"count\"]:,}')

ports = facets.get('port', [])[:5]
if ports:
    print(); print('🔓 Top Ports:')
    for p in ports: print(f'   :{p[\"value\"]:<8} {p[\"count\"]:,}')

orgs = facets.get('org', [])[:5]
if orgs:
    print(); print('🏢 Top Orgs:')
    for o in orgs: print(f'   {o[\"value\"][:30]:30} {o[\"count\"]:,}')

print(); print(f'📋 Sample ({min(5,len(matches))}/{total:,}):')
for m in matches[:5]:
    ip   = m.get('ip_str','?')
    port = m.get('port','?')
    org  = m.get('org','?')[:22]
    cc   = m.get('location',{}).get('country_name','?')[:12]
    prod = m.get('product','')[:15]
    print(f'   {ip:18} :{port:<6} {cc:14} {org:24} {prod}')
"
}

run_shodan() {
  require_key "SHODAN_API_KEY" "$SH_KEY"
  echo "$BOLD_SEP"
  if is_ip "$INPUT"; then
    echo "🌐 Shodan Host: $INPUT"
    echo "$SEP"
    shodan_host "$INPUT"
    echo "$SEP"
    echo "🔗 https://www.shodan.io/host/$INPUT"
  elif ! echo "$INPUT" | grep -q ' ' && echo "$INPUT" | grep -qP '\.[a-z]{2,}$'; then
    echo "🌐 Shodan DNS+Host: $INPUT"
    echo "$SEP"
    local ip
    ip=$(shodan_resolve "$INPUT")
    if [ -n "$ip" ] && [ "$ip" != "None" ]; then
      echo "📍 Resolved → $ip"
      echo ""
      shodan_host "$ip"
    else
      echo "❌ Could not resolve $INPUT via Shodan DNS"
    fi
    echo "$SEP"
    echo "🔗 https://www.shodan.io/search?query=$INPUT"
  else
    echo "🌐 Shodan Search: $INPUT"
    echo "$SEP"
    shodan_search
    echo "$SEP"
  fi
}

# ═══════════════════════════════════════════════════════════════
#  3. CENSYS
# ═══════════════════════════════════════════════════════════════

censys_auth() {
  py "import base64,os; print(base64.b64encode(f'{os.environ[\"CENSYS_API_ID\"]}:{os.environ[\"CENSYS_API_SECRET\"]}'.encode()).decode())"
}

censys_host() {
  local auth="$1" ip="$2"
  local resp
  resp=$(http_get "https://search.censys.io/api/v2/hosts/$ip" \
    "Authorization: Basic $auth" "Accept: application/json")
  py "
import json
d   = json.loads('''$resp''').get('result', {})
ip  = d.get('ip','?')
asn = d.get('autonomous_system', {})
loc = d.get('location', {})
svc = d.get('services', [])
lbl = d.get('labels', [])
lu  = d.get('last_updated_at','')[:10]
coords = loc.get('coordinates',{})

print(f'🌍 Location   : {loc.get(\"city\",\"?\")}, {loc.get(\"country\",\"?\")}')
print(f'🏢 ASN        : AS{asn.get(\"asn\",\"?\")} — {asn.get(\"name\",\"?\")}')
print(f'🕒 Last Seen  : {lu}')
print(f'🏷  Labels     : {\", \".join(lbl) if lbl else \"None\"}')
print()
print(f'🛠  Services ({len(svc)}):')
for s in svc[:10]:
    port = s.get(\"port\",\"?\")
    tpt  = s.get(\"transport_protocol\",\"\")
    name = s.get(\"service_name\",\"unknown\")
    sw   = s.get(\"software\",[{}])[0].get(\"product\",\"\") if s.get(\"software\") else \"\"
    tls  = \"🔒\" if s.get(\"tls\") else \"  \"
    print(f'   {tls} [{port}/{tpt:3}] {name:15} {sw}')
if len(svc) > 10: print(f'   ... and {len(svc)-10} more')

certs = [s for s in svc if s.get('tls')]
if certs:
    print()
    print(f'🔐 TLS Certs ({len(certs)}):')
    seen = set()
    for c in certs[:3]:
        ld  = c.get('tls',{}).get('certificates',{}).get('leaf_data',{})
        sub = ld.get('subject_dn','?')
        exp = ld.get('validity',{}).get('end','?')[:10]
        iss = ld.get('issuer_dn','?')[:50]
        if sub not in seen:
            seen.add(sub)
            print(f'   Subject : {sub[:60]}')
            print(f'   Issuer  : {iss}')
            print(f'   Expires : {exp}')
"
}

censys_search() {
  local auth="$1"
  local q
  q=$(py "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$INPUT")
  local resp
  resp=$(http_get "https://search.censys.io/api/v2/hosts/search?q=$q&per_page=5" \
    "Authorization: Basic $auth" "Accept: application/json")
  py "
import json
d     = json.loads('''$resp''')
total = d.get('result',{}).get('total',0)
hits  = d.get('result',{}).get('hits',[])
print(f'📊 Results: {total:,} hosts')
print()
print(f'📋 Top {len(hits)}:')
for h in hits:
    ip  = h.get('ip','?')
    cc  = h.get('location',{}).get('country_code','?')
    asn = h.get('autonomous_system',{}).get('name','?')[:22]
    svs = h.get('services',[])
    pts = ', '.join(str(s.get('port','?')) for s in svs[:5])
    lbl = ', '.join(h.get('labels',[]))[:16]
    print(f'   {ip:18} [{cc}] {asn:24} ports:{pts:20} {lbl}')
"
}

run_censys() {
  require_key "CENSYS_API_ID"     "$CENSYS_ID"
  require_key "CENSYS_API_SECRET" "$CENSYS_SECRET"
  local auth
  auth=$(censys_auth)
  echo "$BOLD_SEP"
  if is_ip "$INPUT"; then
    echo "🔭 Censys Host: $INPUT"
    echo "$SEP"
    censys_host "$auth" "$INPUT"
    echo "$SEP"
    echo "🔗 https://search.censys.io/hosts/$INPUT"
  elif ! echo "$INPUT" | grep -q ' ' && echo "$INPUT" | grep -qP '\.[a-z]{2,}$'; then
    local q
    q=$(py "import urllib.parse,sys; print(urllib.parse.quote('parsed.names: '+sys.argv[1]))" "$INPUT")
    local resp
    resp=$(http_get "https://search.censys.io/api/v2/hosts/search?q=$q&per_page=5" \
      "Authorization: Basic $auth" "Accept: application/json")
    echo "🔭 Censys Domain: $INPUT"
    echo "$SEP"
    py "
import json
d     = json.loads('''$resp''')
total = d.get('result',{}).get('total',0)
hits  = d.get('result',{}).get('hits',[])
print(f'🌐 Hosts for domain: total {total:,}')
print()
for h in hits:
    ip  = h.get('ip','?')
    cc  = h.get('location',{}).get('country_code','?')
    asn = h.get('autonomous_system',{}).get('name','?')[:25]
    svs = h.get('services',[])
    pts = ', '.join(str(s.get('port','?')) for s in svs[:5])
    print(f'   {ip:18} [{cc}] {asn:25} ports: {pts}')
"
    echo "$SEP"
  else
    echo "🔭 Censys Search: $INPUT"
    echo "$SEP"
    censys_search "$auth"
    echo "$SEP"
  fi
}

# ═══════════════════════════════════════════════════════════════
#  4. ABUSEIPDB
# ═══════════════════════════════════════════════════════════════

run_abuse() {
  require_key "ABUSEIPDB_API_KEY" "$AB_KEY"
  if ! is_ip "$INPUT"; then
    echo "❌ AbuseIPDB only accepts IPv4 addresses. Got: $INPUT"
    exit 1
  fi
  local resp
  resp=$(http_get \
    "https://api.abuseipdb.com/api/v2/check?ipAddress=$INPUT&maxAgeInDays=90&verbose" \
    "Key: $AB_KEY" "Accept: application/json")

  echo "$BOLD_SEP"
  echo "🚨 AbuseIPDB: $INPUT"
  echo "$SEP"

  py "
import json
d     = json.loads('''$resp''').get('data',{})
score = d.get('abuseConfidenceScore',0)
reps  = d.get('totalReports',0)
users = d.get('numDistinctUsers',0)
last  = d.get('lastReportedAt','Never')
cc    = d.get('countryCode','?')
isp   = d.get('isp','?')
dom   = d.get('domain','?')
usage = d.get('usageType','?')
tor   = d.get('isTor',False)
pub   = d.get('isPublic',True)

risk = ('🔴 CRITICAL' if score>=80 else '🟠 HIGH' if score>=50
        else '🟡 MEDIUM' if score>=20 else '🟡 LOW' if score>0 else '🟢 CLEAN')

print(f'🎯 Abuse Score  : {score}/100  {risk}')
print(f'📊 Total Reports: {reps} from {users} distinct users')
print(f'🕒 Last Reported: {last}')
print()
print(f'🌍 Country      : {cc}')
print(f'📡 ISP          : {isp}')
print(f'🌐 Domain       : {dom}')
print(f'🏷  Usage Type   : {usage}')
print(f'🧅 Tor Exit Node: {\"Yes ⚠️\" if tor else \"No\"}')
print(f'🔓 Public IP    : {\"Yes\" if pub else \"No (private)\"}')

reports = d.get('reports',[])
if reports:
    print()
    print(f'📋 Recent Reports (showing {min(5,len(reports))} of {reps}):')
    cat_map = {
        3:'Fraud',4:'DDoS',9:'Open Proxy',10:'Web Spam',11:'Email Spam',
        14:'Port Scan',15:'Hacking',16:'SQL Injection',17:'Spoofing',
        18:'Brute Force',19:'Bad Bot',20:'Exploited Host',
        21:'Web App Attack',22:'SSH',23:'IoT Targeted'
    }
    for r in reports[:5]:
        cats    = [cat_map.get(c,str(c)) for c in r.get('categories',[])]
        comment = (r.get('comment','No comment') or 'No comment')[:60]
        date    = r.get('reportedAt','')[:10]
        print(f'   [{date}] {\" + \".join(cats)}')
        print(f'           {comment}')
"
  echo "$SEP"
  echo "🔗 https://www.abuseipdb.com/check/$INPUT"
}

# ═══════════════════════════════════════════════════════════════
#  5. CVE / NVD + EPSS
# ═══════════════════════════════════════════════════════════════

cve_direct() {
  local cve_id
  cve_id=$(echo "$INPUT" | tr '[:lower:]' '[:upper:]')

  local nvd_resp epss_resp
  nvd_resp=$(http_get  "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve_id")
  epss_resp=$(http_get "https://api.first.org/data/v1/epss?cve=$cve_id")

  py "
import json, textwrap

nvd  = json.loads('''$nvd_resp''')
epss = json.loads('''$epss_resp''')

vulns = nvd.get('vulnerabilities',[])
if not vulns:
    print('❌ CVE not found in NVD database.')
    exit()

cve_data  = vulns[0].get('cve',{})
cve_id    = cve_data.get('id','?')
published = cve_data.get('published','')[:10]
modified  = cve_data.get('lastModified','')[:10]
status    = cve_data.get('vulnStatus','Unknown')
desc      = next((d['value'] for d in cve_data.get('descriptions',[]) if d['lang']=='en'),'No description')

metrics  = cve_data.get('metrics',{})
cvss3    = metrics.get('cvssMetricV31',[{}])[0].get('cvssData',{})
cvss2    = metrics.get('cvssMetricV2',[{}])[0].get('cvssData',{})
score3   = cvss3.get('baseScore', cvss2.get('baseScore','N/A'))
severity = cvss3.get('baseSeverity', cvss2.get('baseSeverity','N/A'))
vector   = cvss3.get('vectorString', cvss2.get('vectorString','N/A'))
av       = cvss3.get('attackVector','N/A')
ac       = cvss3.get('attackComplexity','N/A')
pr       = cvss3.get('privilegesRequired','N/A')
ui       = cvss3.get('userInteraction','N/A')
ci       = cvss3.get('confidentialityImpact','N/A')
ii       = cvss3.get('integrityImpact','N/A')
ai       = cvss3.get('availabilityImpact','N/A')

epss_d    = epss.get('data',[{}])[0]
epss_pct  = float(epss_d.get('epss',0))*100
epss_rank = float(epss_d.get('percentile',0))*100

sev_icon  = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢','NONE':'⚪'}.get(str(severity).upper(),'⚪')

print(f'📌 {cve_id}  {sev_icon} {severity}  CVSS: {score3}')
print(f'📅 Published : {published}  |  Modified: {modified}')
print(f'📊 Status    : {status}')
print()
print('📝 Description:')
for line in textwrap.wrap(desc, 64):
    print(f'   {line}')
print()
print(f'⚔️  Vector     : {vector}')
print(f'   Attack     : {av} / Complexity: {ac}')
print(f'   Privileges : {pr} / User Interact: {ui}')
print(f'   Impact     : C:{ci} I:{ii} A:{ai}')
print()
print(f'🎯 EPSS Score : {epss_pct:.2f}% exploitation probability')
print(f'   Percentile : {epss_rank:.1f}th (higher = actively exploited)')

configs = cve_data.get('configurations',[])
affected = []
for cfg in configs:
    for node in cfg.get('nodes',[]):
        for cpe in node.get('cpeMatch',[]):
            if cpe.get('vulnerable'):
                parts = cpe.get('criteria','').split(':')
                if len(parts) >= 5:
                    affected.append(f'{parts[3]} {parts[4]} {parts[5] if len(parts)>5 else \"*\"}')
if affected:
    print()
    print(f'📦 Affected ({len(affected)}):')
    for a in affected[:8]: print(f'   • {a}')
    if len(affected)>8: print(f'   ... and {len(affected)-8} more')

refs = cve_data.get('references',[])
if refs:
    print()
    print(f'🔗 References ({len(refs)}):')
    for r in refs[:4]:
        tags = ', '.join(r.get('tags',[]))
        url  = r.get('url','')[:70]
        print(f'   [{tags or \"ref\"}] {url}')
"
}

cve_search() {
  local q
  q=$(py "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$INPUT")
  local resp
  resp=$(http_get "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$q&resultsPerPage=10")

  py "
import json
data  = json.loads('''$resp''')
total = data.get('totalResults',0)
vulns = data.get('vulnerabilities',[])

print(f'🔍 Search: \"$INPUT\"')
print(f'📊 Total CVEs: {total:,}')
print()

sev_icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢','NONE':'⚪'}

def score(v):
    m = v['cve'].get('metrics',{})
    c3 = m.get('cvssMetricV31',[{}])[0].get('cvssData',{})
    c2 = m.get('cvssMetricV2',[{}])[0].get('cvssData',{})
    return float(c3.get('baseScore', c2.get('baseScore',0)) or 0)

vulns.sort(key=score, reverse=True)

for v in vulns[:10]:
    cve     = v['cve']
    cid     = cve.get('id','?')
    pub     = cve.get('published','')[:10]
    desc    = next((d['value'] for d in cve.get('descriptions',[]) if d['lang']=='en'),'')[:80]
    m       = cve.get('metrics',{})
    c3      = m.get('cvssMetricV31',[{}])[0].get('cvssData',{})
    c2      = m.get('cvssMetricV2',[{}])[0].get('cvssData',{})
    sc      = c3.get('baseScore', c2.get('baseScore','N/A'))
    sev     = c3.get('baseSeverity', c2.get('baseSeverity','N/A'))
    icon    = sev_icon.get(str(sev).upper(),'⚪')
    print(f'  {icon} {cid:22} CVSS:{sc}  [{pub}]')
    print(f'     {desc[:75]}...')
    print()

if total > 10:
    print(f'  ... {total-10:,} more → https://nvd.nist.gov/vuln/search/results?query={\"$INPUT\".replace(\" \",\"+\")}')
"
}

run_cve() {
  echo "$BOLD_SEP"
  if is_cve "$INPUT"; then
    echo "🛡  CVE Detail: $INPUT"
    echo "$SEP"
    cve_direct
    echo "$SEP"
    echo "🔗 https://nvd.nist.gov/vuln/detail/$INPUT"
  else
    echo "🛡  CVE Search: $INPUT"
    echo "$SEP"
    cve_search
    echo "$SEP"
  fi
}

# ═══════════════════════════════════════════════════════════════
#  6. ALL — run vt + shodan + censys + abuse (IP only)
# ═══════════════════════════════════════════════════════════════

run_all() {
  echo "$BOLD_SEP"
  echo "🎯 NEXUS OSINT — Full Scan: $INPUT"
  echo "$BOLD_SEP"

  echo -e "\n[ 1/4 — VIRUSTOTAL ]"
  run_vt 2>/dev/null || echo "  ❌ VirusTotal failed"

  echo -e "\n[ 2/4 — SHODAN ]"
  run_shodan 2>/dev/null || echo "  ❌ Shodan failed"

  echo -e "\n[ 3/4 — CENSYS ]"
  run_censys 2>/dev/null || echo "  ❌ Censys failed"

  if is_ip "$INPUT"; then
    echo -e "\n[ 4/4 — ABUSEIPDB ]"
    run_abuse 2>/dev/null || echo "  ❌ AbuseIPDB failed"
  else
    echo -e "\n[ 4/4 — ABUSEIPDB — skipped (not an IP) ]"
  fi

  echo -e "\n$BOLD_SEP"
  echo "✅ Full OSINT scan complete: $INPUT"
  echo "$BOLD_SEP"
}

# ═══════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════

if [ -z "$SOURCE" ] || [ -z "$INPUT" ]; then
  echo "Usage: osint.sh <source> <target>"
  echo ""
  echo "  Sources:"
  echo "    vt      <ip|domain|url|hash>   VirusTotal"
  echo "    shodan  <ip|domain|query>      Shodan"
  echo "    censys  <ip|domain|query>      Censys"
  echo "    abuse   <ip>                   AbuseIPDB"
  echo "    cve     <CVE-ID|keyword>       CVE/NVD + EPSS"
  echo "    all     <ip|domain>            All sources"
  echo ""
  echo "  Examples:"
  echo "    osint.sh vt      185.220.101.47"
  echo "    osint.sh shodan  apache port:80 country:RU"
  echo "    osint.sh cve     CVE-2021-44228"
  echo "    osint.sh cve     log4j"
  echo "    osint.sh all     evil.com"
  exit 0
fi

case "$SOURCE" in
  vt|virustotal)  run_vt     ;;
  shodan)         run_shodan ;;
  censys)         run_censys ;;
  abuse|abuseipdb) run_abuse ;;
  cve|nvd)        run_cve    ;;
  all|full)       run_all    ;;
  *)
    echo "❌ Unknown source: $SOURCE"
    echo "   Valid: vt, shodan, censys, abuse, cve, all"
    exit 1
    ;;
esac
