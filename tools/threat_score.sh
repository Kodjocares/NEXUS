#!/bin/bash
# NEXUS — Unified Threat Score Aggregator
# Runs all OSINT tools, combines verdicts into a single risk score
# Usage: bash threat_score.sh <ip|domain> [--json] [--silent]

TARGET="$1"
FLAG="$2"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR=~/.openclaw/nexus_cache
REPORT_DIR=~/.openclaw/nexus_reports
mkdir -p "$CACHE_DIR" "$REPORT_DIR"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
DATE_SLUG=$(date '+%Y%m%d_%H%M%S')
CACHE_FILE="$CACHE_DIR/${TARGET//\//_}_$DATE_SLUG.json"

if [ -z "$TARGET" ]; then
  echo "Usage: threat_score.sh <ip|domain> [--json|--silent]"
  exit 1
fi

IS_IP=$(echo "$TARGET" | grep -cP '^\d{1,3}(\.\d{1,3}){3}$')

# ── Scoring weights ────────────────────────────────────────────
# VT:        40% weight  (most reliable multi-engine verdict)
# AbuseIPDB: 25% weight  (community-reported abuse, IP only)
# Shodan:    20% weight  (exposure surface)
# Censys:    15% weight  (corroboration + TLS posture)

VT_SCORE=0
ABUSE_SCORE=0
SHODAN_SCORE=0
CENSYS_SCORE=0
CVE_SCORE=0

VT_DETAIL=""
ABUSE_DETAIL=""
SHODAN_DETAIL=""
CENSYS_DETAIL=""
CVE_DETAIL=""

[ "$FLAG" != "--silent" ] && echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
[ "$FLAG" != "--silent" ] && echo "🧮 NEXUS Threat Score: $TARGET"
[ "$FLAG" != "--silent" ] && echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. VirusTotal ──────────────────────────────────────────────
[ "$FLAG" != "--silent" ] && echo -n "  [1/5] VirusTotal...    "
VT_RAW=$(curl -s "https://www.virustotal.com/api/v3/$([ "$IS_IP" = "1" ] && echo "ip_addresses" || echo "domains")/$TARGET" \
  -H "x-apikey: ${VIRUSTOTAL_API_KEY}")

VT_MAL=$(echo "$VT_RAW" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['attributes']['last_analysis_stats']['malicious'])" 2>/dev/null || echo 0)
VT_SUS=$(echo "$VT_RAW" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['attributes']['last_analysis_stats']['suspicious'])" 2>/dev/null || echo 0)
VT_REP=$(echo "$VT_RAW" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['attributes'].get('reputation',0))" 2>/dev/null || echo 0)

VT_SCORE=$(python3 -c "
mal=$VT_MAL; sus=$VT_SUS; rep=$VT_REP
score = min(100, (mal * 4) + (sus * 2))
if rep < -10: score = min(100, score + 20)
if rep < -50: score = min(100, score + 30)
print(int(score))
")
VT_DETAIL="malicious=$VT_MAL suspicious=$VT_SUS reputation=$VT_REP"
[ "$FLAG" != "--silent" ] && echo "score=$VT_SCORE/100 ($VT_DETAIL)"

# ── 2. AbuseIPDB (IP only) ─────────────────────────────────────
if [ "$IS_IP" = "1" ]; then
  [ "$FLAG" != "--silent" ] && echo -n "  [2/5] AbuseIPDB...    "
  ABUSE_RAW=$(curl -s -G "https://api.abuseipdb.com/api/v2/check" \
    --data-urlencode "ipAddress=$TARGET" \
    -d "maxAgeInDays=90" \
    -H "Key: ${ABUSEIPDB_API_KEY}" \
    -H "Accept: application/json")

  ABUSE_CONF=$(echo "$ABUSE_RAW" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['abuseConfidenceScore'])" 2>/dev/null || echo 0)
  ABUSE_REPS=$(echo "$ABUSE_RAW" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['totalReports'])" 2>/dev/null || echo 0)
  ABUSE_TOR=$(echo "$ABUSE_RAW"  | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('isTor',False))" 2>/dev/null || echo False)

  ABUSE_SCORE=$(python3 -c "
conf=$ABUSE_CONF; reps=$ABUSE_REPS; tor='$ABUSE_TOR'
score = conf
if reps > 100: score = min(100, score + 10)
if tor == 'True': score = min(100, score + 15)
print(int(score))
")
  ABUSE_DETAIL="confidence=$ABUSE_CONF% reports=$ABUSE_REPS tor=$ABUSE_TOR"
  [ "$FLAG" != "--silent" ] && echo "score=$ABUSE_SCORE/100 ($ABUSE_DETAIL)"
else
  [ "$FLAG" != "--silent" ] && echo "  [2/5] AbuseIPDB...    skipped (domain)"
  ABUSE_SCORE=0
fi

# ── 3. Shodan ──────────────────────────────────────────────────
[ "$FLAG" != "--silent" ] && echo -n "  [3/5] Shodan...       "
if [ "$IS_IP" = "1" ]; then
  SHODAN_RAW=$(curl -s "https://api.shodan.io/shodan/host/$TARGET?key=${SHODAN_API_KEY}")
else
  RESOLVED=$(curl -s "https://api.shodan.io/dns/resolve?hostnames=$TARGET&key=${SHODAN_API_KEY}" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(list(d.values())[0])" 2>/dev/null)
  SHODAN_RAW=$(curl -s "https://api.shodan.io/shodan/host/$RESOLVED?key=${SHODAN_API_KEY}")
fi

SHODAN_PORTS=$(echo "$SHODAN_RAW" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('ports',[])))" 2>/dev/null || echo 0)
SHODAN_VULNS=$(echo "$SHODAN_RAW" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('vulns',{})))" 2>/dev/null || echo 0)
SHODAN_TAGS=$(echo "$SHODAN_RAW"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(','.join(d.get('tags',[])))" 2>/dev/null || echo "")

SHODAN_SCORE=$(python3 -c "
ports=$SHODAN_PORTS; vulns=$SHODAN_VULNS; tags='$SHODAN_TAGS'
score = min(40, ports * 2)         # exposure: open ports
score += min(50, vulns * 15)       # known CVEs are high signal
if 'malware' in tags: score += 20
if 'tor' in tags: score += 15
if 'honeypot' in tags: score -= 20
print(max(0, min(100, int(score))))
")
SHODAN_DETAIL="ports=$SHODAN_PORTS cves=$SHODAN_VULNS tags=$SHODAN_TAGS"
[ "$FLAG" != "--silent" ] && echo "score=$SHODAN_SCORE/100 ($SHODAN_DETAIL)"

# ── 4. Censys ──────────────────────────────────────────────────
[ "$FLAG" != "--silent" ] && echo -n "  [4/5] Censys...       "
AUTH=$(echo -n "${CENSYS_API_ID}:${CENSYS_API_SECRET}" | base64)
if [ "$IS_IP" = "1" ]; then
  CENSYS_RAW=$(curl -s "https://search.censys.io/api/v2/hosts/$TARGET" \
    -H "Authorization: Basic $AUTH" -H "Accept: application/json")
else
  CENSYS_RAW=$(curl -s "https://search.censys.io/api/v2/hosts/search?q=parsed.names:$TARGET&per_page=1" \
    -H "Authorization: Basic $AUTH" -H "Accept: application/json")
fi

CENSYS_SVCS=$(echo "$CENSYS_RAW" | python3 -c "
import sys,json
d=json.load(sys.stdin).get('result',{})
svcs = d.get('services', d.get('hits',[{}])[0].get('services',[]) if d.get('hits') else [])
print(len(svcs))
" 2>/dev/null || echo 0)

CENSYS_TLS=$(echo "$CENSYS_RAW" | python3 -c "
import sys,json
d=json.load(sys.stdin).get('result',{})
svcs = d.get('services',[])
expired = sum(1 for s in svcs if s.get('tls',{}).get('certificates',{}).get('leaf_data',{}).get('validity',{}).get('end','9999') < '2025')
print(expired)
" 2>/dev/null || echo 0)

CENSYS_LABELS=$(echo "$CENSYS_RAW" | python3 -c "
import sys,json
d=json.load(sys.stdin).get('result',{})
print(','.join(d.get('labels',[])))
" 2>/dev/null || echo "")

CENSYS_SCORE=$(python3 -c "
svcs=$CENSYS_SVCS; tls=$CENSYS_TLS; labels='$CENSYS_LABELS'
score = min(30, svcs * 3)
score += tls * 10   # expired certs = bad hygiene
if 'mirai' in labels or 'c2' in labels: score += 40
if 'scanner' in labels: score += 20
print(max(0, min(100, int(score))))
")
CENSYS_DETAIL="services=$CENSYS_SVCS expired_tls=$CENSYS_TLS labels=$CENSYS_LABELS"
[ "$FLAG" != "--silent" ] && echo "score=$CENSYS_SCORE/100 ($CENSYS_DETAIL)"

# ── 5. CVE cross-check ─────────────────────────────────────────
[ "$FLAG" != "--silent" ] && echo -n "  [5/5] CVE check...    "
CVE_CRITICAL=0
CVE_HIGH=0

if [ "$SHODAN_VULNS" -gt 0 ] 2>/dev/null; then
  VULN_LIST=$(echo "$SHODAN_RAW" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print('\n'.join(list(d.get('vulns',{}).keys())[:5]))
" 2>/dev/null)

  while IFS= read -r CVE; do
    [ -z "$CVE" ] && continue
    CVSS=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CVE" | \
      python3 -c "
import sys,json
d=json.load(sys.stdin)
v=d.get('vulnerabilities',[{}])[0].get('cve',{}).get('metrics',{})
s=v.get('cvssMetricV31',[{}])[0].get('cvssData',{}).get('baseScore',
  v.get('cvssMetricV2',[{}])[0].get('cvssData',{}).get('baseScore',0))
sev=v.get('cvssMetricV31',[{}])[0].get('cvssData',{}).get('baseSeverity','LOW')
print(f'{s},{sev}')
" 2>/dev/null || echo "0,LOW")
    SCORE_VAL=$(echo "$CVSS" | cut -d',' -f1)
    SEV_VAL=$(echo "$CVSS" | cut -d',' -f2)
    [ "$SEV_VAL" = "CRITICAL" ] && CVE_CRITICAL=$((CVE_CRITICAL+1))
    [ "$SEV_VAL" = "HIGH" ]     && CVE_HIGH=$((CVE_HIGH+1))
    sleep 0.6  # NVD rate limit
  done <<< "$VULN_LIST"
fi

CVE_SCORE=$(python3 -c "
crit=$CVE_CRITICAL; high=$CVE_HIGH
print(min(100, crit*25 + high*10))
")
CVE_DETAIL="critical=$CVE_CRITICAL high=$CVE_HIGH"
[ "$FLAG" != "--silent" ] && echo "score=$CVE_SCORE/100 ($CVE_DETAIL)"

# ── Weighted final score ───────────────────────────────────────
FINAL=$(python3 -c "
vt=$VT_SCORE; abuse=$ABUSE_SCORE; shodan=$SHODAN_SCORE
censys=$CENSYS_SCORE; cve=$CVE_SCORE; is_ip=$IS_IP

if is_ip:
    score = (vt*0.35) + (abuse*0.25) + (shodan*0.20) + (censys*0.10) + (cve*0.10)
else:
    score = (vt*0.45) + (shodan*0.25) + (censys*0.20) + (cve*0.10)

print(round(score, 1))
")

# ── Risk classification ────────────────────────────────────────
RISK=$(python3 -c "
s=float($FINAL)
if   s >= 80: print('CRITICAL')
elif s >= 60: print('HIGH')
elif s >= 40: print('MEDIUM')
elif s >= 20: print('LOW')
else:         print('CLEAN')
")

RISK_ICON=$(python3 -c "
r='$RISK'
icons={'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟡','CLEAN':'🟢'}
print(icons.get(r,'⚪'))
")

# ── Save JSON cache ────────────────────────────────────────────
python3 - <<EOF > "$CACHE_FILE"
import json
data = {
  "target": "$TARGET",
  "timestamp": "$TIMESTAMP",
  "is_ip": bool($IS_IP),
  "final_score": float($FINAL),
  "risk": "$RISK",
  "breakdown": {
    "virustotal":  {"score": int($VT_SCORE),     "detail": "$VT_DETAIL"},
    "abuseipdb":   {"score": int($ABUSE_SCORE),  "detail": "$ABUSE_DETAIL"},
    "shodan":      {"score": int($SHODAN_SCORE),  "detail": "$SHODAN_DETAIL"},
    "censys":      {"score": int($CENSYS_SCORE),  "detail": "$CENSYS_DETAIL"},
    "cve":         {"score": int($CVE_SCORE),     "detail": "$CVE_DETAIL"}
  }
}
print(json.dumps(data, indent=2))
EOF

# ── Output ─────────────────────────────────────────────────────
if [ "$FLAG" = "--json" ]; then
  cat "$CACHE_FILE"
else
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "$RISK_ICON  THREAT SCORE: $FINAL / 100  [$RISK]"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "   %-12s %3s/100  %s\n" "VirusTotal"  "$VT_SCORE"     "$VT_DETAIL"
  [ "$IS_IP" = "1" ] && \
  printf "   %-12s %3s/100  %s\n" "AbuseIPDB"   "$ABUSE_SCORE"  "$ABUSE_DETAIL"
  printf "   %-12s %3s/100  %s\n" "Shodan"      "$SHODAN_SCORE" "$SHODAN_DETAIL"
  printf "   %-12s %3s/100  %s\n" "Censys"      "$CENSYS_SCORE" "$CENSYS_DETAIL"
  printf "   %-12s %3s/100  %s\n" "CVE"         "$CVE_SCORE"    "$CVE_DETAIL"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "📁 Cache: $CACHE_FILE"
fi

# ── Export for chaining ────────────────────────────────────────
export NEXUS_SCORE=$FINAL
export NEXUS_RISK=$RISK
export NEXUS_CACHE=$CACHE_FILE
