#!/bin/bash
# NEXUS — Master Dispatcher v3
# All OSINT tools now route through the unified osint.sh

INPUT="$1"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG=~/.openclaw/nexus_log.txt
mkdir -p "$(dirname "$LOG")"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] $INPUT" >> "$LOG"

TARGET=$(echo "$INPUT" | grep -oP '\b[\w.-]+\.[a-z]{2,}\b|\b\d{1,3}(\.\d{1,3}){3}\b' | head -1)
CVE_ID=$(echo "$INPUT" | grep -oiP 'CVE-\d{4}-\d+' | head -1)

route() { echo "$INPUT" | grep -qiE "$1"; }

if   route '\bscan\b|\brecon\b';             then bash "$DIR/recon.sh"         "$TARGET"
elif route '\bscore\b|\bthreat\b|\brisk\b';  then bash "$DIR/threat_score.sh"  "$TARGET"
elif route '\breport\b';
  then
    if   route 'notion';   then bash "$DIR/report.sh" "$TARGET" --notion
    elif route 'obsidian'; then bash "$DIR/report.sh" "$TARGET" --obsidian
    else                        bash "$DIR/report.sh" "$TARGET" --all; fi
elif route '\bgraph\b|\bmap\b|\blinks\b';    then bash "$DIR/graph.sh"         "$TARGET"
elif route '\bvt\b|\bvirustotal\b';          then bash "$DIR/osint.sh" vt      "$TARGET"
elif route '\bshodan\b';
  then QUERY=$(echo "$INPUT" | sed 's/nexus//i;s/shodan//i' | xargs)
       bash "$DIR/osint.sh" shodan "$QUERY"
elif route '\bcensys\b';
  then QUERY=$(echo "$INPUT" | sed 's/nexus//i;s/censys//i' | xargs)
       bash "$DIR/osint.sh" censys "$QUERY"
elif route '\babuse\b|\babuseipdb\b';        then bash "$DIR/osint.sh" abuse   "$TARGET"
elif route '\bcve\b|\bvuln\b|\bexploit\b';
  then
    if [ -n "$CVE_ID" ]; then bash "$DIR/osint.sh" cve "$CVE_ID"
    else KW=$(echo "$INPUT" | sed 's/nexus//i;s/cve//i;s/vuln//i' | xargs)
         bash "$DIR/osint.sh" cve "$KW"; fi
elif route '\bpr\b|\bgithub\b|\bcommit\b|\bissue\b|\bdeploy\b|\breview\b';
  then bash "$DIR/github.sh" "$INPUT"
elif route '\bwatch\b|\bmonitor\b|\balert\b|\btrack\b';
  then bash "$DIR/monitor.sh" $INPUT
elif route '\bstatus\b|\bping\b|\bhealth\b';
  then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "⬡  NEXUS System Status"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🕒 Time    : $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "🔑 APIs    :"
    [ -n "${VIRUSTOTAL_API_KEY:-}" ]  && echo "   ✅ VirusTotal"  || echo "   ❌ VirusTotal"
    [ -n "${SHODAN_API_KEY:-}" ]      && echo "   ✅ Shodan"      || echo "   ❌ Shodan"
    [ -n "${CENSYS_API_ID:-}" ]       && echo "   ✅ Censys"      || echo "   ❌ Censys"
    [ -n "${ABUSEIPDB_API_KEY:-}" ]   && echo "   ✅ AbuseIPDB"   || echo "   ❌ AbuseIPDB"
    [ -n "${GITHUB_TOKEN:-}" ]        && echo "   ✅ GitHub"      || echo "   ❌ GitHub"
    [ -n "${NOTION_API_TOKEN:-}" ]    && echo "   ✅ Notion"      || echo "   ❌ Notion"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
elif route '\bhelp\b|\bcommands\b';
  then
    cat <<'HELP'
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NEXUS Command Reference
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RECON
  nexus scan <ip|domain>          Full 6-layer recon + score + graph URL
  nexus score <ip|domain>         Threat score only (fast)
  nexus graph <ip|domain>         Interactive link graph URL

OSINT
  nexus vt <ip|domain|hash|url>   VirusTotal
  nexus shodan <ip|query>         Shodan
  nexus censys <ip|domain|query>  Censys
  nexus abuse <ip>                AbuseIPDB
  nexus cve CVE-2024-xxxx         CVE detail + EPSS
  nexus cve <product version>     CVE keyword search

REPORTS
  nexus report <target>           Notion + Obsidian
  nexus report notion <target>    Notion only
  nexus report obsidian <target>  Obsidian only

DEV
  nexus pr list                   Open PRs
  nexus issue list                Open issues

MONITORING
  nexus watch ip <ip>             Add to watchlist
  nexus watch domain <domain>     Add to watchlist
  nexus watch repo <user/repo>    Watch GitHub repo
  nexus monitor list              Active watches

SYSTEM
  nexus status                    API + cache status
  nexus help                      This message
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HELP
else
  echo "❓ Unknown command. Send: nexus help"
fi
