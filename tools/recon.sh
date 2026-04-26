#!/bin/bash
# NEXUS — Full 6-layer recon runner (delegates to osint.sh)
TARGET=$(echo "$1" | grep -oP '\b[\w.-]+\.[a-z]{2,}\b|\b\d{1,3}(\.\d{1,3}){3}\b' | head -1)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -z "$TARGET" ] && echo "❌ No valid target in: $1" && exit 1
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎯 NEXUS Full Recon: $TARGET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "\n[ 1/6 — WHOIS & DNS ]"
whois "$TARGET" 2>/dev/null | grep -E "Registrar:|Creation Date:|Name Server:" | head -4
dig +short "$TARGET" A 2>/dev/null | head -3
echo -e "\n[ 2/6 — VIRUSTOTAL ]";    bash "$DIR/osint.sh" vt     "$TARGET"
echo -e "\n[ 3/6 — SHODAN ]";        bash "$DIR/osint.sh" shodan "$TARGET"
echo -e "\n[ 4/6 — CENSYS ]";        bash "$DIR/osint.sh" censys "$TARGET"
IS_IP=$(echo "$TARGET" | grep -cP '^\d{1,3}(\.\d{1,3}){3}$')
if [ "$IS_IP" = "1" ]; then
  echo -e "\n[ 5/6 — ABUSEIPDB ]";  bash "$DIR/osint.sh" abuse  "$TARGET"
else
  echo -e "\n[ 5/6 — ABUSEIPDB — skipped (not an IP) ]"
fi
echo -e "\n[ 6/6 — THREAT SCORE ]";  bash "$DIR/threat_score.sh" "$TARGET"
echo -e "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Recon complete: $TARGET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
