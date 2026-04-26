#!/bin/bash
# NEXUS — Monitor Agent
# Manages a persistent watchlist, runs scheduled re-scans, alerts on changes
# Usage:
#   bash monitor.sh watch ip <ip>          Add IP to watchlist
#   bash monitor.sh watch repo <name>      Watch GitHub repo
#   bash monitor.sh watch domain <domain>  Watch domain
#   bash monitor.sh run                    Run all watches (called by cron)
#   bash monitor.sh list                   List active watches
#   bash monitor.sh remove <id>            Remove a watch

ACTION="$1"
ARG1="$2"
ARG2="$3"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCH_FILE=~/.openclaw/nexus_watches.json
HISTORY_FILE=~/.openclaw/nexus_watch_history.json
BOT_SCRIPT="$(dirname "$DIR")/bot/nexus_bot.py"

# ── Init watch file ────────────────────────────────────────────
if [ ! -f "$WATCH_FILE" ]; then
  echo '{"watches":[]}' > "$WATCH_FILE"
fi

# ── Alert helper ──────────────────────────────────────────────
send_alert() {
  local msg="$1"
  echo "[ALERT] $msg"
  if [ -f "$BOT_SCRIPT" ]; then
    python3 "$BOT_SCRIPT" --alert "$msg" --platform both 2>/dev/null &
  fi
}

# ── Add a watch ────────────────────────────────────────────────
add_watch() {
  local type="$1"
  local target="$2"
  local id=$(python3 -c "import uuid; print(str(uuid.uuid4())[:8])")
  local now=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

  python3 - <<EOF
import json, sys

wf = '$WATCH_FILE'
data = json.load(open(wf))
data['watches'].append({
    'id':       '$id',
    'type':     '$type',
    'target':   '$target',
    'added':    '$now',
    'last_run': None,
    'last_score': None,
    'alert_threshold': 20,
    'active':   True
})
json.dump(data, open(wf,'w'), indent=2)
print(f'✅ Watch added: [$id] {type}:{target}')
EOF
}

# ── List watches ───────────────────────────────────────────────
list_watches() {
  python3 - <<EOF
import json
data = json.load(open('$WATCH_FILE'))
watches = data.get('watches', [])
if not watches:
    print("No active watches.")
    exit()
print(f"{'ID':10} {'TYPE':10} {'TARGET':30} {'LAST RUN':20} {'SCORE':8} {'ACTIVE':6}")
print("─"*90)
for w in watches:
    last = (w.get('last_run') or 'never')[:16]
    score = str(w.get('last_score') or '—')
    active = 'yes' if w.get('active') else 'no'
    print(f"{w['id']:10} {w['type']:10} {w['target']:30} {last:20} {score:8} {active:6}")
EOF
}

# ── Remove a watch ─────────────────────────────────────────────
remove_watch() {
  local id="$1"
  python3 - <<EOF
import json
wf   = '$WATCH_FILE'
data = json.load(open(wf))
before = len(data['watches'])
data['watches'] = [w for w in data['watches'] if w['id'] != '$id']
after  = len(data['watches'])
json.dump(data, open(wf,'w'), indent=2)
print(f"{'✅ Removed' if before>after else '❌ ID not found'}: $id")
EOF
}

# ── Run all watches ────────────────────────────────────────────
run_watches() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running all NEXUS watches..."

  python3 - <<'PYEOF'
import json, subprocess, os, sys, datetime
from pathlib import Path

wf  = os.path.expanduser('~/.openclaw/nexus_watches.json')
hf  = os.path.expanduser('~/.openclaw/nexus_watch_history.json')
dir_path = os.path.dirname(os.path.abspath('$DIR'))

data     = json.load(open(wf))
history  = json.load(open(hf)) if Path(hf).exists() else {"history": []}
now      = datetime.datetime.utcnow().isoformat()
alerts   = []

for watch in data['watches']:
    if not watch.get('active'):
        continue

    wtype  = watch['type']
    target = watch['target']
    wid    = watch['id']

    print(f"\n  [{wid}] Checking {wtype}:{target}...")

    try:
        if wtype in ('ip', 'domain'):
            # Run threat score
            result = subprocess.run(
                ['bash', os.path.join(dir_path, 'tools', 'threat_score.sh'), target, '--json'],
                capture_output=True, text=True, timeout=120,
                env={**os.environ}
            )
            score_data = json.loads(result.stdout.strip()) if result.stdout.strip() else {}
            new_score  = score_data.get('final_score', 0)
            new_risk   = score_data.get('risk', 'UNKNOWN')
            old_score  = watch.get('last_score')
            threshold  = watch.get('alert_threshold', 20)

            delta = abs(new_score - (old_score or 0)) if old_score is not None else 0

            print(f"     Score: {new_score}/100 [{new_risk}]  (was {old_score or 'N/A'})")

            watch['last_score'] = new_score
            watch['last_risk']  = new_risk
            watch['last_run']   = now

            if old_score is not None and delta >= threshold:
                direction = "↑" if new_score > old_score else "↓"
                alerts.append(
                    f"🚨 NEXUS ALERT [{wid}]\n"
                    f"Target : {target}\n"
                    f"Score  : {old_score:.1f} → {new_score:.1f} {direction} (Δ{delta:.1f})\n"
                    f"Risk   : {new_risk}\n"
                    f"Time   : {now[:16]} UTC"
                )
            elif old_score is None and new_score >= 60:
                alerts.append(
                    f"🚨 NEXUS NEW THREAT [{wid}]\n"
                    f"Target : {target}\n"
                    f"Score  : {new_score:.1f}/100 [{new_risk}]\n"
                    f"Time   : {now[:16]} UTC"
                )

            history['history'].append({
                'watch_id': wid, 'target': target,
                'score': new_score, 'risk': new_risk, 'checked_at': now
            })

        elif wtype == 'repo':
            # Check GitHub repo for new activity
            result = subprocess.run(
                ['gh', 'api', f'repos/{target}/events', '--jq', '.[0:3]|.[]|.type+" "+.actor.login+" "+.created_at'],
                capture_output=True, text=True, timeout=30, env={**os.environ}
            )
            events = result.stdout.strip()
            last_event = watch.get('last_event', '')

            watch['last_run'] = now
            if events and events != last_event:
                watch['last_event'] = events.split('\n')[0]
                first_line = events.split('\n')[0]
                alerts.append(
                    f"📦 NEXUS REPO ALERT [{wid}]\n"
                    f"Repo  : {target}\n"
                    f"Event : {first_line}\n"
                    f"Time  : {now[:16]} UTC"
                )

    except Exception as e:
        print(f"     ❌ Error: {e}")
        watch['last_run'] = now

# Save updated watches + history
json.dump(data, open(wf,'w'), indent=2)
json.dump(history, open(hf,'w'), indent=2)

# Output alerts for shell to send
if alerts:
    print(f"\n{'='*50}")
    print(f"ALERTS TO SEND: {len(alerts)}")
    for a in alerts:
        print("---ALERT---")
        print(a)
        print("---END---")
else:
    print("\n  No alert thresholds crossed.")
PYEOF
}

# ── Install cron job ───────────────────────────────────────────
install_cron() {
  CRON_LINE="*/15 * * * * bash $DIR/monitor.sh run >> ~/.openclaw/nexus_monitor.log 2>&1"
  (crontab -l 2>/dev/null | grep -v "monitor.sh run"; echo "$CRON_LINE") | crontab -
  echo "✅ Cron installed: runs every 15 minutes"
  echo "   Log: ~/.openclaw/nexus_monitor.log"
}

# ── Dispatch ───────────────────────────────────────────────────
case "$ACTION" in
  watch)
    if [ -z "$ARG1" ] || [ -z "$ARG2" ]; then
      echo "Usage: monitor.sh watch <ip|domain|repo> <target>"
      exit 1
    fi
    add_watch "$ARG1" "$ARG2"
    ;;
  list)
    list_watches
    ;;
  remove)
    remove_watch "$ARG1"
    ;;
  run)
    run_watches
    ;;
  cron)
    install_cron
    ;;
  *)
    echo "Usage: monitor.sh <watch|list|remove|run|cron>"
    echo "  watch ip <ip>          Add IP to watchlist"
    echo "  watch domain <domain>  Watch domain"
    echo "  watch repo <user/repo> Watch GitHub repo"
    echo "  list                   Show all watches"
    echo "  remove <id>            Remove a watch"
    echo "  run                    Execute all watches now"
    echo "  cron                   Install 15-min cron job"
    ;;
esac
