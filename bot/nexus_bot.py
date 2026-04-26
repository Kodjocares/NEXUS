#!/usr/bin/env python3
"""
NEXUS Bot Wrapper
Handles both Telegram and WhatsApp (Twilio) messaging.
Routes commands → dispatch.sh → returns results + graph URL.
"""

import os, subprocess, threading, time, logging, json, re, hashlib
from pathlib import Path
from datetime import datetime

# ── Optional imports (graceful degradation) ────────────────────
try:
    import telebot
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

try:
    from flask import Flask, request as flask_request, jsonify
    from twilio.rest import Client as TwilioClient
    WHATSAPP_AVAILABLE = True
except ImportError:
    WHATSAPP_AVAILABLE = False

# ── Config ─────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

TELEGRAM_TOKEN     = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
TWILIO_SID         = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_TOKEN       = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM        = os.getenv("TWILIO_WHATSAPP_FROM", "")
WHATSAPP_TO        = os.getenv("WHATSAPP_TO", "")
GRAPH_SERVER_URL   = os.getenv("GRAPH_SERVER_URL", "http://localhost:5555")
GRAPH_SERVER_SECRET= os.getenv("GRAPH_SERVER_SECRET", "nexus-secret")
TOOLS_DIR          = Path(__file__).parent.parent / "tools"
LOG_FILE           = Path.home() / ".openclaw" / "nexus_bot.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("nexus")

# ── Helpers ────────────────────────────────────────────────────
def run_dispatch(command: str, timeout: int = 120) -> str:
    """Run dispatch.sh with the given command, return stdout."""
    try:
        env = {**os.environ, "PATH": f"/usr/local/bin:/usr/bin:/bin:{os.environ.get('PATH','')}"}
        result = subprocess.run(
            ["bash", str(TOOLS_DIR / "dispatch.sh"), command],
            capture_output=True, text=True, timeout=timeout, env=env
        )
        out = result.stdout.strip()
        if result.returncode != 0 and result.stderr:
            out += f"\n\nSTDERR: {result.stderr.strip()[:300]}"
        return out or "No output returned."
    except subprocess.TimeoutExpired:
        return f"⏱ Timed out after {timeout}s. Try a more specific command."
    except Exception as e:
        return f"❌ Dispatch error: {e}"


def run_graph_and_get_url(target: str) -> tuple[str, str]:
    """
    Run graph.sh, POST the JSON to graph server, return (graph_url, summary).
    Returns (url, summary_text).
    """
    try:
        env = {**os.environ, "PATH": f"/usr/local/bin:/usr/bin:/bin:{os.environ.get('PATH','')}"}
        result = subprocess.run(
            ["bash", str(TOOLS_DIR / "graph.sh"), target],
            capture_output=True, text=True, timeout=90, env=env
        )
        raw = result.stdout.strip()

        # Extract JSON block from output
        json_match = re.search(r'\{[\s\S]+\}', raw)
        if not json_match:
            return "", raw

        graph_json = json.loads(json_match.group())

        # POST to graph server
        import urllib.request, urllib.error
        payload = json.dumps({
            "data": graph_json,
            "secret": GRAPH_SERVER_SECRET
        }).encode()

        req = urllib.request.Request(
            f"{GRAPH_SERVER_URL}/graph/store",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_data = json.loads(resp.read())
            graph_id  = resp_data.get("id", "")
            graph_url = f"{GRAPH_SERVER_URL}/graph/{graph_id}"

        nodes = graph_json.get("node_count", 0)
        edges = graph_json.get("edge_count", 0)
        summary = f"🕸 Graph: {nodes} nodes, {edges} edges → {graph_url}"
        return graph_url, summary

    except Exception as e:
        log.warning(f"Graph server error: {e}")
        return "", f"⚠️ Graph server unavailable: {e}"


def chunk_message(text: str, max_len: int = 4000) -> list[str]:
    """Split long text into chunks for messaging APIs."""
    if len(text) <= max_len:
        return [text]
    chunks = []
    while text:
        if len(text) <= max_len:
            chunks.append(text)
            break
        split_at = text.rfind('\n', 0, max_len)
        if split_at == -1:
            split_at = max_len
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip('\n')
    return chunks


def format_for_whatsapp(text: str) -> str:
    """Strip ANSI codes and trim for WhatsApp."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    text = ansi_escape.sub('', text)
    lines = text.split('\n')
    # Remove excessive blank lines
    result, blanks = [], 0
    for line in lines:
        if line.strip() == '':
            blanks += 1
            if blanks <= 1:
                result.append(line)
        else:
            blanks = 0
            result.append(line)
    return '\n'.join(result)


def is_graph_command(command: str) -> bool:
    """Check if command should trigger a graph."""
    triggers = ['scan', 'recon', 'graph', 'map', 'links', 'relations', 'score', 'threat']
    return any(t in command.lower() for t in triggers)


def extract_target(command: str) -> str:
    """Extract IP or domain from command string."""
    match = re.search(r'\b([\w.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})\b', command)
    return match.group(1) if match else ""


# ── Telegram Bot ───────────────────────────────────────────────
def start_telegram_bot():
    if not TELEGRAM_AVAILABLE:
        log.error("pyTelegramBotAPI not installed. Run: pip install pyTelegramBotAPI")
        return
    if not TELEGRAM_TOKEN:
        log.error("TELEGRAM_BOT_TOKEN not set")
        return

    bot = telebot.TeleBot(TELEGRAM_TOKEN, parse_mode=None)

    def send_telegram(chat_id, text):
        for chunk in chunk_message(text, 4096):
            try:
                bot.send_message(chat_id, chunk)
            except Exception as e:
                log.error(f"Telegram send error: {e}")

    def handle_command_async(message, command: str):
        chat_id = message.chat.id
        target  = extract_target(command)

        # Typing indicator
        bot.send_chat_action(chat_id, 'typing')
        send_telegram(chat_id, f"⚙️ Running: `{command}`")

        # Run dispatch
        output = run_dispatch(command)
        send_telegram(chat_id, output)

        # Auto-generate graph for recon/scan/score commands
        if is_graph_command(command) and target:
            bot.send_chat_action(chat_id, 'typing')
            graph_url, graph_summary = run_graph_and_get_url(target)
            if graph_url:
                send_telegram(chat_id,
                    f"{graph_summary}\n\n"
                    f"🔗 Open in browser to explore the interactive link graph."
                )
            else:
                send_telegram(chat_id, graph_summary)

    @bot.message_handler(func=lambda m: True)
    def handle_message(message):
        text = (message.text or "").strip()
        log.info(f"Telegram [{message.chat.id}]: {text}")

        if not text:
            return

        # Accept "nexus ..." or raw commands
        command = re.sub(r'^nexus\s*', '', text, flags=re.IGNORECASE).strip()
        if not command:
            bot.send_message(message.chat.id,
                "👋 NEXUS online. Try:\n`nexus scan 1.2.3.4`\n`nexus help`")
            return

        thread = threading.Thread(
            target=handle_command_async,
            args=(message, command),
            daemon=True
        )
        thread.start()

    log.info("Telegram bot polling started...")
    while True:
        try:
            bot.infinity_polling(timeout=10, long_polling_timeout=5)
        except Exception as e:
            log.error(f"Telegram polling error: {e}. Retrying in 5s...")
            time.sleep(5)


# ── WhatsApp / Twilio Flask Webhook ───────────────────────────
def start_whatsapp_server():
    if not WHATSAPP_AVAILABLE:
        log.error("flask or twilio not installed.")
        return
    if not all([TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM, WHATSAPP_TO]):
        log.error("Twilio credentials incomplete in .env")
        return

    app = Flask("nexus_whatsapp")
    twilio_client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)

    def send_whatsapp(to: str, text: str):
        text = format_for_whatsapp(text)
        for chunk in chunk_message(text, 1500):
            try:
                twilio_client.messages.create(
                    body=chunk,
                    from_=f"whatsapp:{TWILIO_FROM}",
                    to=f"whatsapp:{to}"
                )
                time.sleep(0.3)
            except Exception as e:
                log.error(f"WhatsApp send error: {e}")

    def handle_whatsapp_async(from_number: str, command: str):
        target = extract_target(command)

        send_whatsapp(from_number, f"⚙️ Running: {command}")

        output = run_dispatch(command)
        send_whatsapp(from_number, output)

        if is_graph_command(command) and target:
            graph_url, graph_summary = run_graph_and_get_url(target)
            if graph_url:
                send_whatsapp(from_number,
                    f"{graph_summary}\n\n"
                    f"Tap the link above to explore the interactive link graph in your browser."
                )
            else:
                send_whatsapp(from_number, graph_summary)

    @app.route("/whatsapp/webhook", methods=["POST"])
    def whatsapp_webhook():
        from_number = flask_request.form.get("From", "").replace("whatsapp:", "")
        body        = flask_request.form.get("Body", "").strip()
        log.info(f"WhatsApp [{from_number}]: {body}")

        if not body:
            return "ok", 200

        command = re.sub(r'^nexus\s*', '', body, flags=re.IGNORECASE).strip()
        if not command:
            send_whatsapp(from_number, "NEXUS online. Try: nexus scan 1.2.3.4 or nexus help")
            return "ok", 200

        thread = threading.Thread(
            target=handle_whatsapp_async,
            args=(from_number, command),
            daemon=True
        )
        thread.start()

        return "ok", 200

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "nexus-whatsapp", "time": datetime.utcnow().isoformat()})

    log.info("WhatsApp webhook server starting on :8080")
    app.run(host="0.0.0.0", port=8080, debug=False)


# ── Proactive alerting (called from monitor.sh) ────────────────
def send_alert(message: str, platform: str = "both"):
    """
    Send a proactive alert from the monitor agent.
    Called via: python3 bot/nexus_bot.py --alert "message" [--platform telegram|whatsapp|both]
    """
    if platform in ("telegram", "both") and TELEGRAM_AVAILABLE and TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        try:
            bot = telebot.TeleBot(TELEGRAM_TOKEN)
            for chunk in chunk_message(message, 4096):
                bot.send_message(TELEGRAM_CHAT_ID, chunk)
            log.info(f"Alert sent via Telegram")
        except Exception as e:
            log.error(f"Telegram alert error: {e}")

    if platform in ("whatsapp", "both") and WHATSAPP_AVAILABLE and TWILIO_SID and WHATSAPP_TO:
        try:
            client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)
            text = format_for_whatsapp(message)
            for chunk in chunk_message(text, 1500):
                client.messages.create(
                    body=chunk,
                    from_=f"whatsapp:{TWILIO_FROM}",
                    to=f"whatsapp:{WHATSAPP_TO}"
                )
            log.info(f"Alert sent via WhatsApp")
        except Exception as e:
            log.error(f"WhatsApp alert error: {e}")


# ── Entry point ────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    # Alert mode (called from monitor.sh)
    if "--alert" in sys.argv:
        idx = sys.argv.index("--alert")
        msg = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else ""
        platform = "both"
        if "--platform" in sys.argv:
            pidx = sys.argv.index("--platform")
            platform = sys.argv[pidx + 1] if pidx + 1 < len(sys.argv) else "both"
        send_alert(msg, platform)
        sys.exit(0)

    # Determine mode from env
    use_telegram  = bool(TELEGRAM_TOKEN)
    use_whatsapp  = bool(TWILIO_SID)

    if not use_telegram and not use_whatsapp:
        log.error("No bot credentials found. Set TELEGRAM_BOT_TOKEN or Twilio credentials in .env")
        sys.exit(1)

    threads = []

    if use_telegram:
        log.info("Starting Telegram bot...")
        t = threading.Thread(target=start_telegram_bot, daemon=True)
        t.start()
        threads.append(t)

    if use_whatsapp:
        log.info("Starting WhatsApp webhook server...")
        t = threading.Thread(target=start_whatsapp_server, daemon=True)
        t.start()
        threads.append(t)

    log.info(f"NEXUS bot running — Telegram: {use_telegram} | WhatsApp: {use_whatsapp}")

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        log.info("NEXUS bot stopped.")
