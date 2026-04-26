#!/usr/bin/env python3
"""
NEXUS Graph Server
Stores graph JSON, serves interactive D3 link graph pages.
Each scan gets a unique URL returned to the bot → sent to user.
"""

import os, json, uuid, time, logging
from pathlib import Path
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, render_template_string, abort
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

GRAPH_SERVER_SECRET = os.getenv("GRAPH_SERVER_SECRET", "nexus-secret")
GRAPH_STORE_DIR     = Path.home() / ".openclaw" / "nexus_graphs"
GRAPH_STORE_DIR.mkdir(parents=True, exist_ok=True)
MAX_AGE_HOURS       = 72   # Graphs expire after 72h
PORT                = int(os.getenv("GRAPH_SERVER_PORT", 5555))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("nexus-graph-server")

app = Flask("nexus_graph_server")

# ── HTML template for graph page ──────────────────────────────
GRAPH_TEMPLATE = r"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NEXUS Graph — {{ target }}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
  header{padding:14px 20px;border-bottom:1px solid #1e2535;display:flex;align-items:center;gap:14px;background:#0f1117}
  .logo{font-size:15px;font-weight:600;letter-spacing:.08em;color:#e2e8f0}
  .logo span{color:#e24b4a}
  .target-badge{font-size:12px;background:#1e2535;border:1px solid #2d3748;border-radius:6px;padding:4px 10px;color:#94a3b8;font-family:monospace}
  .risk-badge{font-size:11px;font-weight:600;padding:4px 10px;border-radius:6px;margin-left:auto}
  .risk-CRITICAL{background:#4a1515;color:#fc8181;border:1px solid #e24b4a}
  .risk-HIGH    {background:#451c0a;color:#f6ad55;border:1px solid #d85a30}
  .risk-MEDIUM  {background:#3d3000;color:#f6e05e;border:1px solid #ef9f27}
  .risk-LOW     {background:#1a2e1a;color:#68d391;border:1px solid #639922}
  .risk-CLEAN   {background:#0d2b22;color:#38bdf8;border:1px solid #1d9e75}
  .stats{display:flex;gap:12px;padding:10px 20px;border-bottom:1px solid #1e2535;background:#0c0f18}
  .stat{background:#1a1f2e;border:1px solid #1e2535;border-radius:6px;padding:6px 14px;font-size:12px}
  .stat-label{color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.05em}
  .stat-value{color:#e2e8f0;font-weight:600;font-size:16px}
  #graph-container{width:100%;height:calc(100vh - 105px);position:relative}
  svg{width:100%;height:100%}
  .link{stroke:#2d3748;stroke-width:1;opacity:0.7}
  .link-label{font-size:9px;fill:#475569;pointer-events:none}
  .node circle{cursor:pointer;transition:all 0.15s}
  .node circle:hover{opacity:0.85;filter:brightness(1.2)}
  .node-label{font-size:10px;fill:#94a3b8;pointer-events:none;text-anchor:middle}
  #tooltip{position:absolute;background:#1e2535;border:1px solid #2d3748;border-radius:8px;padding:10px 14px;font-size:12px;pointer-events:none;display:none;max-width:260px;box-shadow:0 4px 20px rgba(0,0,0,.5)}
  #tooltip .tip-title{font-weight:600;color:#e2e8f0;margin-bottom:4px;font-size:13px}
  #tooltip .tip-type{color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
  #tooltip .tip-score{margin-bottom:4px}
  #tooltip .tip-detail{color:#94a3b8;font-size:11px;word-break:break-all}
  .score-bar{background:#1a1f2e;border-radius:3px;height:5px;width:120px;margin-top:4px}
  .score-fill{height:100%;border-radius:3px;transition:width .3s}
  .legend{position:absolute;bottom:16px;left:16px;background:#1a1f2e;border:1px solid #1e2535;border-radius:8px;padding:10px 14px;font-size:11px}
  .legend-title{color:#64748b;margin-bottom:6px;font-size:10px;text-transform:uppercase;letter-spacing:.05em}
  .legend-item{display:flex;align-items:center;gap:6px;margin-bottom:4px;color:#94a3b8}
  .legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
  .controls{position:absolute;top:10px;right:14px;display:flex;gap:6px}
  .ctrl-btn{background:#1a1f2e;border:1px solid #2d3748;color:#94a3b8;padding:5px 10px;border-radius:5px;font-size:11px;cursor:pointer}
  .ctrl-btn:hover{background:#2d3748;color:#e2e8f0}
  .ts{color:#475569;font-size:11px;margin-left:6px}
</style>
</head>
<body>
<header>
  <div class="logo"><span>NEX</span>US</div>
  <div class="target-badge">{{ target }}</div>
  <div class="ts">{{ timestamp }}</div>
  <div class="risk-badge risk-{{ risk }}" id="risk-label">{{ risk }} {{ score }}/100</div>
</header>
<div class="stats">
  <div class="stat"><div class="stat-label">nodes</div><div class="stat-value" id="s-nodes">—</div></div>
  <div class="stat"><div class="stat-label">edges</div><div class="stat-value" id="s-edges">—</div></div>
  <div class="stat"><div class="stat-label">CVEs</div><div class="stat-value" id="s-cves">—</div></div>
  <div class="stat"><div class="stat-label">services</div><div class="stat-value" id="s-svcs">—</div></div>
  <div class="stat"><div class="stat-label">malware links</div><div class="stat-value" id="s-mal">—</div></div>
</div>
<div id="graph-container">
  <svg id="graph-svg"></svg>
  <div id="tooltip"></div>
  <div class="controls">
    <button class="ctrl-btn" onclick="resetZoom()">Reset zoom</button>
    <button class="ctrl-btn" onclick="toggleLabels()">Labels</button>
    <button class="ctrl-btn" onclick="exportPNG()">Export</button>
  </div>
  <div class="legend" id="legend"></div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script>
const GRAPH_DATA = {{ graph_json }};

const TYPE_CFG = {
  target:        {color:"#e24b4a", r:24, label:"target"},
  ip:            {color:"#378add", r:14, label:"ip"},
  subdomain:     {color:"#5b9bd5", r:12, label:"subdomain"},
  hostname:      {color:"#5dcaa5", r:11, label:"hostname"},
  intel_source:  {color:"#7f77dd", r:17, label:"intel source"},
  asn:           {color:"#888780", r:13, label:"ASN"},
  org:           {color:"#6b7280", r:13, label:"org"},
  country:       {color:"#5dcaa5", r:10, label:"country"},
  service:       {color:"#ef9f27", r:11, label:"service"},
  cve:           {color:"#e24b4a", r:14, label:"CVE"},
  malware:       {color:"#dc2626", r:15, label:"malware"},
  tag:           {color:"#4b5563", r:8,  label:"tag"},
  infrastructure:{color:"#d4537e", r:12, label:"infra"},
  abuse_category:{color:"#d85a30", r:11, label:"abuse"},
};

function scoreColor(s){
  if(s>=80)return"#e24b4a";if(s>=60)return"#d85a30";
  if(s>=40)return"#ef9f27";if(s>=20)return"#639922";return"#1d9e75";
}

const nodes = GRAPH_DATA.nodes.map(d=>({...d}));
const edges = GRAPH_DATA.edges.map(d=>({...d}));

document.getElementById("s-nodes").textContent = nodes.length;
document.getElementById("s-edges").textContent = edges.length;
document.getElementById("s-cves").textContent  = nodes.filter(n=>n.type==="cve").length;
document.getElementById("s-svcs").textContent  = nodes.filter(n=>n.type==="service").length;
document.getElementById("s-mal").textContent   = nodes.filter(n=>n.type==="malware").length;

const seenTypes = [...new Set(nodes.map(n=>n.type))];
const leg = document.getElementById("legend");
leg.innerHTML = '<div class="legend-title">node types</div>' +
  seenTypes.filter(t=>TYPE_CFG[t]).map(t=>
    `<div class="legend-item"><span class="legend-dot" style="background:${TYPE_CFG[t].color}"></span>${TYPE_CFG[t].label}</div>`
  ).join("");

const svg = d3.select("#graph-svg");
const g   = svg.append("g");

const zoom = d3.zoom().scaleExtent([0.15,5]).on("zoom", e=>g.attr("transform",e.transform));
svg.call(zoom);

const W = document.getElementById("graph-container").clientWidth;
const H = document.getElementById("graph-container").clientHeight;

const link = g.append("g").selectAll("line")
  .data(edges).join("line").attr("class","link");

const linkLabel = g.append("g").selectAll("text")
  .data(edges).join("text").attr("class","link-label").text(d=>d.label||"");

let labelsVisible = true;

const node = g.append("g").selectAll("g")
  .data(nodes).join("g").attr("class","node")
  .call(d3.drag()
    .on("start",(e,d)=>{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y})
    .on("drag",(e,d)=>{d.fx=e.x;d.fy=e.y})
    .on("end",(e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}));

node.append("circle")
  .attr("r", d=>(TYPE_CFG[d.type]||{r:10}).r)
  .attr("fill", d=>(TYPE_CFG[d.type]||{color:"#555"}).color)
  .attr("stroke", "#0f1117").attr("stroke-width", 2);

const labels = node.append("text").attr("class","node-label")
  .attr("dy","1.5em")
  .text(d=>d.label.length>18?d.label.slice(0,16)+"…":d.label);

const tooltip = document.getElementById("tooltip");
node.on("mouseover",(e,d)=>{
  const sc = d.score||0;
  tooltip.style.display = "block";
  tooltip.innerHTML = `
    <div class="tip-title">${d.label}</div>
    <div class="tip-type">${d.type}</div>
    ${sc>0?`<div class="tip-score" style="color:${scoreColor(sc)};font-weight:600">${sc}/100
      <div class="score-bar"><div class="score-fill" style="width:${sc}%;background:${scoreColor(sc)}"></div></div>
    </div>`:""}
    ${d.detail?`<div class="tip-detail">${d.detail}</div>`:""}`;
}).on("mousemove",e=>{
  tooltip.style.left=(e.offsetX+14)+"px";
  tooltip.style.top=(e.offsetY-10)+"px";
}).on("mouseout",()=>{tooltip.style.display="none";});

const sim = d3.forceSimulation(nodes)
  .force("link", d3.forceLink(edges).id(d=>d.id).distance(100).strength(0.5))
  .force("charge", d3.forceManyBody().strength(-320))
  .force("center", d3.forceCenter(W/2, H/2))
  .force("collision", d3.forceCollide().radius(d=>(TYPE_CFG[d.type]||{r:10}).r+20))
  .on("tick",()=>{
    link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
        .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
    linkLabel.attr("x",d=>(d.source.x+d.target.x)/2).attr("y",d=>(d.source.y+d.target.y)/2);
    node.attr("transform",d=>`translate(${d.x},${d.y})`);
  });

function resetZoom(){
  svg.transition().duration(500)
    .call(zoom.transform, d3.zoomIdentity.translate(W/2,H/2).scale(0.9).translate(-W/2,-H/2));
}

function toggleLabels(){
  labelsVisible = !labelsVisible;
  labels.style("display", labelsVisible ? null : "none");
  linkLabel.style("display", labelsVisible ? null : "none");
}

function exportPNG(){
  const svgEl = document.getElementById("graph-svg");
  const serializer = new XMLSerializer();
  const svgStr = serializer.serializeToString(svgEl);
  const blob = new Blob([svgStr], {type:"image/svg+xml"});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = "nexus-graph.svg"; a.click();
  URL.revokeObjectURL(url);
}
</script>
</body>
</html>"""

# ── Routes ─────────────────────────────────────────────────────
@app.route("/graph/store", methods=["POST"])
def store_graph():
    """Accept graph JSON from graph.sh, return a short ID."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    if data.get("secret") != GRAPH_SERVER_SECRET:
        return jsonify({"error": "Unauthorized"}), 403

    graph_data = data.get("data", {})
    if not graph_data:
        return jsonify({"error": "No graph data"}), 400

    graph_id = str(uuid.uuid4())[:8]
    store_path = GRAPH_STORE_DIR / f"{graph_id}.json"

    payload = {
        "id":        graph_id,
        "stored_at": datetime.utcnow().isoformat(),
        "expires_at":(datetime.utcnow() + timedelta(hours=MAX_AGE_HOURS)).isoformat(),
        "data":      graph_data
    }

    store_path.write_text(json.dumps(payload))
    log.info(f"Stored graph {graph_id} for target: {graph_data.get('target','?')}")

    return jsonify({
        "id":  graph_id,
        "url": f"{os.getenv('GRAPH_SERVER_URL','http://localhost:'+str(PORT))}/graph/{graph_id}",
        "expires_in_hours": MAX_AGE_HOURS
    })


@app.route("/graph/<graph_id>")
def view_graph(graph_id):
    """Serve the interactive D3 graph page."""
    # Sanitize ID
    if not re.match(r'^[a-f0-9]{8}$', graph_id):
        abort(404)

    store_path = GRAPH_STORE_DIR / f"{graph_id}.json"
    if not store_path.exists():
        abort(404)

    payload    = json.loads(store_path.read_text())
    graph_data = payload.get("data", {})

    # Check expiry
    expires_at = datetime.fromisoformat(payload.get("expires_at", "9999-01-01"))
    if datetime.utcnow() > expires_at:
        store_path.unlink(missing_ok=True)
        abort(410)  # Gone

    # Compute display values
    target    = graph_data.get("target", "unknown")
    nodes     = graph_data.get("nodes", [])
    avg_score = sum(n.get("score", 0) for n in nodes) / max(len(nodes), 1)
    score     = round(avg_score)

    risk_map  = {80:"CRITICAL", 60:"HIGH", 40:"MEDIUM", 20:"LOW"}
    risk      = "CLEAN"
    for threshold, label in sorted(risk_map.items(), reverse=True):
        if score >= threshold:
            risk = label
            break

    timestamp = datetime.fromisoformat(payload["stored_at"]).strftime("%Y-%m-%d %H:%M UTC")

    return render_template_string(
        GRAPH_TEMPLATE,
        target     = target,
        timestamp  = timestamp,
        risk       = risk,
        score      = score,
        graph_json = json.dumps(graph_data)
    )


@app.route("/health")
def health():
    graphs = list(GRAPH_STORE_DIR.glob("*.json"))
    return jsonify({
        "status":       "ok",
        "service":      "nexus-graph-server",
        "graphs_stored": len(graphs),
        "time":         datetime.utcnow().isoformat()
    })


@app.route("/")
def index():
    graphs = sorted(GRAPH_STORE_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    items  = []
    for g in graphs[:20]:
        try:
            payload = json.loads(g.read_text())
            items.append({
                "id":      payload["id"],
                "target":  payload["data"].get("target","?"),
                "stored":  payload["stored_at"][:16],
                "nodes":   payload["data"].get("node_count",0),
                "edges":   payload["data"].get("edge_count",0),
            })
        except Exception:
            pass

    rows = "".join(
        f'<tr><td><a href="/graph/{i["id"]}" style="color:#378add">{i["id"]}</a></td>'
        f'<td style="font-family:monospace">{i["target"]}</td>'
        f'<td>{i["stored"]}</td><td>{i["nodes"]}</td><td>{i["edges"]}</td></tr>'
        for i in items
    )

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>NEXUS Graph Server</title>
<style>body{{font-family:monospace;background:#0f1117;color:#94a3b8;padding:2rem}}
h1{{color:#e2e8f0;margin-bottom:1.5rem}}
table{{border-collapse:collapse;width:100%}}
th{{text-align:left;color:#64748b;font-size:12px;padding:6px 12px;border-bottom:1px solid #1e2535}}
td{{padding:6px 12px;border-bottom:1px solid #0c0f18}}
a{{color:#378add}}</style></head><body>
<h1>⬡ NEXUS Graph Server</h1>
<table><thead><tr><th>ID</th><th>Target</th><th>Stored</th><th>Nodes</th><th>Edges</th></tr></thead>
<tbody>{rows or '<tr><td colspan=5 style="color:#475569;padding:1rem">No graphs stored yet</td></tr>'}</tbody>
</table></body></html>"""


# ── Cleanup job ────────────────────────────────────────────────
def cleanup_expired():
    while True:
        time.sleep(3600)
        for g in GRAPH_STORE_DIR.glob("*.json"):
            try:
                payload    = json.loads(g.read_text())
                expires_at = datetime.fromisoformat(payload.get("expires_at","9999-01-01"))
                if datetime.utcnow() > expires_at:
                    g.unlink()
                    log.info(f"Expired graph removed: {g.name}")
            except Exception:
                pass


if __name__ == "__main__":
    import threading
    t = threading.Thread(target=cleanup_expired, daemon=True)
    t.start()
    log.info(f"NEXUS Graph Server running on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
