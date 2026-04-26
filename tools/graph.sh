#!/bin/bash
# NEXUS — Link Graph Generator
# Collects all entity relationships and outputs JSON for the D3 visualizer
# Usage: bash graph.sh <ip|domain> [--open]

TARGET="$1"
OPEN_FLAG="$2"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRAPH_DIR=~/.openclaw/nexus_graphs
mkdir -p "$GRAPH_DIR"

DATE_SLUG=$(date '+%Y%m%d_%H%M%S')
GRAPH_JSON="$GRAPH_DIR/${TARGET//[.\/]/_}_$DATE_SLUG.json"
GRAPH_HTML="$GRAPH_DIR/${TARGET//[.\/]/_}_$DATE_SLUG.html"

if [ -z "$TARGET" ]; then
  echo "Usage: graph.sh <ip|domain> [--open]"
  exit 1
fi

IS_IP=$(echo "$TARGET" | grep -cP '^\d{1,3}(\.\d{1,3}){3}$')

echo "🕸  NEXUS Link Graph: $TARGET"
echo "─────────────────────────────────────"

# ── Collect nodes and edges ────────────────────────────────────
python3 - <<'PYEOF'
import json, subprocess, os, re, sys

target  = "$TARGET"
is_ip   = bool($IS_IP)
vt_key  = os.environ.get('VIRUSTOTAL_API_KEY','')
sh_key  = os.environ.get('SHODAN_API_KEY','')
ab_key  = os.environ.get('ABUSEIPDB_API_KEY','')

try:
    import urllib.request, urllib.error
    def fetch(url, headers={}):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                return json.loads(r.read())
        except:
            return {}
except:
    def fetch(url, headers={}):
        return {}

nodes = []
edges = []
node_ids = set()

def add_node(id_, label, type_, score=0, detail=""):
    if id_ not in node_ids:
        node_ids.add(id_)
        nodes.append({"id": id_, "label": label, "type": type_,
                       "score": score, "detail": detail})

def add_edge(source, target, label=""):
    edges.append({"source": source, "target": target, "label": label})

# Root node
add_node(target, target, "target", detail="Primary target")

# ── VirusTotal ──────────────────────────────────────────────────
if vt_key:
    endpoint = "ip_addresses" if is_ip else "domains"
    vt = fetch(f"https://www.virustotal.com/api/v3/{endpoint}/{target}",
               {"x-apikey": vt_key})
    attrs = vt.get("data", {}).get("attributes", {})

    mal  = attrs.get("last_analysis_stats", {}).get("malicious", 0)
    score = min(100, mal * 4)

    add_node("vt_node", "VirusTotal", "intel_source", score, f"{mal} malicious detections")
    add_edge(target, "vt_node", f"{mal} detections")

    # ASN
    asn = attrs.get("asn") or attrs.get("network")
    if asn:
        asn_id = f"asn_{asn}"
        add_node(asn_id, f"ASN {asn}", "asn", detail=attrs.get("as_owner",""))
        add_edge(target, asn_id, "belongs to")

    # Country
    country = attrs.get("country")
    if country:
        cid = f"country_{country}"
        add_node(cid, country, "country")
        add_edge(target, cid, "located in")

    # Resolutions (domain → IPs or IP → hostnames)
    if not is_ip:
        # Get subdomains
        subs = fetch(f"https://www.virustotal.com/api/v3/domains/{target}/subdomains?limit=5",
                     {"x-apikey": vt_key})
        for item in subs.get("data", [])[:5]:
            sub_id = item.get("id","")
            if sub_id:
                add_node(sub_id, sub_id, "subdomain")
                add_edge(target, sub_id, "subdomain of")

        # Resolutions
        res = fetch(f"https://www.virustotal.com/api/v3/domains/{target}/resolutions?limit=5",
                    {"x-apikey": vt_key})
        for item in res.get("data", [])[:5]:
            ip_val = item.get("attributes",{}).get("ip_address","")
            if ip_val:
                add_node(ip_val, ip_val, "ip")
                add_edge(target, ip_val, "resolves to")
    else:
        # IP hostnames
        for hn in attrs.get("last_dns_records",[])[:5]:
            if hn.get("type") == "PTR":
                hname = hn.get("value","")
                if hname:
                    add_node(hname, hname, "hostname")
                    add_edge(target, hname, "PTR record")

    # Communicating files (malware that talks to this host)
    comms = fetch(f"https://www.virustotal.com/api/v3/{endpoint}/{target}/communicating_files?limit=3",
                  {"x-apikey": vt_key})
    for item in comms.get("data", [])[:3]:
        fid   = item.get("id","")[:16]
        fname = item.get("attributes",{}).get("names",["unknown"])[0] if item.get("attributes",{}).get("names") else fid
        fmal  = item.get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0)
        if fid:
            add_node(f"file_{fid}", fname[:20], "malware", score=min(100,fmal*4), detail=f"hash:{fid}")
            add_edge(target, f"file_{fid}", "C2 for")

# ── Shodan ─────────────────────────────────────────────────────
if sh_key:
    if is_ip:
        sh = fetch(f"https://api.shodan.io/shodan/host/{target}?key={sh_key}")
    else:
        resolved = fetch(f"https://api.shodan.io/dns/resolve?hostnames={target}&key={sh_key}")
        ip_val   = list(resolved.values())[0] if resolved else None
        sh       = fetch(f"https://api.shodan.io/shodan/host/{ip_val}?key={sh_key}") if ip_val else {}

    # Open ports as nodes
    for svc in sh.get("data", [])[:8]:
        port    = svc.get("port", 0)
        product = svc.get("product", "unknown")
        pid     = f"port_{port}"
        add_node(pid, f":{port} {product[:12]}", "service",
                 detail=f"{product} {svc.get('version','')}")
        add_edge(target, pid, "exposes")

    # CVEs
    for cve_id in list(sh.get("vulns", {}).keys())[:6]:
        add_node(cve_id, cve_id, "cve", score=70, detail="Known vulnerability")
        add_edge(target, cve_id, "vulnerable to")

    # Tags
    for tag in sh.get("tags", []):
        tid = f"tag_{tag}"
        add_node(tid, tag, "tag")
        add_edge(target, tid, "tagged")

    # Org
    org = sh.get("org")
    if org:
        oid = f"org_{org[:20]}"
        add_node(oid, org[:20], "org", detail=sh.get("isp",""))
        add_edge(target, oid, "hosted by")

# ── AbuseIPDB (IP only) ────────────────────────────────────────
if ab_key and is_ip:
    import urllib.parse
    ab = fetch(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={target}&maxAgeInDays=90",
        {"Key": ab_key, "Accept": "application/json"}
    )
    ab_data  = ab.get("data", {})
    ab_score = ab_data.get("abuseConfidenceScore", 0)
    ab_reps  = ab_data.get("totalReports", 0)
    ab_tor   = ab_data.get("isTor", False)

    add_node("abuseipdb_node", "AbuseIPDB", "intel_source",
             score=ab_score, detail=f"{ab_reps} reports")
    add_edge(target, "abuseipdb_node", f"score: {ab_score}%")

    if ab_tor:
        add_node("tor_network", "Tor Network", "infrastructure")
        add_edge(target, "tor_network", "exit node")

    # Report categories as nodes
    reports = ab_data.get("reports", [])
    cat_counts = {}
    for rep in reports[:20]:
        for cat in rep.get("categories", []):
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

    cat_names = {
        3:"Fraud",4:"DDoS",9:"Open Proxy",10:"Web Spam",
        11:"Email Spam",14:"Port Scan",15:"Hacking",
        16:"SQL Injection",17:"Spoofing",18:"Brute Force",
        19:"Bad Bot",20:"Exploited Host",21:"Web App Attack",
        22:"SSH",23:"IoT Targeted"
    }
    for cat_id, count in sorted(cat_counts.items(), key=lambda x:-x[1])[:5]:
        cname = cat_names.get(cat_id, f"Category {cat_id}")
        cnode = f"cat_{cat_id}"
        add_node(cnode, cname, "abuse_category", score=min(100,count*10),
                 detail=f"{count} reports")
        add_edge(target, cnode, f"{count}x reported")

# ── Output JSON ────────────────────────────────────────────────
output = {
    "target": target,
    "is_ip": is_ip,
    "node_count": len(nodes),
    "edge_count": len(edges),
    "nodes": nodes,
    "edges": edges
}
print(json.dumps(output, indent=2))
PYEOF
