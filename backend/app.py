# app.py (paste this replacing your current app.py)
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import os, re, json, sqlite3, socket, ipaddress, time
from urllib.parse import urlparse
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "viruscan.db")

app = Flask(__name__)
CORS(app)

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute("""
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_type TEXT NOT NULL,
      target_value TEXT NOT NULL,
      label TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      reasons TEXT NOT NULL,
      solutions TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    """)
    db.commit()

@app.before_request
def _ensure_db():
    init_db()

SUSPICIOUS_KEYWORDS = ["verify","secure","login","update","gift","free","bonus","bank","paypal","apple","support","reset","wallet"]
BAD_TLDS = [".tk",".ru",".zip",".xyz",".click",".top",".country",".loan",".kim",".work"]

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 30
_rate_store = {}

def too_many_requests(ip):
    now = time.time()
    arr = _rate_store.get(ip, [])
    arr = [t for t in arr if t > now - RATE_LIMIT_WINDOW]
    arr.append(now)
    _rate_store[ip] = arr
    return len(arr) > RATE_LIMIT_MAX

def bar(v:int):
    return max(0, min(100, int(v)))

def score_to_label(score:int)->str:
    if score >= 70: return "Dangerous"
    if score >= 35: return "Warning"
    return "Safe"

def gen_solutions(reasons:list):
    out = []
    out.append({"title":"Enforce HTTPS (TLS 1.2+)", "details":"Redirect HTTP→HTTPS and enable HSTS; use Let's Encrypt.","effectiveness":85,"difficulty":30,"time_minutes":30})
    out.append({"title":"Parameter sanitization & WAF", "details":"Validate inputs server-side and apply WAF rules to block suspicious patterns.","effectiveness":80,"difficulty":45,"time_minutes":90})
    out.append({"title":"Phishing wording & brand checks", "details":"Remove deceptive words and any brand impersonation.","effectiveness":60,"difficulty":25,"time_minutes":45})
    return out

def is_private_address(hostname):
    try:
        addrs = set()
        for res in socket.getaddrinfo(hostname, None):
            addrs.add(res[4][0])
        for a in addrs:
            ip = ipaddress.ip_address(a)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True
        return False
    except Exception:
        return True

def analyze_url(u:str):
    reasons = []
    risk = 0
    try:
        parsed = urlparse(u if "://" in u else "http://" + u)
    except Exception:
        reasons.append("Invalid URL format")
        return {"label":"Dangerous","risk_score":95,"reasons":reasons,"solutions":gen_solutions(reasons)}

    host = (parsed.netloc or "").lower()
    scheme = (parsed.scheme or "").lower()
    path_q = (parsed.path or "") + (("?" + parsed.query) if parsed.query else "")

    if not host or is_private_address(host):
        reasons.append("Blocked internal/private host")
        return {"label":"Dangerous","risk_score":95,"reasons":reasons,"solutions":gen_solutions(reasons)}

    if scheme != "https":
        reasons.append("No HTTPS")
        risk += 25

    for tld in BAD_TLDS:
        if host.endswith(tld):
            reasons.append(f"Suspicious top-level domain ({tld})")
            risk += 20
            break

    if re.search(r"\d{4,}", host) or len(re.findall(r"\d", host)) >= 6:
        reasons.append("High randomness in domain")
        risk += 10

    if len(path_q) > 40 and re.search(r"[0-9A-Za-z]{16,}", path_q.replace("/","")):
        reasons.append("High randomness in URL structure")
        risk += 10

    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in (host+path_q)]
    if found_kw:
        reasons.append("Contains suspicious keywords: " + ", ".join(sorted(set(found_kw))[:4]))
        risk += 20

    if any(b in host for b in ["paypal","apple","meta","microsoft","bank"]):
        reasons.append("Possible brand impersonation")
        risk += 15

    risk = bar(risk)
    label = score_to_label(risk)
    solutions = gen_solutions(reasons)
    return {"label":label, "risk_score":risk, "reasons":reasons, "solutions":solutions}

def analyze_app(pkg:str):
    reasons = []
    risk = 0
    if not re.fullmatch(r"[a-zA-Z]{2,}(?:\.[a-zA-Z0-9_]{2,}){1,}", pkg or ""):
        reasons.append("Invalid package name format")
        risk += 40

    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in (pkg or "").lower()]
    if found_kw:
        reasons.append("Suspicious keywords in package name: " + ", ".join(sorted(set(found_kw))[:4]))
        risk += 20

    if pkg.count(".") >= 5:
        reasons.append("Unusual package depth")
        risk += 10
    if re.search(r"[0-9]{3,}", pkg):
        reasons.append("High randomness in package")
        risk += 10

    risk = bar(risk)
    label = score_to_label(risk)
    solutions = [
        {"title":"Code signing & provenance checks","details":"Verify developer signature; avoid sideloading.","effectiveness":80,"difficulty":35,"time_minutes":45},
        {"title":"Runtime permissions audit","details":"Review dangerous permissions; enforce scoped storage.","effectiveness":70,"difficulty":45,"time_minutes":90},
        {"title":"Static analysis & obfuscation","details":"Run MobSF and inspect network endpoints.","effectiveness":65,"difficulty":55,"time_minutes":120}
    ]
    return {"label":label, "risk_score":risk, "reasons":reasons, "solutions":solutions}

@app.post("/api/scan/url")
def scan_url():
    client_ip = request.remote_addr or "unknown"
    if too_many_requests(client_ip):
        return jsonify({"error":"rate limit exceeded"}), 429

    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error":"Missing url"}), 400

    res = analyze_url(url)
    db = get_db()
    cur = db.execute(
        "INSERT INTO scans(target_type,target_value,label,risk_score,reasons,solutions,created_at) VALUES(?,?,?,?,?,?,?)",
        ("url", url, res["label"], res["risk_score"], json.dumps(res["reasons"]), json.dumps(res["solutions"]), datetime.utcnow().isoformat())
    )
    db.commit()
    scan_id = cur.lastrowid
    return jsonify({"scan_id": scan_id, "target_type":"url", "target_value": url, **res}), 201

@app.post("/api/scan/app")
def scan_app():
    client_ip = request.remote_addr or "unknown"
    if too_many_requests(client_ip):
        return jsonify({"error":"rate limit exceeded"}), 429

    data = request.get_json(force=True, silent=True) or {}
    pkg = (data.get("package") or "").strip()
    if not pkg:
        return jsonify({"error":"Missing package"}), 400

    res = analyze_app(pkg)
    db = get_db()
    cur = db.execute(
        "INSERT INTO scans(target_type,target_value,label,risk_score,reasons,solutions,created_at) VALUES(?,?,?,?,?,?,?)",
        ("app", pkg, res["label"], res["risk_score"], json.dumps(res["reasons"]), json.dumps(res["solutions"]), datetime.utcnow().isoformat())
    )
    db.commit()
    scan_id = cur.lastrowid
    return jsonify({"scan_id": scan_id, "target_type":"app", "target_value": pkg, **res}), 201

@app.get("/api/history")
def history():
    db = get_db()
    rows = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "target_type": r["target_type"],
            "target_value": r["target_value"],
            "label": r["label"],
            "risk_score": r["risk_score"],
            "reasons": json.loads(r["reasons"]),
            "solutions": json.loads(r["solutions"]),
            "created_at": r["created_at"]
        })
    return jsonify(items)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)
