from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_migrate import Migrate
import os, re, socket, ipaddress, time
from urllib.parse import urlparse
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from config import config
from models import db, Scan, Feedback, ContactMessage, User

app = Flask(__name__)
app.config.from_object(config[os.getenv('FLASK_ENV', 'development')])

CORS(app, supports_credentials=True)
db.init_app(app)
migrate = Migrate(app, db)

# Rate limiting store
_rate_store = {}

# Constants
SUSPICIOUS_KEYWORDS = [
    "verify", "secure", "login", "update", "gift", "free", "bonus",
    "bank", "paypal", "apple", "support", "reset", "wallet"
]
BAD_TLDS = [
    ".tk", ".ru", ".zip", ".xyz", ".click", ".top", ".country",
    ".loan", ".kim", ".work"
]

def too_many_requests(ip):
    """Rate limiting check"""
    now = time.time()
    window = app.config['RATE_LIMIT_WINDOW']
    max_requests = app.config['RATE_LIMIT_MAX']
    
    arr = _rate_store.get(ip, [])
    arr = [t for t in arr if t > now - window]
    arr.append(now)
    _rate_store[ip] = arr
    return len(arr) > max_requests

def bar(v: int):
    """Clamp value between 0-100"""
    return max(0, min(100, int(v)))

def score_to_label(score: int) -> str:
    """Convert risk score to label"""
    if score >= 70: return "Dangerous"
    if score >= 35: return "Warning"
    return "Safe"

def gen_solutions(reasons: list, target_type: str):
    """Generate remediation solutions"""
    if target_type == "url":
        return [
            {
                "title": "Enforce HTTPS (TLS 1.2+)",
                "details": "Redirect HTTP→HTTPS and enable HSTS; use Let's Encrypt.",
                "effectiveness": 85,
                "difficulty": 30,
                "time_minutes": 30
            },
            {
                "title": "Parameter sanitization & WAF",
                "details": "Validate inputs server-side and apply WAF rules to block suspicious patterns.",
                "effectiveness": 80,
                "difficulty": 45,
                "time_minutes": 90
            },
            {
                "title": "Phishing wording & brand checks",
                "details": "Remove deceptive words and any brand impersonation.",
                "effectiveness": 60,
                "difficulty": 25,
                "time_minutes": 45
            }
        ]
    else:  # app
        return [
            {
                "title": "Code signing & provenance checks",
                "details": "Verify developer signature; avoid sideloading.",
                "effectiveness": 80,
                "difficulty": 35,
                "time_minutes": 45
            },
            {
                "title": "Runtime permissions audit",
                "details": "Review dangerous permissions; enforce scoped storage.",
                "effectiveness": 70,
                "difficulty": 45,
                "time_minutes": 90
            },
            {
                "title": "Static analysis & obfuscation",
                "details": "Run MobSF and inspect network endpoints.",
                "effectiveness": 65,
                "difficulty": 55,
                "time_minutes": 120
            }
        ]

def is_private_address(hostname):
    """Check if hostname resolves to private IP (SSRF protection)"""
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

def analyze_url(u: str):
    """Analyze URL for threats"""
    reasons = []
    risk = 0
    
    try:
        parsed = urlparse(u if "://" in u else "http://" + u)
    except Exception:
        reasons.append("Invalid URL format")
        return {
            "label": "Dangerous",
            "risk_score": 95,
            "reasons": reasons,
            "solutions": gen_solutions(reasons, "url")
        }
    
    host = (parsed.netloc or "").lower()
    scheme = (parsed.scheme or "").lower()
    path_q = (parsed.path or "") + (("?" + parsed.query) if parsed.query else "")
    
    # SSRF protection
    if not host or is_private_address(host):
        reasons.append("Blocked internal/private host")
        return {
            "label": "Dangerous",
            "risk_score": 95,
            "reasons": reasons,
            "solutions": gen_solutions(reasons, "url")
        }
    
    # Protocol check
    if scheme != "https":
        reasons.append("No HTTPS")
        risk += 25
    
    # TLD check
    for tld in BAD_TLDS:
        if host.endswith(tld):
            reasons.append(f"Suspicious top-level domain ({tld})")
            risk += 20
            break
    
    # Domain randomness
    if re.search(r"\d{4,}", host) or len(re.findall(r"\d", host)) >= 6:
        reasons.append("High randomness in domain")
        risk += 10
    
    # URL structure randomness
    if len(path_q) > 40 and re.search(r"[0-9A-Za-z]{16,}", path_q.replace("/", "")):
        reasons.append("High randomness in URL structure")
        risk += 10
    
    # Suspicious keywords
    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in (host + path_q)]
    if found_kw:
        reasons.append("Contains suspicious keywords: " + ", ".join(sorted(set(found_kw))[:4]))
        risk += 20
    
    # Brand impersonation
    if any(b in host for b in ["paypal", "apple", "meta", "microsoft", "bank"]):
        reasons.append("Possible brand impersonation")
        risk += 15
    
    risk = bar(risk)
    label = score_to_label(risk)
    solutions = gen_solutions(reasons, "url")
    
    return {
        "label": label,
        "risk_score": risk,
        "reasons": reasons,
        "solutions": solutions
    }

def analyze_app(pkg: str):
    """Analyze Android package for threats"""
    reasons = []
    risk = 0
    
    # Package format validation
    if not re.fullmatch(r"[a-zA-Z]{2,}(?:\.[a-zA-Z0-9_]{2,}){1,}", pkg or ""):
        reasons.append("Invalid package name format")
        risk += 40
    
    # Suspicious keywords
    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in (pkg or "").lower()]
    if found_kw:
        reasons.append("Suspicious keywords in package name: " + ", ".join(sorted(set(found_kw))[:4]))
        risk += 20
    
    # Package depth
    if pkg.count(".") >= 5:
        reasons.append("Unusual package depth")
        risk += 10
    
    # Randomness
    if re.search(r"[0-9]{3,}", pkg):
        reasons.append("High randomness in package")
        risk += 10
    
    risk = bar(risk)
    label = score_to_label(risk)
    solutions = gen_solutions(reasons, "app")
    
    return {
        "label": label,
        "risk_score": risk,
        "reasons": reasons,
        "solutions": solutions
    }

# ========== USER AUTHENTICATION ENDPOINTS ==========

@app.post("/api/users/register")
def register_user():
    """Register a new user"""
    data = request.get_json(force=True, silent=True) or {}
    
    email = (data.get("email") or "").strip().lower()
    full_name = (data.get("full_name") or "").strip()
    phone = (data.get("phone") or "").strip()
    password = data.get("password", "")
    
    # Validation
    if not email or not full_name or not password:
        return jsonify({"error": "Email, full name, and password are required"}), 400
    
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    # Check if email already exists
    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({"error": "Email already registered"}), 409
    
    # Create user
    user = User(
        email=email,
        full_name=full_name,
        phone=phone,
        password_hash=generate_password_hash(password),
        is_admin=False
    )
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        "message": "Account created successfully",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name
        }
    }), 201

@app.post("/api/users/login")
def login_user():
    """Login user"""
    data = request.get_json(force=True, silent=True) or {}
    
    email = (data.get("email") or "").strip().lower()
    password = data.get("password", "")
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    # Find user
    user = User.query.filter_by(email=email).first()
    
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 401
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Store user in session
    session['user_id'] = user.id
    session['user_email'] = user.email
    session['is_admin'] = user.is_admin
    
    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": user.is_admin
        }
    }), 200

@app.post("/api/admin/login")
def admin_login():
    """Admin login"""
    data = request.get_json(force=True, silent=True) or {}
    
    email = (data.get("email") or "").strip().lower()
    password = data.get("password", "")
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    # Find admin user
    user = User.query.filter_by(email=email, is_admin=True).first()
    
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid admin credentials"}), 401
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Store admin in session
    session['user_id'] = user.id
    session['user_email'] = user.email
    session['is_admin'] = True
    
    return jsonify({
        "message": "Admin login successful",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": True
        }
    }), 200

@app.post("/api/users/logout")
def logout_user():
    """Logout user"""
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200

@app.get("/api/users/me")
def get_current_user():
    """Get current logged-in user"""
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "phone": user.phone,
        "is_admin": user.is_admin
    }), 200

# ========== SCAN ENDPOINTS ==========

@app.post("/api/scan/url")
def scan_url():
    """Scan a URL"""
    client_ip = request.remote_addr or "unknown"
    
    if too_many_requests(client_ip):
        return jsonify({"error": "rate limit exceeded"}), 429
    
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    
    if not url:
        return jsonify({"error": "Missing url"}), 400
    
    # Analyze
    res = analyze_url(url)
    
    # Save to database
    scan = Scan(
        target_type="url",
        target_value=url,
        label=res["label"],
        risk_score=res["risk_score"],
        reasons=res["reasons"],
        solutions=res["solutions"],
        client_ip=client_ip
    )
    db.session.add(scan)
    db.session.commit()
    
    return jsonify({
        "scan_id": scan.id,
        "target_type": "url",
        "target_value": url,
        **res
    }), 201

@app.post("/api/scan/app")
def scan_app():
    """Scan an Android app package"""
    client_ip = request.remote_addr or "unknown"
    
    if too_many_requests(client_ip):
        return jsonify({"error": "rate limit exceeded"}), 429
    
    data = request.get_json(force=True, silent=True) or {}
    pkg = (data.get("package") or "").strip()
    
    if not pkg:
        return jsonify({"error": "Missing package"}), 400
    
    # Analyze
    res = analyze_app(pkg)
    
    # Save to database
    scan = Scan(
        target_type="app",
        target_value=pkg,
        label=res["label"],
        risk_score=res["risk_score"],
        reasons=res["reasons"],
        solutions=res["solutions"],
        client_ip=client_ip
    )
    db.session.add(scan)
    db.session.commit()
    
    return jsonify({
        "scan_id": scan.id,
        "target_type": "app",
        "target_value": pkg,
        **res
    }), 201

@app.get("/api/history")
def history():
    """Get scan history"""
    limit = request.args.get('limit', 100, type=int)
    limit = min(limit, 500)  # Max 500
    
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(limit).all()
    return jsonify([scan.to_dict() for scan in scans])

@app.post("/api/feedback")
def submit_feedback():
    """Submit user feedback"""
    data = request.get_json(force=True, silent=True) or {}
    
    user_name = data.get("user_name", "Guest")
    rating = data.get("rating")
    comment = data.get("comment", "")
    
    if not rating or not (1 <= int(rating) <= 5):
        return jsonify({"error": "Invalid rating (1-5)"}), 400
    
    feedback = Feedback(
        user_name=user_name,
        rating=int(rating),
        comment=comment
    )
    db.session.add(feedback)
    db.session.commit()
    
    return jsonify({"message": "Feedback submitted", "id": feedback.id}), 201

@app.get("/api/feedback")
def get_feedback():
    """Get all feedback"""
    feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).limit(100).all()
    return jsonify([fb.to_dict() for fb in feedbacks])

@app.post("/api/contact")
def submit_contact():
    """Submit contact message"""
    data = request.get_json(force=True, silent=True) or {}
    
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    message = data.get("message", "").strip()
    
    if not name or not email or not message:
        return jsonify({"error": "All fields required"}), 400
    
    contact = ContactMessage(
        name=name,
        email=email,
        message=message
    )
    db.session.add(contact)
    db.session.commit()
    
    return jsonify({"message": "Message sent", "id": contact.id}), 201

# ========== ADMIN ENDPOINTS ==========

@app.get("/api/admin/users")
def get_all_users():
    """Get all users (admin only)"""
    if not session.get('is_admin'):
        return jsonify({"error": "Admin access required"}), 403
    
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify([{
        "id": u.id,
        "email": u.email,
        "full_name": u.full_name,
        "phone": u.phone,
        "is_admin": u.is_admin,
        "created_at": u.created_at.isoformat(),
        "last_login": u.last_login.isoformat() if u.last_login else None
    } for u in users])

@app.get("/api/admin/stats")
def admin_stats():
    """Admin dashboard statistics"""
    total_users = User.query.count()
    total_scans = Scan.query.count()
    total_feedback = Feedback.query.count()
    total_contacts = ContactMessage.query.count()
    
    scans_today = Scan.query.filter(
        db.func.date(Scan.created_at) == datetime.utcnow().date()
    ).count()
    
    return jsonify({
        "total_users": total_users,
        "total_scans": total_scans,
        "total_feedback": total_feedback,
        "total_contacts": total_contacts,
        "scans_today": scans_today
    })

@app.route("/health")
def health():
    """Health check endpoint"""
    try:
        db.session.execute(db.text('SELECT 1'))
        return jsonify({"status": "healthy", "database": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)