from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_migrate import Migrate
import os, re, socket, ipaddress, time
from urllib.parse import urlparse
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from config import config
from models import db, Scan, Feedback, ContactMessage, User

app = Flask(__name__)
app.config.from_object(config[os.getenv('FLASK_ENV', 'development')])

# --- NEW/FIXED CORS CONFIGURATION ---
CORS(app, 
     origins=[
         "http://127.0.0.1:5500", 
         "http://localhost:5500"
     ], 
     supports_credentials=True,
     # This explicitly allows the headers your front-end needs
     allow_headers=["Content-Type", "Authorization"] 
)
# ------------------------------------

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

# Add OPTIONS handler for all routes
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# DECORATORS
def login_required(f):
    """Require user to be logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Require user to be admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
        if not session.get('is_admin', False):
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# UTILITY FUNCTIONS
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
    else:
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
    
    if not host or is_private_address(host):
        reasons.append("Blocked internal/private host")
        return {
            "label": "Dangerous",
            "risk_score": 95,
            "reasons": reasons,
            "solutions": gen_solutions(reasons, "url")
        }
    
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
    
    if len(path_q) > 40 and re.search(r"[0-9A-Za-z]{16,}", path_q.replace("/", "")):
        reasons.append("High randomness in URL structure")
        risk += 10
    
    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in (host + path_q)]
    if found_kw:
        reasons.append("Contains suspicious keywords: " + ", ".join(sorted(set(found_kw))[:4]))
        risk += 20
    
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
    solutions = gen_solutions(reasons, "app")
    
    return {
        "label": label,
        "risk_score": risk,
        "reasons": reasons,
        "solutions": solutions
    }

# ========== AUTHENTICATION ENDPOINTS ==========

@app.route("/api/users/register", methods=["POST", "OPTIONS"])
def register_user():
    """Register a new user"""
    if request.method == "OPTIONS":
        return "", 204
    
    try:
        data = request.get_json(force=True, silent=True) or {}
        
        email = (data.get("email") or "").strip().lower()
        full_name = (data.get("full_name") or "").strip()
        phone = (data.get("phone") or "").strip()
        password = data.get("password", "")
        
        if not email or not full_name or not password:
            return jsonify({"error": "Email, full name, and password are required"}), 400
        
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        
        existing = User.query.filter_by(email=email).first()
        if existing:
            return jsonify({"error": "Email already registered"}), 409
        
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
            "success": True,
            "message": "Account created successfully",
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "is_admin": False
            }
        }), 201
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/users/login", methods=["POST", "OPTIONS"])
def login_user():
    """Login user"""
    if request.method == "OPTIONS":
        return "", 204
    
    try:
        data = request.get_json(force=True, silent=True) or {}
        
        email = (data.get("email") or "").strip().lower()
        password = data.get("password", "")
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Invalid email or password"}), 401
        
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        session.clear()
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['user_name'] = user.full_name
        session['is_admin'] = user.is_admin
        session.permanent = True
        
        return jsonify({
            "success": True,
            "message": "Login successful",
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "is_admin": user.is_admin
            }
        }), 200
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/login", methods=["POST", "OPTIONS"])
def admin_login():
    """Admin login"""
    if request.method == "OPTIONS":
        return "", 204
    
    try:
        data = request.get_json(force=True, silent=True) or {}
        
        email = (data.get("email") or "").strip().lower()
        password = data.get("password", "")
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({"error": "Invalid admin credentials"}), 401
        
        if not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Invalid admin credentials"}), 401
        
        if not user.is_admin:
            return jsonify({"error": "Admin access required"}), 403
        
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        session.clear()
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['user_name'] = user.full_name
        session['is_admin'] = True
        session.permanent = True
        
        return jsonify({
            "success": True,
            "message": "Admin login successful",
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "is_admin": True
            }
        }), 200
    except Exception as e:
        print(f"Admin login error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/users/logout", methods=["POST", "OPTIONS"])
def logout_user():
    """Logout user"""
    if request.method == "OPTIONS":
        return "", 204
    session.clear()
    return jsonify({"success": True, "message": "Logged out successfully"}), 200

@app.route("/api/users/me", methods=["GET", "OPTIONS"])
def get_current_user():
    """Get current logged-in user"""
    if request.method == "OPTIONS":
        return "", 204
    
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401
    
    user = User.query.get(user_id)
    if not user:
        session.clear()
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "phone": user.phone,
        "is_admin": user.is_admin
    }), 200

@app.route("/api/session/check", methods=["GET", "OPTIONS"])
def check_session():
    """Check if user session is valid"""
    if request.method == "OPTIONS":
        return "", 204
    
    if 'user_id' in session:
        return jsonify({
            "authenticated": True,
            "is_admin": session.get('is_admin', False),
            "user_id": session.get('user_id'),
            "user_name": session.get('user_name')
        }), 200
    else:
        return jsonify({"authenticated": False}), 401

# ========== SCAN ENDPOINTS ==========

@app.route("/api/scan/url", methods=["POST", "OPTIONS"])
def scan_url():
    """Scan a URL"""
    if request.method == "OPTIONS":
        return "", 204
    
    client_ip = request.remote_addr or "unknown"
    
    if too_many_requests(client_ip):
        return jsonify({"error": "rate limit exceeded"}), 429
    
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    
    if not url:
        return jsonify({"error": "Missing url"}), 400
    
    res = analyze_url(url)
    
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

@app.route("/api/scan/app", methods=["POST", "OPTIONS"])
def scan_app():
    """Scan an Android app package"""
    if request.method == "OPTIONS":
        return "", 204
    
    client_ip = request.remote_addr or "unknown"
    
    if too_many_requests(client_ip):
        return jsonify({"error": "rate limit exceeded"}), 429
    
    data = request.get_json(force=True, silent=True) or {}
    pkg = (data.get("package") or "").strip()
    
    if not url:
        return jsonify({"error": "Missing package"}), 400
    
    res = analyze_app(pkg)
    
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

@app.route("/api/history", methods=["GET", "OPTIONS"])
def history():
    """Get scan history"""
    if request.method == "OPTIONS":
        return "", 204
    
    limit = request.args.get('limit', 100, type=int)
    limit = min(limit, 500)
    
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(limit).all()
    return jsonify([scan.to_dict() for scan in scans])

@app.route("/api/feedback", methods=["GET", "POST", "OPTIONS"])
def feedback_route():
    """Handle feedback"""
    if request.method == "OPTIONS":
        return "", 204
    
    if request.method == "POST":
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
    
    else:  # GET
        feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).limit(100).all()
        return jsonify([fb.to_dict() for fb in feedbacks])

@app.route("/api/contact", methods=["POST", "OPTIONS"])
def submit_contact():
    """Submit contact message"""
    if request.method == "OPTIONS":
        return "", 204
    
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

@app.route("/api/admin/users", methods=["GET", "OPTIONS"])
@admin_required
def get_all_users():
    """Get all users (admin only)"""
    if request.method == "OPTIONS":
        return "", 204
    
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

@app.route("/api/admin/stats", methods=["GET", "OPTIONS"])
@admin_required
def admin_stats():
    """Admin dashboard statistics"""
    if request.method == "OPTIONS":
        return "", 204
    
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

@app.route("/api/test", methods=["GET", "OPTIONS"])
def test():
    """Test endpoint to verify backend is running"""
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({"message": "Backend is running!", "timestamp": datetime.utcnow().isoformat()}), 200

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Starting ViruScan AI Backend")
    print("=" * 60)
    print(f"📍 API Base URL: http://127.0.0.1:8000")
    print(f"🔧 Test endpoint: http://127.0.0.1:8000/api/test")
    print(f"❤️  Health check: http://127.0.0.1:8000/health")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=8000)