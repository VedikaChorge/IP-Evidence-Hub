import os, io, re, hashlib, secrets, sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from PIL import Image, ImageDraw, ImageFont
import qrcode
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import chain as chain_lib

load_dotenv()
BASE = Path(__file__).resolve().parent

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=int(os.getenv("MAX_UPLOAD_MB", "25")) * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
ALLOWED_EXTENSIONS = set(os.getenv("ALLOWED_EXTENSIONS", "pdf,png,jpg,jpeg,webp,txt,doc,docx,zip,py,js,html,css,svg").split(","))
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
TX_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
MAX_LOGIN_FAILURES, LOCKOUT = 5, timedelta(minutes=15)
STATUS_LABELS = {"local": "Not anchored", "pending": "Pending confirmation", "confirmed": "Confirmed", "failed": "Last attempt failed"}
EVIDENCE_COLUMNS = {
    "chain_status": "TEXT NOT NULL DEFAULT 'local'", "registrant_address": "TEXT DEFAULT ''",
    "onchain_recorded_at": "INTEGER DEFAULT 0", "block_number": "INTEGER DEFAULT 0",
    "root_id": "INTEGER", "parent_id": "INTEGER", "version_no": "INTEGER NOT NULL DEFAULT 1",
}
chain = chain_lib.from_env()
DB_PATH = ORIGINALS = WATERMARKS = REPORTS = None

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        with conn: yield conn
    finally:
        conn.close()

def configure(db_path, storage):
    global DB_PATH, ORIGINALS, WATERMARKS, REPORTS
    storage = Path(storage); DB_PATH = Path(db_path)
    ORIGINALS, WATERMARKS, REPORTS = storage / "originals", storage / "watermarked", storage / "reports"
    for p in (storage, ORIGINALS, WATERMARKS, REPORTS): p.mkdir(parents=True, exist_ok=True)
    init_db()

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
          email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
          title TEXT NOT NULL, description TEXT DEFAULT '', original_name TEXT NOT NULL,
          stored_name TEXT NOT NULL, sha256 TEXT NOT NULL, file_size INTEGER NOT NULL,
          mime_type TEXT DEFAULT '', created_at TEXT NOT NULL, watermark_name TEXT DEFAULT '',
          chain_network TEXT DEFAULT '', tx_hash TEXT DEFAULT '', contract_address TEXT DEFAULT '',
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS audit_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, evidence_id INTEGER,
          action TEXT NOT NULL, details TEXT DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS login_failures (
          id INTEGER PRIMARY KEY AUTOINCREMENT, attempt_key TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256);
        CREATE INDEX IF NOT EXISTS idx_login_failures_key ON login_failures(attempt_key, created_at);
        """)
        existing = {r["name"] for r in c.execute("PRAGMA table_info(evidence)")}
        for column, ddl in EVIDENCE_COLUMNS.items():
            if column not in existing: c.execute(f"ALTER TABLE evidence ADD COLUMN {column} {ddl}")
        c.execute("UPDATE evidence SET root_id=id WHERE root_id IS NULL")
        c.execute("UPDATE evidence SET chain_status='confirmed' WHERE chain_status='local' AND tx_hash<>''")
        if not c.execute("SELECT id FROM users WHERE role='admin'").fetchone():
            username = os.getenv("ADMIN_USERNAME", "admin")
            email = os.getenv("ADMIN_EMAIL", "admin@example.com")
            password = os.getenv("ADMIN_PASSWORD", "ChangeMe123!")
            c.execute("INSERT OR IGNORE INTO users(username,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                      (username, email, generate_password_hash(password), "admin", now()))
def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def utc(ts): return datetime.fromtimestamp(int(ts), timezone.utc).isoformat() if ts else ""
def allowed(filename): return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS
def log_action(user_id, evidence_id, action, details=""):
    with db() as c: c.execute("INSERT INTO audit_log(user_id,evidence_id,action,details,created_at) VALUES(?,?,?,?,?)",(user_id,evidence_id,action,details,now()))
def login_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning"); return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapped
def admin_required(f):
    @wraps(f)
    @login_required
    def wrapped(*a, **kw):
        if current_user()["role"]!="admin": abort(403)
        return f(*a, **kw)
    return wrapped
def current_user():
    if not session.get("user_id"): return None
    with db() as c: return c.execute("SELECT id,username,email,role FROM users WHERE id=?",(session["user_id"],)).fetchone()
def csrf_token():
    if "csrf" not in session: session["csrf"]=secrets.token_urlsafe(32)
    return session["csrf"]
def explorer_tx_url(e):
    return chain.network.tx_url(e["tx_hash"]) if e["tx_hash"] and e["chain_network"]==chain.network.name else ""
app.jinja_env.globals.update(csrf_token=csrf_token, explorer_tx_url=explorer_tx_url, status_labels=STATUS_LABELS)
app.jinja_env.filters["utc"]=utc
@app.context_processor
def inject_user(): return {"current_user": current_user(), "network": chain.network, "chain": chain}
@app.before_request
def csrf_protect():
    if request.method=="POST":
        sent=request.form.get("csrf_token") or request.headers.get("X-CSRF-Token","")
        expected=session.get("csrf","")
        if not sent or not expected or not secrets.compare_digest(sent,expected): abort(400)
@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options","nosniff")
    response.headers.setdefault("X-Frame-Options","DENY")
    response.headers.setdefault("Referrer-Policy","same-origin")
    response.headers.setdefault("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
                                "font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
    return response
@app.route("/")
def index():
    if session.get("user_id"): return redirect(url_for("dashboard"))
    return render_template("landing.html")
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        username=request.form.get("username","").strip()
        email=request.form.get("email","").strip().lower()
        password=request.form.get("password","")
        if len(username)<3 or len(password)<10 or "@" not in email:
            flash("Use a username of 3+ characters, a valid email, and a password of at least 10 characters.","danger")
        else:
            try:
                with db() as c:
                    c.execute("INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                              (username,email,generate_password_hash(password),now()))
                flash("Account created. Please log in.","success"); return redirect(url_for("login"))
            except sqlite3.IntegrityError: flash("Username or email already exists.","danger")
    return render_template("register.html")
def login_locked(key):
    since=(datetime.now(timezone.utc)-LOCKOUT).isoformat(timespec="seconds")
    with db() as c: n=c.execute("SELECT COUNT(*) n FROM login_failures WHERE attempt_key=? AND created_at>=?",(key,since)).fetchone()["n"]
    return n>=MAX_LOGIN_FAILURES
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        identity=request.form.get("identity","").strip()
        key=f"{request.remote_addr}|{identity.lower()}"
        if login_locked(key):
            flash("Too many failed login attempts. Try again in 15 minutes.","danger"); return render_template("login.html")
        with db() as c: user=c.execute("SELECT * FROM users WHERE username=? OR email=?",(identity,identity.lower())).fetchone()
        if user and check_password_hash(user["password_hash"],request.form.get("password","")):
            with db() as c: c.execute("DELETE FROM login_failures WHERE attempt_key=?",(key,))
            session.clear(); session.permanent=True; session["user_id"]=user["id"]
            log_action(user["id"],None,"login")
            return redirect(url_for("dashboard"))
        with db() as c: c.execute("INSERT INTO login_failures(attempt_key,created_at) VALUES(?,?)",(key,now()))
        flash("Invalid username/email or password.","danger")
    return render_template("login.html")
@app.post("/logout")
def logout():
    if session.get("user_id"): log_action(session["user_id"],None,"logout")
    session.clear(); flash("You have been logged out.","success"); return redirect(url_for("index"))
@app.route("/account/password", methods=["GET","POST"])
@login_required
def change_password():
    if request.method=="POST":
        with db() as c: user=c.execute("SELECT password_hash FROM users WHERE id=?",(session["user_id"],)).fetchone()
        new=request.form.get("new_password","")
        if not check_password_hash(user["password_hash"],request.form.get("current_password","")):
            flash("Current password is incorrect.","danger")
        elif len(new)<10: flash("The new password must be at least 10 characters.","danger")
        elif new!=request.form.get("confirm_password",""): flash("The new passwords do not match.","danger")
        else:
            with db() as c: c.execute("UPDATE users SET password_hash=? WHERE id=?",(generate_password_hash(new),session["user_id"]))
            log_action(session["user_id"],None,"password_changed")
            flash("Password changed.","success"); return redirect(url_for("dashboard"))
    return render_template("account_password.html")
@app.route("/dashboard")
@login_required
def dashboard():
    u=current_user()
    q=request.args.get("q","").strip(); status=request.args.get("status","")
    where,params=[],[]
    if u["role"]!="admin": where.append("e.user_id=?"); params.append(u["id"])
    scope_sql=" AND ".join(where) or "1=1"; scope_params=list(params)
    if q:
        like=f"%{q}%"
        where.append("(e.title LIKE ? OR e.description LIKE ? OR e.original_name LIKE ? OR e.sha256 LIKE ?)")
        params+=[like,like,like,f"{q.lower()}%"]
    if status in STATUS_LABELS: where.append("e.chain_status=?"); params.append(status)
    with db() as c:
        rows=c.execute(f"SELECT e.*,u.username FROM evidence e JOIN users u ON u.id=e.user_id WHERE {' AND '.join(where) or '1=1'} ORDER BY e.id DESC LIMIT 200",params).fetchall()
        total=c.execute(f"SELECT COUNT(*) n FROM evidence e WHERE {scope_sql}",scope_params).fetchone()["n"]
        anchored=c.execute(f"SELECT COUNT(*) n FROM evidence e WHERE {scope_sql} AND e.chain_status='confirmed'",scope_params).fetchone()["n"]
        users=c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] if u["role"]=="admin" else None
    return render_template("dashboard.html", evidence=rows, total=total, anchored=anchored, users=users, q=q, status=status)
def parent_from_request():
    parent_id=request.values.get("parent_id","").strip()
    if not parent_id: return None
    if not parent_id.isdigit(): abort(400)
    return get_owned_evidence(int(parent_id))
@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():
    parent=parent_from_request()
    if request.method=="POST":
        f=request.files.get("file"); title=request.form.get("title","").strip(); desc=request.form.get("description","").strip()
        retry=redirect(url_for("upload",parent_id=parent["id"]) if parent else url_for("upload"))
        if not f or not f.filename or not title:
            flash("Choose a file and enter a title.","danger"); return retry
        original=secure_filename(f.filename)
        if not allowed(original): flash("File extension is not allowed.","danger"); return retry
        data=f.read()
        if not data: flash("The uploaded file is empty.","danger"); return retry
        digest=hashlib.sha256(data).hexdigest()
        stored=f"{secrets.token_hex(12)}_{original}"
        (ORIGINALS/stored).write_bytes(data)
        watermark_name=""
        if (f.mimetype or "").startswith("image/"):
            try:
                im=Image.open(io.BytesIO(data)).convert("RGBA")
                overlay=Image.new("RGBA", im.size, (255,255,255,0)); draw=ImageDraw.Draw(overlay)
                text=f"IP Evidence Hub | {digest[:16]}"
                font=ImageFont.load_default()
                bbox=draw.textbbox((0,0),text,font=font)
                x=max(8,im.width-bbox[2]-16); y=max(8,im.height-bbox[3]-16)
                draw.rounded_rectangle((x-6,y-5,x+bbox[2]+6,y+bbox[3]+5),radius=5,fill=(0,0,0,130))
                draw.text((x,y),text,font=font,fill=(255,255,255,220))
                out=Image.alpha_composite(im,overlay).convert("RGB")
                watermark_name=f"wm_{stored.rsplit('.',1)[0]}.jpg"
                out.save(WATERMARKS/watermark_name,quality=92)
            except Exception: watermark_name=""
        with db() as c:
            duplicate=c.execute("SELECT id,created_at FROM evidence WHERE sha256=? ORDER BY id LIMIT 1",(digest,)).fetchone()
            root_id=parent["root_id"] if parent else None
            version=c.execute("SELECT MAX(version_no)+1 n FROM evidence WHERE root_id=?",(root_id,)).fetchone()["n"] if parent else 1
            cur=c.execute("""INSERT INTO evidence(user_id,title,description,original_name,stored_name,sha256,file_size,mime_type,created_at,watermark_name,root_id,parent_id,version_no)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",(session["user_id"],title,desc,original,stored,digest,len(data),f.mimetype or "",now(),watermark_name,root_id,parent["id"] if parent else None,version))
            eid=cur.lastrowid
            if not parent: c.execute("UPDATE evidence SET root_id=id WHERE id=?",(eid,))
        log_action(session["user_id"],eid,"evidence_uploaded",f"sha256={digest}" + (f" version={version} of #{root_id}" if parent else ""))
        if duplicate:
            flash(f"This file is identical to one already recorded as evidence #{duplicate['id']} on {duplicate['created_at'][:10]}.","warning")
        flash(f"Evidence saved. SHA-256: {digest}","success"); return redirect(url_for("evidence_detail", evidence_id=eid))
    return render_template("upload.html",parent=parent)
def get_evidence(eid, user=None):
    with db() as c: row=c.execute("SELECT e.*,u.username FROM evidence e JOIN users u ON u.id=e.user_id WHERE e.id=?",(eid,)).fetchone()
    if not row: abort(404)
    u=current_user()
    if not u or (row["user_id"] != u["id"] and u["role"]!="admin"): abort(403)
    return row
def get_owned_evidence(eid):
    row=get_evidence(eid)
    if row["user_id"]!=session.get("user_id"): abort(403)
    return row
def reference_id(e): return f"IPEH-{e['id']}"
@app.route("/evidence/<int:evidence_id>")
@login_required
def evidence_detail(evidence_id):
    e=get_evidence(evidence_id)
    path=ORIGINALS/e["stored_name"]
    current_hash=hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "MISSING"
    with db() as c:
        logs=c.execute("SELECT * FROM audit_log WHERE evidence_id=? ORDER BY id DESC",(evidence_id,)).fetchall()
        versions=c.execute("SELECT id,title,version_no,created_at,sha256 FROM evidence WHERE root_id=? ORDER BY version_no",(e["root_id"],)).fetchall()
    is_owner=e["user_id"]==session["user_id"]
    calldata=chain.calldata(e["sha256"],reference_id(e)) if is_owner and chain.configured and e["chain_status"]!="confirmed" else ""
    return render_template("evidence_detail.html",e=e,current_hash=current_hash,logs=logs,versions=versions,is_owner=is_owner,calldata=calldata)
@app.route("/evidence/<int:evidence_id>/new-version")
@login_required
def new_version(evidence_id):
    return render_template("upload.html",parent=get_owned_evidence(evidence_id))
@app.route("/evidence/<int:evidence_id>/download")
@login_required
def download(evidence_id):
    e=get_evidence(evidence_id); path=ORIGINALS/e["stored_name"]
    if not path.exists(): abort(404)
    log_action(session["user_id"],evidence_id,"original_downloaded")
    return send_file(path,as_attachment=True,download_name=e["original_name"])
@app.route("/evidence/<int:evidence_id>/watermark")
@login_required
def watermark_download(evidence_id):
    e=get_evidence(evidence_id)
    if not e["watermark_name"] or not (WATERMARKS/e["watermark_name"]).exists(): abort(404)
    log_action(session["user_id"],evidence_id,"watermarked_downloaded")
    return send_file(WATERMARKS/e["watermark_name"],as_attachment=True,download_name=e["watermark_name"])
def save_anchor(e, result):
    with db() as c:
        c.execute("""UPDATE evidence SET tx_hash=?,chain_status=?,chain_network=?,contract_address=?,registrant_address=?,onchain_recorded_at=?,block_number=?
                     WHERE id=?""",(result.tx_hash,result.status,chain.network.name,chain.contract_address,result.registrant,result.recorded_at,result.block_number,e["id"]))
    log_action(session["user_id"],e["id"],f"anchor_{result.status}",f"network={chain.network.name} tx={result.tx_hash}")
    if result.status=="confirmed": flash(f"Evidence anchored on {chain.network.name} in block {result.block_number}.","success")
    elif result.status=="pending": flash("Transaction submitted and waiting for confirmation. Use Refresh status in a moment.","warning")
    else: flash(f"Transaction {result.tx_hash} did not register this evidence in the registry contract.","danger")
def chain_failure(action):
    app.logger.exception("MST %s failed", action)
    flash("Could not complete the request on the MST network. Check the RPC, contract address and signer balance, then try again.","danger")
@app.post("/evidence/<int:evidence_id>/anchor/server")
@login_required
def anchor_server(evidence_id):
    e=get_owned_evidence(evidence_id); back=redirect(url_for("evidence_detail",evidence_id=evidence_id))
    if e["chain_status"] in ("confirmed","pending"): flash("This evidence already has an on-chain transaction.","warning"); return back
    if not chain.server_signer: flash("Server signing is not configured. Use MetaMask, or set CONTRACT_ADDRESS and MST_SIGNER_PRIVATE_KEY.","danger"); return back
    try:
        existing=chain.lookup(e["sha256"])
        if existing:
            flash(f"This file hash is already registered on-chain since {utc(existing.recorded_at)} by {existing.registrant}.","danger"); return back
        result=chain.register(e["sha256"],reference_id(e))
    except Exception:
        chain_failure("server anchoring"); return back
    save_anchor(e,result); return back
@app.post("/evidence/<int:evidence_id>/anchor/wallet")
@login_required
def anchor_wallet(evidence_id):
    e=get_owned_evidence(evidence_id); back=redirect(url_for("evidence_detail",evidence_id=evidence_id))
    tx_hash=request.form.get("tx_hash","").strip()
    if not TX_RE.match(tx_hash): flash("Invalid transaction hash.","danger"); return back
    if e["chain_status"]=="confirmed": flash("This evidence is already anchored.","warning"); return back
    if not chain.configured: flash("No registry contract is configured.","danger"); return back
    try: result=chain.verify(tx_hash.lower(),e["sha256"],timeout=45)
    except Exception:
        chain_failure("wallet transaction verification"); return back
    save_anchor(e,result); return back
@app.post("/evidence/<int:evidence_id>/anchor/refresh")
@login_required
def anchor_refresh(evidence_id):
    e=get_owned_evidence(evidence_id); back=redirect(url_for("evidence_detail",evidence_id=evidence_id))
    if not e["tx_hash"] or e["chain_status"]=="confirmed": return back
    try: result=chain.verify(e["tx_hash"],e["sha256"],timeout=10)
    except Exception:
        chain_failure("status refresh"); return back
    save_anchor(e,result); return back
@app.route("/verify", methods=["GET","POST"])
def verify():
    result=None
    if request.method=="POST":
        f=request.files.get("file"); claimed=request.form.get("sha256","").strip().lower()
        if f and f.filename:
            digest=hashlib.sha256(f.read()).hexdigest()
            result={"hash":digest,"matches":bool(claimed and secrets.compare_digest(digest,claimed)),"claimed":claimed}
        else: flash("Select a file to hash.","warning")
    return render_template("verify.html",result=result)
@app.route("/lookup", methods=["GET","POST"])
def lookup():
    digest=None; records=[]; onchain=None; chain_error=False
    if request.method=="POST":
        f=request.files.get("file")
        if f and f.filename: digest=hashlib.sha256(f.read()).hexdigest()
        else: flash("Select a file to look up.","warning")
    else:
        raw=request.args.get("sha256","").strip().lower()
        if raw and HASH_RE.match(raw): digest=raw
        elif raw: flash("A SHA-256 hash is 64 hexadecimal characters.","danger")
    if digest:
        with db() as c: records=c.execute("SELECT id,title,created_at,chain_status FROM evidence WHERE sha256=? ORDER BY id",(digest,)).fetchall()
        if chain.configured:
            try: onchain=chain.lookup(digest)
            except Exception:
                app.logger.exception("MST lookup failed"); chain_error=True
    return render_template("lookup.html",digest=digest,records=records,onchain=onchain,chain_error=chain_error)
@app.route("/evidence/<int:evidence_id>/report")
@login_required
def report(evidence_id):
    e=get_evidence(evidence_id)
    verify_url=request.url_root.rstrip("/") + url_for("public_verify", evidence_id=evidence_id)
    qr=qrcode.make(verify_url); qr_path=REPORTS/f"qr_{evidence_id}.png"; qr.save(qr_path)
    path=REPORTS/f"evidence_{evidence_id}.pdf"
    c=canvas.Canvas(str(path),pagesize=A4); w,h=A4
    c.setTitle(f"IP Evidence Certificate {evidence_id}")
    c.setFont("Helvetica-Bold",20); c.drawString(48,h-58,"IP Evidence Hub")
    c.setFont("Helvetica-Bold",14); c.drawString(48,h-90,"Evidence Integrity Certificate")
    c.setFont("Helvetica",10)
    fields=[("Evidence ID",str(e["id"])),("Title",e["title"]),("Version",str(e["version_no"])),("Submitted by",e["username"]),("Original filename",e["original_name"]),
            ("Recorded (UTC)",e["created_at"]),("File size",f'{e["file_size"]} bytes'),("SHA-256",e["sha256"]),
            ("Blockchain status",STATUS_LABELS.get(e["chain_status"],e["chain_status"])),("Network",e["chain_network"] or "Local-only")]
    if e["tx_hash"]: fields+=[("Transaction",e["tx_hash"]),("Contract",e["contract_address"])]
    if e["chain_status"]=="confirmed":
        fields+=[("On-chain time (UTC)",utc(e["onchain_recorded_at"])),("Block",str(e["block_number"])),("Registrant",e["registrant_address"])]
    y=h-130
    for label,value in fields:
        c.setFont("Helvetica-Bold",9); c.drawString(48,y,label+":")
        c.setFont("Helvetica",9)
        chunks=[value[i:i+85] for i in range(0,len(value),85)] or [""]
        c.drawString(150,y,chunks[0]); y-=16
        for chunk in chunks[1:]: c.drawString(150,y,chunk); y-=13
    c.drawImage(ImageReader(str(qr_path)),w-145,65,width=90,height=90, preserveAspectRatio=True,mask="auto")
    c.setFont("Helvetica",8); c.drawString(48,82,"Scan QR code to view public integrity status.")
    c.drawString(48,65,"This certificate records a hash; it is not a legal ownership determination.")
    c.save()
    log_action(session["user_id"],evidence_id,"report_generated")
    return send_file(path,as_attachment=True,download_name=f"IP_Evidence_{evidence_id}.pdf")
@app.route("/public/verify/<int:evidence_id>")
def public_verify(evidence_id):
    with db() as c: e=c.execute("""SELECT id,title,original_name,sha256,file_size,created_at,version_no,chain_network,chain_status,tx_hash,contract_address,
                                   registrant_address,onchain_recorded_at,block_number FROM evidence WHERE id=?""",(evidence_id,)).fetchone()
    if not e: abort(404)
    return render_template("public_verify.html",e=e)
@app.route("/admin/users")
@admin_required
def admin_users():
    with db() as c: users=c.execute("SELECT id,username,email,role,created_at FROM users ORDER BY id").fetchall()
    return render_template("admin_users.html",users=users)
@app.post("/admin/users/<int:user_id>/role")
@admin_required
def admin_set_role(user_id):
    role=request.form.get("role","")
    if role not in ("user","admin"): abort(400)
    if user_id==session["user_id"]: flash("You cannot change your own role.","danger"); return redirect(url_for("admin_users"))
    with db() as c:
        target=c.execute("SELECT username FROM users WHERE id=?",(user_id,)).fetchone()
        if not target: abort(404)
        c.execute("UPDATE users SET role=? WHERE id=?",(role,user_id))
    log_action(session["user_id"],None,"role_changed",f"user={target['username']} role={role}")
    flash(f"{target['username']} is now {role}.","success"); return redirect(url_for("admin_users"))
@app.route("/admin/audit")
@admin_required
def admin_audit():
    action=request.args.get("action","")
    with db() as c:
        actions=[r["action"] for r in c.execute("SELECT DISTINCT action FROM audit_log ORDER BY action")]
        sql="SELECT a.*,u.username FROM audit_log a LEFT JOIN users u ON u.id=a.user_id"
        rows=c.execute(sql+(" WHERE a.action=?" if action else "")+" ORDER BY a.id DESC LIMIT 300",(action,) if action else ()).fetchall()
    return render_template("admin_audit.html",rows=rows,actions=actions,action=action)
@app.route("/health")
def health(): return {"status":"ok","network":chain.network.key,"chain_id":chain.network.chain_id,"contract_configured":chain.configured}
configure(BASE / os.getenv("DATABASE_PATH", "ip_evidence.db"), BASE / os.getenv("STORAGE_PATH", "storage"))
if __name__=="__main__":
    app.run(host=os.getenv("HOST","127.0.0.1"),port=int(os.getenv("PORT","5000")),debug=os.getenv("FLASK_DEBUG","false").lower()=="true")
