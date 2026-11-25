from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, secrets, hmac, getpass
from functools import wraps

app = Flask(__name__)
# This classroom prototype is not approved for public deployment.
if os.environ.get("RENDER"):
    raise RuntimeError("Local prototype only; faculty security review required")
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
DB = os.path.join(os.path.dirname(__file__), "mentorship.db")

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('student','mentor','admin')),
          department TEXT DEFAULT '', year TEXT DEFAULT '',
          interests TEXT DEFAULT '', goals TEXT DEFAULT '',
          availability TEXT DEFAULT '', skills TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS requests(
          id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL,
          mentor_id INTEGER NOT NULL, message TEXT DEFAULT '',
          status TEXT DEFAULT 'pending',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(student_id) REFERENCES users(id),
          FOREIGN KEY(mentor_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS meetings(
          id INTEGER PRIMARY KEY AUTOINCREMENT, request_id INTEGER NOT NULL,
          meeting_date TEXT NOT NULL, topic TEXT NOT NULL, notes TEXT DEFAULT '',
          FOREIGN KEY(request_id) REFERENCES requests(id)
        );
        CREATE TABLE IF NOT EXISTS feedback(
          id INTEGER PRIMARY KEY AUTOINCREMENT, request_id INTEGER NOT NULL,
          from_user INTEGER NOT NULL, rating INTEGER NOT NULL,
          comments TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(request_id) REFERENCES requests(id),
          FOREIGN KEY(from_user) REFERENCES users(id)
        );
        """)
        columns = {r["name"] for r in c.execute("PRAGMA table_info(users)")}
        if "verified" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")
        password = os.environ.get("ADMIN_PASSWORD")
        if not password:
            password = getpass.getpass("Set faculty demo admin password (16+ characters): ")
        if len(password) < 16:
            raise ValueError("Admin password is too short")
        admin = c.execute("SELECT id,role,password FROM users WHERE email=?", ("admin@mentorship.local",)).fetchone()
        if admin:
            if admin["role"] != "admin":
                raise RuntimeError("Reserved administrator email collision")
            if not check_password_hash(admin["password"], password):
                c.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(password), admin["id"]))
        else:
            c.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)", ("System Admin", "admin@mentorship.local", generate_password_hash(password), "admin"))
        c.execute("""CREATE TABLE IF NOT EXISTS video_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meeting_id INTEGER NOT NULL UNIQUE REFERENCES meetings(id) ON DELETE CASCADE,
            status TEXT NOT NULL DEFAULT 'pending'
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE, sender_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")

@app.before_request
def csrf_guard():
    session.setdefault("csrf", secrets.token_hex(32))
    if request.method == "POST" and not hmac.compare_digest(session["csrf"], request.form.get("csrf", "")):
        return "Invalid form token. Refresh and try again.", 400

@app.route("/chat/<int:req_id>", methods=["GET", "POST"])
def chat(req_id):
    uid = session.get("user_id")
    with db() as c:
        current = c.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
        connection = c.execute("""SELECT r.*, s.name student_name, m.name mentor_name FROM requests r JOIN users s ON s.id=r.student_id JOIN users m ON m.id=r.mentor_id WHERE r.id=? AND r.status='accepted' AND m.verified=1""", (req_id,)).fetchone()
        if not current or not connection or (current['role'] != 'admin' and uid not in (connection['student_id'], connection['mentor_id'])):
            return "Access denied", 403
        if request.method == 'POST':
            if current['role'] == 'admin': return "Read-only faculty review", 403
            body = request.form.get('body','').strip()
            if 0 < len(body) <= 2000:
                c.execute("INSERT INTO messages(request_id,sender_id,body) VALUES(?,?,?)", (req_id,uid,body))
            return redirect(url_for('chat',req_id=req_id))
        rows = c.execute("SELECT messages.*, users.name FROM messages JOIN users ON users.id=sender_id WHERE request_id=? ORDER BY messages.id",(req_id,)).fetchall()
    return render_template('chat.html', connection=connection, rows=rows, faculty=current['role']=='admin')

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        with db() as c:
            current = c.execute("SELECT id,role FROM users WHERE id=?", (session.get("user_id"),)).fetchone()
        if not current:
            session.clear()
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        session["role"] = current["role"]
        return fn(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                flash("You do not have permission to view that page.", "danger")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapper
    return deco

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name=request.form.get("name","").strip()
        email=request.form.get("email","").strip().lower()
        password=request.form.get("password","")
        role=request.form.get("role","student")
        if not name or not email or len(password) < 8 or role not in ("student","mentor"):
            flash("Enter all details. Password must be at least 8 characters.", "danger")
            return render_template("register.html")
        try:
            with db() as c:
                c.execute("INSERT INTO users(name,email,password,role,department,year,interests,goals,availability,skills) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (name,email,generate_password_hash(password),role,
                     request.form.get("department",""),request.form.get("year",""),
                     request.form.get("interests",""),request.form.get("goals",""),
                     request.form.get("availability",""),request.form.get("skills","")))
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email address is already registered.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email=request.form.get("email","").strip().lower()
        password=request.form.get("password","")
        with db() as c:
            user=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        if user and check_password_hash(user["password"],password):
            session.clear()
            session.update(user_id=user["id"],name=user["name"],role=user["role"])
            return redirect(url_for("dashboard"))
        flash("Incorrect email or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    with db() as c:
        user=c.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
        if user["role"] == "admin":
            stats = {
              "students": c.execute("SELECT COUNT(*) FROM users WHERE role='student'").fetchone()[0],
              "mentors": c.execute("SELECT COUNT(*) FROM users WHERE role='mentor'").fetchone()[0],
              "requests": c.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
              "meetings": c.execute("SELECT COUNT(*) FROM meetings").fetchone()[0]}
            return render_template("dashboard.html", user=user, stats=stats)
        if user["role"] == "student":
            items=c.execute("""SELECT r.*,u.name AS other_name,u.department,u.year,u.skills
                FROM requests r JOIN users u ON u.id=r.mentor_id
                WHERE r.student_id=? ORDER BY r.created_at DESC""",(user["id"],)).fetchall()
        else:
            items=c.execute("""SELECT r.*,u.name AS other_name,u.department,u.year,u.skills
                FROM requests r JOIN users u ON u.id=r.student_id
                WHERE r.mentor_id=? ORDER BY r.created_at DESC""",(user["id"],)).fetchall()
        uid = user["id"]
        meeting_rows = c.execute("""SELECT m.*, CASE WHEN r.student_id=? THEN me.name ELSE st.name END AS other_name
            FROM meetings m JOIN requests r ON r.id=m.request_id
            JOIN users st ON st.id=r.student_id JOIN users me ON me.id=r.mentor_id
            WHERE (r.student_id=? OR r.mentor_id=?) AND r.status='accepted'
            ORDER BY m.meeting_date DESC""", (uid,uid,uid)).fetchall()
        rating = c.execute("""SELECT AVG(f.rating) FROM feedback f JOIN requests r ON r.id=f.request_id
            WHERE (r.student_id=? OR r.mentor_id=?) AND f.from_user<>? AND r.status='accepted'""",(uid,uid,uid)).fetchone()[0]
        sent_feedback = c.execute("SELECT COUNT(*) FROM feedback WHERE from_user=?",(uid,)).fetchone()[0]
    active = sum(r['status']=='accepted' for r in items)
    pending = sum(r['status']=='pending' for r in items)
    milestones = [('Profile completed', bool(user['department'] and user['interests'])), ('Connection accepted', bool(active)), ('Meeting recorded', bool(meeting_rows)), ('Feedback submitted', bool(sent_feedback))]
    progress = 25 * sum(done for _,done in milestones)
    return render_template("dashboard.html",user=user,items=items,meeting_rows=meeting_rows,active=active,pending=pending,rating=rating,milestones=milestones,progress=progress)

@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    with db() as c:
        if request.method == "POST":
            c.execute("""UPDATE users SET department=?,year=?,interests=?,goals=?,availability=?,skills=?
                         WHERE id=?""",
                (request.form.get("department",""),request.form.get("year",""),
                 request.form.get("interests",""),request.form.get("goals",""),
                 request.form.get("availability",""),request.form.get("skills",""),
                 session["user_id"]))
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
        user=c.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    return render_template("profile.html",user=user)

def compatibility(student, mentor):
    # Simple explainable score: interests (50), goals/skills (30), availability (20).
    si=set(x.strip().lower() for x in (student["interests"] or "").split(",") if x.strip())
    mi=set(x.strip().lower() for x in ((mentor["interests"] or "") + "," + (mentor["skills"] or "")).split(",") if x.strip())
    shared=len(si & mi)
    interest= min(50, shared * 25) if si else 0
    sg=set(x.strip().lower() for x in (student["goals"] or "").split(",") if x.strip())
    mg=set(x.strip().lower() for x in (mentor["skills"] or "").split(",") if x.strip())
    goal= min(30, len(sg & mg) * 15) if sg else 0
    sa=(student["availability"] or "").lower()
    ma=(mentor["availability"] or "").lower()
    avail=20 if sa and ma and any(x.strip() and x.strip() in ma for x in sa.split(",")) else 0
    return min(100, interest+goal+avail)

@app.route("/matches")
@login_required
@role_required("student")
def matches():
    with db() as c:
        student=c.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
        mentors=c.execute("SELECT * FROM users WHERE role='mentor' AND verified=1").fetchall()
        sent=[r["mentor_id"] for r in c.execute("SELECT mentor_id FROM requests WHERE student_id=?",(student["id"],)).fetchall()]
    results=sorted([(m,compatibility(student,m)) for m in mentors],key=lambda x:x[1],reverse=True)
    return render_template("matches.html",results=results,sent=sent)

@app.route("/request/<int:mentor_id>", methods=["POST"])
@login_required
@role_required("student")
def send_request(mentor_id):
    with db() as c:
        mentor=c.execute("SELECT id FROM users WHERE id=? AND role='mentor' AND verified=1",(mentor_id,)).fetchone()
        if not mentor:
            flash("Mentor not found.", "danger")
        else:
            exists=c.execute("SELECT id FROM requests WHERE student_id=? AND mentor_id=? AND status IN ('pending','accepted')",
                             (session["user_id"],mentor_id)).fetchone()
            if exists:
                flash("You already have an active request with this mentor.", "warning")
            else:
                c.execute("INSERT INTO requests(student_id,mentor_id,message) VALUES(?,?,?)",
                          (session["user_id"],mentor_id,request.form.get("message","")))
                flash("Mentorship invitation sent.", "success")
    return redirect(url_for("matches"))

@app.route("/request/<int:req_id>/<action>", methods=["POST"])
@login_required
@role_required("mentor")
def update_request(req_id,action):
    with db() as c:
        approved = c.execute("SELECT verified FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if not approved or not approved["verified"]:
        flash("Faculty approval is required.", "warning")
        return redirect(url_for("dashboard"))
    if action not in ("accepted","rejected"):
        return redirect(url_for("dashboard"))
    with db() as c:
        c.execute("UPDATE requests SET status=? WHERE id=? AND mentor_id=? AND status='pending'",
                  (action,req_id,session["user_id"]))
    flash("Request updated.", "success")
    return redirect(url_for("dashboard"))

@app.route("/meetings", methods=["GET","POST"])
@login_required
def meetings():
    with db() as c:
        if request.method=="POST":
            req_id=request.form.get("request_id")
            allowed=c.execute("""SELECT id FROM requests WHERE id=? AND status='accepted'
                AND (student_id=? OR mentor_id=?)""",(req_id,session["user_id"],session["user_id"])).fetchone()
            if allowed:
                c.execute("INSERT INTO meetings(request_id,meeting_date,topic,notes) VALUES(?,?,?,?)",
                    (req_id,request.form.get("meeting_date"),request.form.get("topic"),request.form.get("notes","")))
                flash("Meeting log saved.", "success")
            else:
                flash("Choose an accepted mentorship connection.", "danger")
        rows=c.execute("""SELECT m.*,s.name AS student_name,me.name AS mentor_name, (SELECT status FROM video_requests WHERE meeting_id=m.id) AS video_status
            FROM meetings m JOIN requests r ON r.id=m.request_id
            JOIN users s ON s.id=r.student_id JOIN users me ON me.id=r.mentor_id
            WHERE r.student_id=? OR r.mentor_id=? ORDER BY m.meeting_date DESC""",
            (session["user_id"],session["user_id"])).fetchall()
        accepted=c.execute("""SELECT r.id,s.name AS student_name,me.name AS mentor_name
            FROM requests r JOIN users s ON s.id=r.student_id JOIN users me ON me.id=r.mentor_id
            WHERE r.status='accepted' AND (r.student_id=? OR r.mentor_id=?)""",
            (session["user_id"],session["user_id"])).fetchall()
    return render_template("meetings.html",rows=rows,accepted=accepted)

@app.route("/feedback", methods=["GET","POST"])
@login_required
def feedback():
    with db() as c:
        if request.method=="POST":
            req_id=request.form.get("request_id")
            allowed=c.execute("""SELECT id FROM requests WHERE id=? AND status='accepted'
                AND (student_id=? OR mentor_id=?)""",(req_id,session["user_id"],session["user_id"])).fetchone()
            if allowed:
                rating=request.form.get("rating", type=int, default=0)
                if 1 <= rating <= 5:
                    c.execute("INSERT INTO feedback(request_id,from_user,rating,comments) VALUES(?,?,?,?)",
                              (req_id,session["user_id"],rating,request.form.get("comments","")))
                    flash("Thank you for your feedback.", "success")
            else:
                flash("Feedback is available only for accepted connections.", "danger")
        rows=c.execute("""SELECT f.*,u.name AS author FROM feedback f JOIN users u ON u.id=f.from_user
            JOIN requests r ON r.id=f.request_id WHERE r.student_id=? OR r.mentor_id=?
            ORDER BY f.created_at DESC""",(session["user_id"],session["user_id"])).fetchall()
        accepted=c.execute("""SELECT r.id,s.name AS student_name,me.name AS mentor_name
            FROM requests r JOIN users s ON s.id=r.student_id JOIN users me ON me.id=r.mentor_id
            WHERE r.status='accepted' AND (r.student_id=? OR r.mentor_id=?)""",
            (session["user_id"],session["user_id"])).fetchall()
    return render_template("feedback.html",rows=rows,accepted=accepted)

@app.route("/admin")
@login_required
@role_required("admin")
def admin():
    session.setdefault("review_token", secrets.token_hex(32))
    with db() as c:
        users=c.execute("SELECT id,name,email,role,department,verified FROM users ORDER BY role,name").fetchall()
        requests_=c.execute("""SELECT r.*,s.name AS student_name,m.name AS mentor_name
            FROM requests r JOIN users s ON s.id=r.student_id JOIN users m ON m.id=r.mentor_id
            ORDER BY r.created_at DESC""").fetchall()
        video_requests = c.execute("""SELECT v.*,m.topic,m.meeting_date FROM video_requests v JOIN meetings m ON m.id=v.meeting_id ORDER BY v.id DESC""").fetchall()
    return render_template("admin.html",users=users,requests=requests_,video_requests=video_requests)

@app.route("/admin/verify-mentor/<int:user_id>", methods=["POST"])
@login_required
@role_required("admin")
def verify_mentor(user_id):
    with db() as c:
        c.execute("UPDATE users SET verified=1 WHERE id=? AND role='mentor'", (user_id,))
    flash("Mentor approved for demo.", "success")
    return redirect(url_for("admin"))

# Local demonstration only: video requests are recorded for faculty review.
# Actual conferencing is managed by the institution, not this app.
@app.route("/video-request/<int:meeting_id>", methods=["POST"])
@login_required
@role_required("student", "mentor")
def video_request(meeting_id):
    with db() as c:
        allowed = c.execute("""SELECT m.id FROM meetings m
            JOIN requests r ON r.id=m.request_id
            JOIN users u ON u.id=r.mentor_id
            WHERE m.id=? AND r.status='accepted' AND u.verified=1
            AND (r.student_id=? OR r.mentor_id=?)""",
            (meeting_id, session["user_id"], session["user_id"])).fetchone()
        if allowed:
            c.execute("INSERT OR IGNORE INTO video_requests(meeting_id) VALUES(?)", (meeting_id,))
            flash("Video session requested. Faculty must arrange the supervised meeting.", "success")
        else:
            flash("An approved mentorship connection is required.", "danger")
    return redirect(url_for("meetings"))

@app.route("/admin/video-review/<int:request_id>", methods=["POST"])
@login_required
@role_required("admin")
def review_video(request_id):
    token = session.get("review_token", "")
    if not token or not hmac.compare_digest(token, request.form.get("review_token", "")):
        return "Invalid review token", 400
    decision = request.form.get("decision")
    if decision not in ("approved", "rejected"):
        return "Invalid decision", 400
    with db() as c:
        result = c.execute("UPDATE video_requests SET status=? WHERE id=? AND status='pending'", (decision, request_id))
        changed = result.rowcount
    flash("Review saved." if changed else "Request already reviewed or not found.", "success" if changed else "warning")
    return redirect(url_for("admin"))


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@login_required
@role_required("admin")
def delete_user(user_id):
    if user_id == session["user_id"]:
        flash("You cannot delete your own admin account.", "danger")
    else:
        with db() as c:
            c.execute("DELETE FROM messages WHERE request_id IN (SELECT id FROM requests WHERE student_id=? OR mentor_id=?)",(user_id,user_id))
            c.execute("DELETE FROM feedback WHERE request_id IN (SELECT id FROM requests WHERE student_id=? OR mentor_id=?)",(user_id,user_id))
            c.execute("DELETE FROM meetings WHERE request_id IN (SELECT id FROM requests WHERE student_id=? OR mentor_id=?)",(user_id,user_id))
            c.execute("DELETE FROM requests WHERE student_id=? OR mentor_id=?",(user_id,user_id))
            c.execute("DELETE FROM users WHERE id=?",(user_id,))
        flash("User deleted.", "success")
    return redirect(url_for("admin"))

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html",message="Page not found."),404

init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
