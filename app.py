import hashlib
import os
from functools import wraps

from flask import Flask, render_template, request, redirect, session, send_from_directory, abort
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename

from config import Config
from database.models import db, User, File, AuditLog

app = Flask(__name__)
app.config.from_object(Config)
# secret_key now comes from Config (which loads it from .env) — no more hardcoded string here

db.init_app(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)  # protects every POST form against CSRF by default

os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)


# ---------------- AUTH DECORATORS ---------------- #
# Small helpers so every route doesn't repeat the same "if user not in session" check,
# and so the admin check can never accidentally be skipped or written wrong again.

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")

        user = User.query.filter_by(username=session["user"]).first()

        if not user or user.role != "Admin":
            abort(403)

        return view(*args, **kwargs)
    return wrapped


# ---------------- HELPER FUNCTIONS ---------------- #

def log_action(username, action):
    log = AuditLog(
        username=username,
        action=action
    )

    db.session.add(log)
    db.session.commit()


def calculate_sha256(filepath):

    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(4096)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def validate_password(password):

    if len(password) < 8:
        return "Password must be at least 8 characters long."

    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."

    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."

    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number."

    if not any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
        return "Password must contain at least one special character."

    return None


# ---------------- HOME ---------------- #

@app.route("/")
def home():
    return "<h1>Welcome to SecureVault 🔒</h1>"


# ---------------- REGISTER ---------------- #

@app.route("/register", methods=["GET", "POST"])
def register():

    error = None

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        error = validate_password(password)

        if error:
            return render_template("register.html", error=error)

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            return render_template(
                "register.html",
                error="Username already exists."
            )

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        new_user = User(
            username=username,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect("/login")

    return render_template("register.html", error=error)


# ---------------- LOGIN ---------------- #

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session["user"] = user.username

            log_action(user.username, "Logged In")

            return redirect("/dashboard")

        return "Invalid Username or Password"

    return render_template("login.html")


# ---------------- DASHBOARD ---------------- #

@app.route("/dashboard")
@login_required
def dashboard():

    user = User.query.filter_by(username=session["user"]).first()

    total_users = User.query.count()
    total_files = File.query.count()
    total_logs = AuditLog.query.count()

    return render_template(
        "dashboard.html",
        username=user.username,
        role=user.role,
        total_users=total_users,
        total_files=total_files,
        total_logs=total_logs
    )


# ---------------- FILE UPLOAD ---------------- #

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():

    user = User.query.filter_by(username=session["user"]).first()

    if request.method == "POST":

        file = request.files["file"]

        if file:

            filename = secure_filename(file.filename)

            filepath = os.path.join(Config.UPLOAD_FOLDER, filename)

            file.save(filepath)

            file_hash = calculate_sha256(filepath)

            new_file = File(
                filename=filename,
                owner=session["user"],
                file_hash=file_hash
            )

            db.session.add(new_file)
            db.session.commit()

            log_action(session["user"], f"Uploaded {filename}")

            return "File Uploaded Successfully"

    return render_template("upload.html", role=user.role)


# ---------------- MY FILES ---------------- #

@app.route("/files")
@login_required
def files():

    user = User.query.filter_by(username=session["user"]).first()

    user_files = File.query.filter_by(owner=session["user"]).all()

    return render_template(
        "files.html",
        files=user_files,
        role=user.role
    )


# ---------------- DOWNLOAD ---------------- #

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):

    file = File.query.get_or_404(file_id)

    if file.owner != session["user"]:
        return "Access Denied"

    filepath = os.path.join(Config.UPLOAD_FOLDER, file.filename)

    current_hash = calculate_sha256(filepath)

    if current_hash != file.file_hash:

        log_action(session["user"], f"Integrity Check Failed: {file.filename}")

        return "<h2>❌ Integrity Check Failed! File has been modified.</h2>"

    log_action(session["user"], f"Downloaded {file.filename}")

    return send_from_directory(
        Config.UPLOAD_FOLDER,
        file.filename,
        as_attachment=True
    )


# ---------------- ADMIN ---------------- #

@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html")


# ---------------- MAKE ADMIN ---------------- #
# Now locked behind @admin_required — only an existing Admin can promote someone else.
# (Before, this was a public URL anyone could hit to become Admin instantly.)

@app.route("/make_admin/<username>")
@admin_required
def make_admin(username):

    user = User.query.filter_by(username=username).first()

    if user:
        user.role = "Admin"
        db.session.commit()
        log_action(session["user"], f"Promoted {username} to Admin")
        return f"{username} is now Admin"

    return "User not found"


# ---------------- LOGOUT ---------------- #

@app.route("/logout")
def logout():

    if "user" in session:
        log_action(session["user"], "Logged Out")

    session.clear()

    return redirect("/login")


# ---------------- MAIN ---------------- #

if __name__ == "__main__":

    with app.app_context():
        # db.drop_all() removed — this used to wipe every user, file, and log on every restart.
        # create_all() only builds tables that don't exist yet, so your data survives restarts.
        db.create_all()

    app.run(debug=Config.DEBUG)
