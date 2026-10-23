

import os
import hashlib
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# App configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)

SECRET_KEY_FILE = os.path.join(BASE_DIR, ".secret_key")
secret_key = os.environ.get("SECRET_KEY")

if not secret_key:
    try:
        with open(SECRET_KEY_FILE, "r", encoding="utf-8") as key_file:
            secret_key = key_file.read().strip()
    except FileNotFoundError:
        secret_key = secrets.token_hex(32)
        with open(SECRET_KEY_FILE, "w", encoding="utf-8") as key_file:
            key_file.write(secret_key)
        try:
            os.chmod(SECRET_KEY_FILE, 0o600)
        except OSError:
            pass

app.config["SECRET_KEY"] = secret_key
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + os.path.join(BASE_DIR, "trustvault.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {
    "pdf", "txt", "doc", "docx", "png", "jpg", "jpeg", "csv", "xlsx"
}


def now_utc():
    return datetime.now(timezone.utc)


# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    company = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(500), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)

    user = db.relationship("User", backref="audit_events")


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    company = db.Column(db.String(100), nullable=False)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=now_utc)

    owner = db.relationship("User", backref="owned_documents")


class DocumentShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer, db.ForeignKey("document.id"), nullable=False
    )
    recipient_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    granted_by_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)

    document = db.relationship("Document", backref="shares")
    recipient = db.relationship("User", foreign_keys=[recipient_id])
    granted_by = db.relationship("User", foreign_keys=[granted_by_id])

    __table_args__ = (
        db.UniqueConstraint(
            "document_id",
            "recipient_id",
            name="unique_document_share",
        ),
    )


# Helper functions
def log_action(action, details=""):
    user_id = session.get("user_id")
    db.session.add(
        AuditLog(
            user_id=user_id,
            action=action,
            details=details[:500],
        )
    )
    db.session.commit()


def current_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


# Login protection
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            session.clear()
            flash("Please sign in first.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


# Admin-only protection
def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()

        if user is None:
            session.clear()
            flash("Please sign in first.")
            return redirect(url_for("login"))

        if user.role != "admin":
            abort(403)

        return view(*args, **kwargs)

    return wrapped


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def get_accessible_document(document_id, user):
    document = db.session.get(Document, document_id)

    if document is None or document.company != user.company:
        abort(404)

    if document.owner_id == user.id:
        return document

    share = DocumentShare.query.filter_by(
        document_id=document.id,
        recipient_id=user.id,
    ).first()

    if share is None:
        abort(403)

    return document


# Home
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        company = request.form.get("company", "").strip()

        if not all([name, email, password, company]):
            flash("Please complete every field.")

        elif len(password) < 10:
            flash("Password must be at least 10 characters.")

        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.")

        else:
            user = User(
                name=name,
                email=email,
                password_hash=generate_password_hash(password),
                company=company,
                role="user",
            )

            db.session.add(user)
            db.session.commit()

            session.clear()
            session["user_id"] = user.id

            log_action("REGISTER", f"Account created: {email}")
            return redirect(url_for("dashboard"))

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id

            log_action("LOGIN", f"Signed in: {email}")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")


# Logout
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_action("LOGOUT", "User signed out")
    session.clear()
    flash("You have signed out.")
    return redirect(url_for("login"))


# User dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()

    owned_documents = Document.query.filter_by(
        owner_id=user.id,
        company=user.company,
    ).order_by(Document.uploaded_at.desc()).all()

    shared_rows = (
        DocumentShare.query.join(Document)
        .filter(
            DocumentShare.recipient_id == user.id,
            Document.company == user.company,
        )
        .order_by(DocumentShare.created_at.desc())
        .all()
    )

    return render_template(
        "dashboard.html",
        user=user,
        documents=owned_documents,
        shared_rows=shared_rows,
    )


# Upload document
@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    user = current_user()
    uploaded = request.files.get("document")

    if uploaded is None or not uploaded.filename:
        flash("Please choose a file to upload.")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(uploaded.filename)

    if not original_name or not allowed_file(original_name):
        flash("That file type is not allowed.")
        return redirect(url_for("dashboard"))

    stored_name = secrets.token_hex(16) + "_" + original_name
    destination = os.path.join(
        app.config["UPLOAD_FOLDER"], stored_name
    )

    try:
        uploaded.save(destination)
        digest = sha256_file(destination)

        document = Document(
            filename=original_name,
            stored_filename=stored_name,
            sha256_hash=digest,
            owner_id=user.id,
            company=user.company,
        )

        db.session.add(document)
        db.session.commit()

        log_action(
            "DOCUMENT_UPLOAD",
            f"Uploaded document ID {document.id}",
        )
        flash("Document uploaded successfully.")

    except Exception:
        db.session.rollback()

        if os.path.exists(destination):
            os.remove(destination)

        app.logger.exception("Document upload failed")
        flash("Upload failed. Please try again.")

    return redirect(url_for("dashboard"))


# Download document
@app.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    user = current_user()
    document = get_accessible_document(document_id, user)

    log_action(
        "DOCUMENT_DOWNLOAD",
        f"Downloaded document ID {document.id}",
    )

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document.stored_filename,
        as_attachment=True,
        download_name=document.filename,
    )


# Verify document integrity
@app.route("/documents/<int:document_id>/verify")
@login_required
def verify_document(document_id):
    user = current_user()
    document = get_accessible_document(document_id, user)

    path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document.stored_filename,
    )

    if not os.path.isfile(path):
        flash("Stored file is missing.")
        log_action(
            "INTEGRITY_CHECK_FAILED",
            f"Missing file ID {document.id}",
        )
        return redirect(url_for("dashboard"))

    actual_hash = sha256_file(path)
    valid = secrets.compare_digest(
        actual_hash,
        document.sha256_hash,
    )

    log_action(
        "INTEGRITY_CHECK",
        f"Document ID {document.id}: {'PASS' if valid else 'FAIL'}",
    )

    if valid:
        flash(
            "Integrity check passed: file matches its saved SHA-256 hash."
        )
    else:
        flash(
            "WARNING: integrity check failed; the file hash has changed."
        )

    return redirect(url_for("dashboard"))


# Share document
@app.route("/documents/<int:document_id>/share", methods=["POST"])
@login_required
def share_document(document_id):
    user = current_user()

    document = Document.query.filter_by(
        id=document_id,
        owner_id=user.id,
        company=user.company,
    ).first_or_404()

    email = request.form.get("email", "").strip().lower()

    recipient = User.query.filter_by(
        email=email,
        company=user.company,
    ).first()

    if recipient is None:
        flash("Recipient not found in your company.")

    elif recipient.id == user.id:
        flash("You already own this document.")

    elif DocumentShare.query.filter_by(
        document_id=document.id,
        recipient_id=recipient.id,
    ).first():
        flash("This document is already shared with that user.")

    else:
        share = DocumentShare(
            document_id=document.id,
            recipient_id=recipient.id,
            granted_by_id=user.id,
        )

        db.session.add(share)
        db.session.commit()

        log_action(
            "DOCUMENT_SHARED",
            f"Document ID {document.id} shared with user ID {recipient.id}",
        )
        flash("Document shared successfully.")

    return redirect(url_for("dashboard"))


# Revoke document access
@app.route(
    "/documents/<int:document_id>/revoke/<int:recipient_id>",
    methods=["POST"],
)
@login_required
def revoke_share(document_id, recipient_id):
    user = current_user()

    document = Document.query.filter_by(
        id=document_id,
        owner_id=user.id,
        company=user.company,
    ).first_or_404()

    share = DocumentShare.query.filter_by(
        document_id=document.id,
        recipient_id=recipient_id,
    ).first_or_404()

    db.session.delete(share)
    db.session.commit()

    log_action(
        "SHARE_REVOKED",
        f"Document ID {document.id}; recipient ID {recipient_id}",
    )

    flash("Document access revoked.")
    return redirect(url_for("dashboard"))


# Admin dashboard
@app.route("/admin")
@admin_required
def admin():
    user = current_user()

    users = User.query.filter_by(
        company=user.company,
    ).order_by(User.created_at.desc()).all()

    documents = Document.query.filter_by(
        company=user.company,
    ).order_by(Document.uploaded_at.desc()).all()

    logs = (
        AuditLog.query.outerjoin(User, AuditLog.user_id == User.id)
        .filter(
            db.or_(
                User.company == user.company,
                AuditLog.user_id.is_(None),
            )
        )
        .order_by(AuditLog.created_at.desc())
        .limit(200)
        .all()
    )

    return render_template(
        "admin.html",
        users=users,
        documents=documents,
        logs=logs,
    )


# Error handlers
@app.errorhandler(403)
def forbidden(_error):
    return (
        "Access denied. You do not have permission to view this page.",
        403,
    )


@app.errorhandler(404)
def not_found(_error):
    return "Not found.", 404


@app.errorhandler(413)
def too_large(_error):
    return "File too large. Maximum upload size is 10 MB.", 413


# Create database tables
    
# Create database tables and configure the designated admin
with app.app_context():
    db.create_all()

    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()

    if admin_email:
        admin_user = User.query.filter_by(email=admin_email).first()

        if admin_user:
            admin_user.role = "admin"
            db.session.commit()
            app.logger.info("Configured designated admin account.")
        else:
            app.logger.warning(
                "ADMIN_EMAIL account not found; no role was changed."
            )



if __name__ == "__main__":
    app.run(debug=False)    