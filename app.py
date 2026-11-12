"""
app.py - Flask application for the Secure QR Code-Based Identity Verification System.

Run:  python app.py      then open  http://127.0.0.1:5000
"""
import base64
import io
import os
import sqlite3
from datetime import date, timedelta
from functools import wraps

import qrcode
from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

import database  # noqa: E402  (imported after load_dotenv so env vars are ready)
import security  # noqa: E402

DUMMY_HASH = generate_password_hash("not-a-real-password")  # keeps login timing similar
RESULT_FILTERS = ("VALID", "INVALID", "EXPIRED", "REVOKED")


def make_qr_data_uri(payload):
    """Create a QR code image in memory and return it as a data: URI (nothing saved to disk)."""
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def create_app():
    app = Flask(__name__)

    secret = os.environ.get("FLASK_SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError("FLASK_SECRET_KEY is missing or too short. Copy .env.example to .env and set it.")
    security.get_hmac_key()  # fail early if QR_HMAC_KEY is missing

    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=64 * 1024,
    )

    database.init_db()
    login_limiter = security.RateLimiter(max_calls=10, period_seconds=300)
    verify_limiter = security.RateLimiter(max_calls=60, period_seconds=60)

    # ------------------------------------------------------------ hooks
    @app.before_request
    def csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not security.validate_csrf(session, sent):
                return error_response(400, "Invalid or missing security token. Reload the page and try again.")

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data: blob:; script-src 'self'; style-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(self)"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.context_processor
    def inject_globals():
        return {
            "csrf_token": lambda: security.get_csrf_token(session),
            "current_admin": session.get("admin_username"),
        }

    def error_response(code, message):
        if request.path.startswith("/api/"):
            return jsonify(result="ERROR", message=message), code
        return render_template("error.html", code=code, message=message), code

    @app.errorhandler(HTTPException)
    def handle_http_error(err):
        return error_response(err.code, err.description)

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("admin_id"):
                flash("Please log in as admin to continue.", "error")
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    # ----------------------------------------------------------- public pages
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("admin_id"):
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            if not login_limiter.allow(request.remote_addr):
                flash("Too many login attempts. Please wait a few minutes.", "error")
                return render_template("login.html"), 429
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not username or not password:
                flash("Enter both username and password.", "error")
                return render_template("login.html"), 400
            admin = database.get_admin_by_username(username)
            password_ok = check_password_hash(admin["password_hash"] if admin else DUMMY_HASH, password)
            if admin and password_ok:
                session.clear()  # new session on login (prevents session fixation)
                session["admin_id"] = admin["id"]
                session["admin_username"] = admin["username"]
                session.permanent = True
                flash("Welcome back, " + admin["username"] + ".", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid username or password.", "error")
            return render_template("login.html"), 401
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("index"))

    @app.route("/verify")
    def verify():
        return render_template("verify.html")

    # ---------------------------------------------------------- admin pages
    @app.route("/dashboard")
    @login_required
    def dashboard():
        users = database.list_users()
        stats = {
            "total": len(users),
            "active": sum(u["effective_status"] == "ACTIVE" for u in users),
            "expired": sum(u["effective_status"] == "EXPIRED" for u in users),
            "revoked": sum(u["effective_status"] == "REVOKED" for u in users),
            "scans": database.count_logs(),
        }
        return render_template("dashboard.html", users=users, stats=stats)

    @app.route("/register", methods=["GET", "POST"])
    @login_required
    def register():
        min_date = (date.today() + timedelta(days=1)).isoformat()
        form, errors = {}, []
        if request.method == "POST":
            form = {k: request.form.get(k, "").strip() for k in ("name", "user_id", "department", "expiry_date")}
            errors = security.validate_registration(
                form["name"], form["user_id"], form["department"], form["expiry_date"]
            )
            if not errors:
                token = security.generate_token()
                try:
                    pk = database.create_user(
                        form["user_id"], form["name"], form["department"],
                        form["expiry_date"], security.hash_token(token),
                    )
                except sqlite3.IntegrityError:
                    errors.append("That User ID is already registered. Choose a different one.")
                else:
                    payload = security.build_payload(token)
                    return render_template(
                        "qr.html", user=database.get_user(pk),
                        qr_image=make_qr_data_uri(payload), title="Identity registered",
                    )
            status = 400
        else:
            status = 200
        return render_template("register.html", form=form, errors=errors, min_date=min_date), status

    @app.post("/users/<int:pk>/regenerate")
    @login_required
    def regenerate(pk):
        user = database.get_user(pk)
        if user is None:
            return error_response(404, "User not found.")
        if user["effective_status"] != "ACTIVE":
            flash("Only ACTIVE identities can get a new QR code.", "error")
            return redirect(url_for("dashboard"))
        token = security.generate_token()
        database.update_token_hash(pk, security.hash_token(token))
        payload = security.build_payload(token)
        return render_template(
            "qr.html", user=database.get_user(pk),
            qr_image=make_qr_data_uri(payload), title="New QR code issued",
        )

    @app.post("/users/<int:pk>/revoke")
    @login_required
    def revoke(pk):
        user = database.get_user(pk)
        if user is None:
            return error_response(404, "User not found.")
        if database.revoke_user(pk):
            flash(f"Identity {user['user_id']} was revoked. Its QR code no longer works.", "success")
        else:
            flash("That identity was already revoked.", "error")
        return redirect(url_for("dashboard"))

    @app.route("/history")
    @login_required
    def history():
        selected = request.args.get("result", "").upper()
        if selected not in RESULT_FILTERS:
            selected = ""
        logs = database.list_logs(selected or None)
        return render_template("history.html", logs=logs, selected=selected, filters=RESULT_FILTERS)

    # ------------------------------------------------------------ verification
    def finish(result, message, user, ip):
        database.log_verification(user["id"] if user else None, result, message, ip)
        outcome = {"result": result, "message": message}
        if result == "VALID":  # personal details come from the DATABASE, never from the QR
            outcome["user"] = {
                "name": user["name"], "user_id": user["user_id"],
                "department": user["department"], "expiry_date": user["expiry_date"],
            }
        return outcome

    def run_verification(payload, ip):
        parsed = security.parse_payload(payload)
        if parsed is None:
            return finish("INVALID", "This is not a valid identity QR code.", None, ip)
        token, signature = parsed
        if not security.verify_signature(token, signature):
            return finish("INVALID", "Signature check failed. The QR code is forged or altered.", None, ip)
        user = database.get_user_by_token_hash(security.hash_token(token))
        if user is None:
            return finish("INVALID", "Token is not registered (or this QR code was replaced).", None, ip)
        if user["effective_status"] == "REVOKED":
            return finish("REVOKED", "This identity has been revoked by an administrator.", user, ip)
        if user["effective_status"] == "EXPIRED":
            return finish("EXPIRED", "This identity has passed its expiry date.", user, ip)
        return finish("VALID", "Signature, registration, expiry and status checks all passed.", user, ip)

    @app.post("/api/verify")
    def api_verify():
        ip = request.remote_addr
        if not verify_limiter.allow(ip):
            return jsonify(result="ERROR", message="Too many requests. Slow down and try again."), 429
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("payload"), str):
            return jsonify(result="ERROR", message="Bad request: a text 'payload' is required."), 400
        return jsonify(run_verification(data["payload"], ip))

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
