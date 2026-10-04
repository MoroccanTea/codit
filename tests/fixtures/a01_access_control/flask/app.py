import os
from urllib.parse import urlparse

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, send_from_directory, session, url_for
from flask_jwt_extended import JWTManager
from flask_login import LoginManager, current_user, login_required, login_user

from blueprints.api import api_bp
from blueprints.reports import reports_bp
from decorators import admin_required
from models import Invoice, User, db

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
app.config["JWT_SECRET_KEY"] = os.environ["JWT_SECRET_KEY"]
UPLOAD_DIR = os.path.join(app.root_path, "uploads")

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
JWTManager(app)
app.register_blueprint(reports_bp, url_prefix="/reports")
app.register_blueprint(api_bp, url_prefix="/api")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route("/login", methods=["GET", "POST"])  # codit-safe: CWE-862 login page is public by design
def login():
    if request.method == "GET":
        return render_template("login.html")
    user = User.query.filter_by(email=request.form["email"]).first()
    if not user or not user.check_password(request.form["password"]):
        abort(401)
    login_user(user)
    session["is_admin"] = user.is_admin  # codit-safe: CWE-807,CWE-915 flag copied from the database record, not from the request
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)


@app.route("/profile/upgrade", methods=["POST"])
@login_required
def upgrade_profile():
    session["is_admin"] = request.form.get("is_admin") == "on"  # codit-expect: CWE-807,CWE-915 privilege flag taken from the submitted form
    return redirect(url_for("dashboard"))


@app.route("/admin/users")  # codit-safe: CWE-862 @login_required + @admin_required
@login_required
@admin_required
def admin_users():
    return render_template("admin/users.html", users=User.query.order_by(User.email).all())


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])  # codit-expect: CWE-862 sibling admin route with no @login_required/@admin_required
def admin_delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/impersonate", methods=["POST"])  # codit-expect: CWE-862,CWE-863 admin-only action guarded by @login_required only
@login_required
def admin_impersonate(user_id):
    login_user(db.session.get(User, user_id))
    return redirect(url_for("dashboard"))


@app.route("/account/statement")
@login_required
def statement():
    user = User.query.get_or_404(request.args["user_id"])  # codit-expect: CWE-639 any user's statement via ?user_id=, never compared to current_user.id
    return jsonify(user.statement())


@app.route("/account/statement/full")
@login_required
def statement_full():
    user_id = int(request.args.get("user_id", current_user.id))
    if user_id != current_user.id and not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)  # codit-safe: CWE-639 requested id compared with current_user.id before loading
    return jsonify(user.statement(full=True))


@app.route("/invoices/<int:invoice_id>")
@login_required
def invoice_detail(invoice_id):
    invoice = Invoice.query.filter_by(id=invoice_id, owner_id=current_user.id).first_or_404()  # codit-safe: CWE-639 owner-scoped query
    return jsonify(invoice.to_dict())


@app.route("/invoices/<int:invoice_id>/pdf")
@login_required
def invoice_pdf(invoice_id):
    invoice = db.session.get(Invoice, invoice_id)  # codit-expect: CWE-639 invoice loaded by path id without owner check
    return send_file(invoice.pdf_path, mimetype="application/pdf")


@app.route("/go")
def go():
    return redirect(request.args.get("next", "/"))  # codit-expect: CWE-601 redirect target taken from the query string


@app.route("/continue")
def continue_to():
    target = request.args.get("next", "/")
    if urlparse(target).netloc or not target.startswith("/") or target.startswith("//") or "\\" in target:
        target = "/"
    return redirect(target)  # codit-safe: CWE-601 only same-site relative paths


@app.route("/downloads")
@login_required
def download():
    return send_file(os.path.join(UPLOAD_DIR, request.args["name"]))  # codit-expect: CWE-22 user-supplied name joined into a filesystem path


@app.route("/downloads/v2")
@login_required
def download_v2():
    return send_from_directory(UPLOAD_DIR, request.args["name"])  # codit-safe: CWE-22 send_from_directory uses safe_join confinement
