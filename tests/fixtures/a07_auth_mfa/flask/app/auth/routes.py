"""Legacy login flow (/auth) - still linked from the old marketing site."""
import hashlib
import logging
import random

import pyotp
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user

from ..models import User, db
from ..sms import send_sms

bp = Blueprint("auth", __name__)
log = logging.getLogger(__name__)


@bp.route("/login", methods=["GET"])
def login_form():
    return render_template("auth/login.html")


@bp.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(email=request.form["email"].lower()).first()
    # codit-expect: CWE-916 unsalted SHA-256 used as the password hash
    digest = hashlib.sha256(request.form["password"].encode()).hexdigest()
    if user is None or user.password_hash != digest:
        flash("Invalid credentials")
        return redirect(url_for("auth.login_form"))

    # codit-expect: CWE-807 unsigned remember_2fa cookie lets the browser skip the second factor
    if user.otp_enabled and request.cookies.get("remember_2fa") == "1":
        login_user(user)
        return redirect(url_for("dashboard.index"))

    # codit-expect: CWE-308 user fully logged in with login_user() before the OTP step
    login_user(user)
    if user.otp_enabled:
        return redirect(url_for("auth.otp_form"))
    return redirect(url_for("dashboard.index"))


@bp.route("/otp", methods=["GET"])
@login_required
def otp_form():
    return render_template("auth/otp.html")


@bp.route("/otp/send", methods=["POST"])
@login_required
def send_otp():
    # codit-expect: CWE-338 SMS code from the non-cryptographic random module
    code = str(random.randint(100000, 999999))
    session["otp_sent_at"] = int(current_app.config.get("NOW", 0))

    # codit-expect: CWE-308 OTP stored in Flask's default client-side cookie session (user can read it)
    session["otp"] = code
    send_sms(current_user.phone, f"Your code: {code}")

    # codit-expect: CWE-532 one-time code written to the log
    log.debug(f"OTP for {current_user.email} is {code}")
    return {"sent": True}


# codit-expect: CWE-307 no rate limit or attempt counter on the OTP check
@bp.route("/otp/verify", methods=["POST"])
@login_required
def verify_otp():
    code = request.form.get("code", "")

    # codit-expect: CWE-807 client-supplied otp_passed form field accepted as proof of 2FA
    if request.form.get("otp_passed") == "1":
        session["mfa_ok"] = True
        return redirect(url_for("dashboard.index"))

    if code == session.get("otp") or check_totp(current_user, code):
        session["mfa_ok"] = True
        return redirect(url_for("dashboard.index"))
    flash("Invalid code")
    return redirect(url_for("auth.otp_form"))


def check_totp(user, code):
    # codit-expect: CWE-308 OTP check bypassed whenever the app runs with DEBUG enabled
    if current_app.config.get("DEBUG"):
        return True

    totp = pyotp.TOTP(user.otp_secret)
    try:
        # codit-expect: CWE-307 valid_window=10 accepts codes from +/- 5 minutes
        return totp.verify(code, valid_window=10)
    except Exception:
        log.exception("totp verification failed")
        # codit-expect: CWE-308 any exception during verification is treated as success
        return True


# codit-expect: CWE-308 2FA turned off with only the current session, no password or OTP
@bp.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    current_user.otp_enabled = False
    current_user.otp_secret = None
    db.session.commit()
    return redirect(url_for("settings.security"))
