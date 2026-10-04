"""Current login flow (/v2/auth): password -> pre-2FA marker -> TOTP/SMS -> login_user()."""
import logging
import os
import secrets

import pyotp
import redis
from flask import Blueprint, abort, redirect, request, session, url_for
from flask_login import current_user, login_required, login_user
from werkzeug.security import check_password_hash, generate_password_hash

from .. import limiter
from ..models import User, db
from ..sms import send_sms

bp = Blueprint("auth_v2", __name__)
log = logging.getLogger(__name__)
otp_store = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))

MAX_OTP_ATTEMPTS = 5
OTP_TTL_SECONDS = 300


def _pending_user():
    user_id = session.get("pre_2fa_user_id")
    if user_id is None:
        abort(401)
    return db.session.get(User, user_id)


@bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    user = User.query.filter_by(email=request.form["email"].lower()).first()
    # codit-safe: CWE-916 werkzeug salted scrypt/pbkdf2 hash verification
    if user is None or not check_password_hash(user.password_hash, request.form["password"]):
        abort(401)

    session.clear()
    if user.otp_enabled:
        # codit-safe: CWE-308 only a pre-2FA marker is stored, login_user() runs after OTP verification
        session["pre_2fa_user_id"] = user.id
        return redirect(url_for("auth_v2.otp_form"))
    login_user(user)
    return redirect(url_for("dashboard.index"))


@bp.route("/otp/send", methods=["POST"])
@limiter.limit("3 per minute")
def send_otp():
    user = _pending_user()
    # codit-safe: CWE-338 code generated with the secrets module
    code = f"{secrets.randbelow(10**6):06d}"
    otp_store.delete(f"otp-attempts:{user.id}")

    # codit-safe: CWE-308 OTP kept server-side, hashed, with a 5 minute TTL - never in the cookie session
    otp_store.setex(f"otp:{user.id}", OTP_TTL_SECONDS, generate_password_hash(code))
    send_sms(user.phone, f"Your code: {code}")

    # codit-safe: CWE-532 no secret in the log record
    log.info("sms otp sent user_id=%s", user.id)
    return {"sent": True}


# codit-safe: CWE-307 rate limited and capped at 5 attempts per pending login
@bp.route("/otp/verify", methods=["POST"])
@limiter.limit("5 per minute")
def verify_otp():
    user = _pending_user()
    attempts = otp_store.incr(f"otp-attempts:{user.id}")
    otp_store.expire(f"otp-attempts:{user.id}", OTP_TTL_SECONDS)
    if attempts > MAX_OTP_ATTEMPTS:
        abort(429)
    if not _check_totp(user, request.form.get("code", "")):
        abort(401)
    session.clear()
    login_user(user)
    return redirect(url_for("dashboard.index"))


def _check_totp(user, code):
    if not code.isdigit() or len(code) != 6:
        return False
    totp = pyotp.TOTP(user.otp_secret)
    try:
        # codit-safe: CWE-307 valid_window=1 tolerates a single 30 s step of drift
        return totp.verify(code, valid_window=1)
    except Exception:
        log.exception("totp verification error")
        # codit-safe: CWE-308 fail-closed
        return False


# codit-safe: CWE-308 disabling 2FA requires the current password and a valid TOTP code
@bp.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    if not check_password_hash(current_user.password_hash, request.form.get("password", "")):
        abort(403)
    if not _check_totp(current_user, request.form.get("code", "")):
        abort(403)
    current_user.otp_enabled = False
    current_user.otp_secret = None
    db.session.commit()
    return redirect(url_for("settings.security"))
