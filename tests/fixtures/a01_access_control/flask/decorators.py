from functools import wraps

from flask import abort, request
from flask_login import current_user


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:  # codit-safe: CWE-807 role from the server-side user record
            abort(403)
        return view(*args, **kwargs)

    return wrapper


def staff_required(view):
    """Used by the warehouse kiosk; the kiosk sets X-Staff-Role itself."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if request.headers.get("X-Staff-Role") != "staff":  # codit-expect: CWE-807 authorization decided by a client-controlled header
            abort(403)
        return view(*args, **kwargs)

    return wrapper
