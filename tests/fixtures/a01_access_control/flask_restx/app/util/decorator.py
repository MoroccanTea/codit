from functools import wraps

from flask import request

from app.service.auth import get_logged_in_customer, get_logged_in_user


def customer_token_required(allow_inactive=False):
    """Reject the request unless it carries a valid customer access token."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            customer = get_logged_in_customer(request)
            if not customer or (not allow_inactive and not customer.is_active):
                return {"message": "unauthorized"}, 401
            return f(*args, **kwargs)
        return wrapper
    return decorator


def token_required(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_logged_in_user(request)
            if user is None:
                return {"message": "unauthorized"}, 401
            if roles and user.role not in roles:
                return {"message": "forbidden"}, 403
            return f(*args, **kwargs)
        return wrapper
    return decorator
