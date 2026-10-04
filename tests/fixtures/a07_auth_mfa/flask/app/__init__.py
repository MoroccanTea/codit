import os

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager

login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address, storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"))


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
    # Default Flask session: signed with itsdangerous but NOT encrypted, stored in the browser cookie.
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    login_manager.init_app(app)
    limiter.init_app(app)

    from .auth.routes import bp as auth_bp
    from .auth.routes_v2 import bp as auth_v2_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(auth_v2_bp, url_prefix="/v2/auth")
    return app
