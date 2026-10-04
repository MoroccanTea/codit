"""Production overrides (DJANGO_SETTINGS_MODULE=shop.settings_production)."""
from .settings import *  # noqa: F401,F403

# codit-safe: CWE-489 DEBUG off in production
DEBUG = False



# codit-safe: CWE-16 explicit host allow-list
ALLOWED_HOSTS = ["shop.acme.example", "www.shop.acme.example"]



# codit-safe: CWE-942 explicit origin allow-list
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = ["https://shop.acme.example"]

SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
