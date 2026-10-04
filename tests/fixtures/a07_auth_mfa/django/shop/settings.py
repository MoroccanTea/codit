"""Django settings for the shop project (single settings module used in every environment)."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
ALLOWED_HOSTS = ["shop.acme.example"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "accounts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "shop.urls"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "shop",
        "HOST": os.environ.get("DB_HOST", "db"),
        "USER": "shop",
        "PASSWORD": os.environ["DB_PASSWORD"],
    }
}

PASSWORD_HASHERS = [
    # codit-expect: CWE-916 unsalted MD5 is the primary hasher used for new passwords
    "django.contrib.auth.hashers.UnsaltedMD5PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        # codit-expect: CWE-521 minimum password length of 6
        "OPTIONS": {"min_length": 6},
    },
]

# codit-expect: CWE-613 session cookie valid for one year
SESSION_COOKIE_AGE = 60 * 60 * 24 * 365
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

MASTER_OTP = os.environ.get("MASTER_OTP", "000000")

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}

STATIC_URL = "/static/"
