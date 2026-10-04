import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

DEBUG = True  # codit-expect: CWE-489 debug mode enabled in the shipped settings module

ALLOWED_HOSTS = ["*"]  # codit-expect: CWE-16 any Host header accepted (host-header poisoning of reset links)

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "corsheaders",
    "rest_framework",
    "tickets",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

ROOT_URLCONF = "portal.urls"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.AllowAny",  # codit-expect: CWE-862 DRF default permission AllowAny: every viewset without permission_classes is anonymous
    ],
}

CORS_ALLOW_CREDENTIALS = True



CORS_ALLOW_ALL_ORIGINS = True  # codit-expect: CWE-942 all origins allowed together with CORS_ALLOW_CREDENTIALS
