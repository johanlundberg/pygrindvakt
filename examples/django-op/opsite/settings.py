"""Settings for the demo OpenID Provider (DEMO ONLY: dev secrets, DEBUG on)."""

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR.parent))  # examples/, for the shared ``common`` package

SECRET_KEY = os.environ.get("OP_SECRET_KEY", "dev-only-django-secret")
DEBUG = os.environ.get("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = ["*"]

ROOT_URLCONF = "opsite.urls"
INSTALLED_APPS: list[str] = []
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

# Signed-cookie sessions: the pending authorization request lives in the
# cookie, so no database table (and no migration) is needed.
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
SESSION_COOKIE_NAME = "op_sessionid"  # the demo RP also runs on 127.0.0.1

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

# The OP's public base URL. Every endpoint URL (in particular the token URL
# used as private_key_jwt audience / DPoP htu) derives from it, never from Host.
OP_ISSUER = os.environ.get("OP_ISSUER", "http://127.0.0.1:5000")
