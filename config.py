"""
AegisShield AI – Configuration Module
Supports Development (SQLite), Testing, and Production (PostgreSQL) environments.
"""

import os
from datetime import timedelta


class Config:
    """Base configuration with shared settings."""

    # ── Security ────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get("SECRET_KEY", "aegisshield-dev-secret-key-change-in-production")
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # ── Session ─────────────────────────────────────────────────────────────
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = False          # set True in production (HTTPS)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # ── Database ─────────────────────────────────────────────────────────────
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }

    # ── Mail (password reset) ─────────────────────────────────────────────
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@aegisshield.io")

    # ── File Upload ───────────────────────────────────────────────────────
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024   # 16 MB
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")

    # ── Rate Limiting ─────────────────────────────────────────────────────
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    RATELIMIT_STORAGE_URL = "memory://"

    # ── ML Model Paths ─────────────────────────────────────────────────────
    ML_MODELS_DIR = os.path.join(os.path.dirname(__file__), "aegisshield", "ml", "saved_models")

    # ── App Metadata ───────────────────────────────────────────────────────
    APP_NAME = "AegisShield AI"
    APP_VERSION = "1.0.0"
    APP_DESCRIPTION = "AI-Powered Cyber Crime Detection Platform"


class DevelopmentConfig(Config):
    """Development configuration – SQLite."""
    DEBUG = True
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(os.path.dirname(__file__), "aegisshield_dev.db"),
    )


class TestingConfig(Config):
    """Testing configuration – in-memory SQLite."""
    DEBUG = False
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    """Production configuration – PostgreSQL on Render."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True

    # Render injects DATABASE_URL; fix 'postgres://' → 'postgresql://' for SQLAlchemy 2.x
    _db_url = os.environ.get("DATABASE_URL", "")
    if _db_url.startswith("postgres://"):
        _db_url = _db_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _db_url or "sqlite:///aegisshield_prod.db"

    RATELIMIT_STORAGE_URL = os.environ.get("REDIS_URL", "memory://")


# ── Config selector ──────────────────────────────────────────────────────────
config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config():
    env = os.environ.get("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)
