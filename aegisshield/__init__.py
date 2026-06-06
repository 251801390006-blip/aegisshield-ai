"""
AegisShield AI – Application Factory
"""

import os
from flask import Flask, render_template
from config import get_config
from aegisshield.extensions import db, login_manager, csrf, mail, migrate, limiter


def create_app(config_class=None):
    """Create and configure the Flask application."""

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"),
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
    )

    # ── Load configuration ──────────────────────────────────────────────────
    if config_class is None:
        config_class = get_config()
    app.config.from_object(config_class)

    # Ensure upload folder exists
    os.makedirs(app.config.get("UPLOAD_FOLDER", "uploads"), exist_ok=True)
    os.makedirs(app.config.get("ML_MODELS_DIR", "ml_models"), exist_ok=True)

    # ── Initialise extensions ───────────────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    # ── Login manager configuration ─────────────────────────────────────────
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    # ── Security headers ────────────────────────────────────────────────────
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if not app.debug:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # ── Register blueprints ─────────────────────────────────────────────────
    from aegisshield.routes.auth import auth_bp
    from aegisshield.routes.dashboard import dashboard_bp
    from aegisshield.routes.spam import spam_bp
    from aegisshield.routes.phishing import phishing_bp
    from aegisshield.routes.password import password_bp
    from aegisshield.routes.malware import malware_bp
    from aegisshield.routes.history import history_bp
    from aegisshield.routes.reports import reports_bp
    from aegisshield.routes.profile import profile_bp
    from aegisshield.routes.api import api_bp
    from aegisshield.routes.main import main_bp
    from aegisshield.routes.admin import admin_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
    app.register_blueprint(spam_bp, url_prefix="/spam")
    app.register_blueprint(phishing_bp, url_prefix="/phishing")
    app.register_blueprint(password_bp, url_prefix="/password")
    app.register_blueprint(malware_bp, url_prefix="/malware")
    app.register_blueprint(history_bp, url_prefix="/history")
    app.register_blueprint(reports_bp, url_prefix="/reports")
    app.register_blueprint(profile_bp, url_prefix="/profile")
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    # ── Create DB tables ────────────────────────────────────────────────────
    with app.app_context():
        db.create_all()
        _seed_demo_data(app)

    # ── Error handlers ──────────────────────────────────────────────────────
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(429)
    def too_many_requests(e):
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def server_error(e):
        return render_template("errors/500.html"), 500

    return app


def _seed_demo_data(app):
    """Seed demo and admin users on first run (development only)."""
    if app.config.get("TESTING"):
        return
    from aegisshield.models.user import User
    
    # Seed demo user
    if not User.query.filter_by(email="demo@aegisshield.io").first():
        demo = User(
            username="demo_user",
            email="demo@aegisshield.io",
            role="user",
        )
        demo.set_password("Demo@1234")
        db.session.add(demo)
        
    # Seed admin user
    if not User.query.filter_by(email="admin@aegisshield.io").first():
        admin = User(
            username="admin_user",
            email="admin@aegisshield.io",
            role="admin",
        )
        admin.set_password("Admin@1234")
        db.session.add(admin)
        
    db.session.commit()
