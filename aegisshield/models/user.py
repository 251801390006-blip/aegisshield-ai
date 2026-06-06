"""
AegisShield AI – User Model
"""

from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer
from flask import current_app

from aegisshield.extensions import db, login_manager


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")
    is_active = db.Column(db.Boolean, default=True)
    avatar_url = db.Column(db.String(256), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)

    # ── Relationships ───────────────────────────────────────────────────────
    scan_histories = db.relationship("ScanHistory", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    threat_reports = db.relationship("ThreatReport", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def get_reset_token(self, expires_sec: int = 1800) -> str:
        s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        return s.dumps(self.email, salt="password-reset-salt")

    @staticmethod
    def verify_reset_token(token: str, expires_sec: int = 1800):
        s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        try:
            email = s.loads(token, salt="password-reset-salt", max_age=expires_sec)
        except Exception:
            return None
        return User.query.filter_by(email=email).first()

    def update_last_login(self):
        self.last_login = datetime.now(timezone.utc)
        db.session.commit()

    def get_scan_stats(self) -> dict:
        from aegisshield.models.scan_history import ScanHistory
        total = self.scan_histories.count()
        spam = self.scan_histories.filter_by(scan_type="spam").count()
        phishing = self.scan_histories.filter_by(scan_type="phishing").count()
        password = self.scan_histories.filter_by(scan_type="password").count()
        malware = self.scan_histories.filter_by(scan_type="malware").count()
        threats = self.scan_histories.filter_by(is_threat=True).count()
        return {
            "total": total,
            "spam": spam,
            "phishing": phishing,
            "password": password,
            "malware": malware,
            "threats": threats,
            "safe": total - threats,
        }

    def __repr__(self):
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))
