"""
AegisShield AI – Password Reset OTP Model
"""

from datetime import datetime
from aegisshield.extensions import db


class PasswordResetOTP(db.Model):
    __tablename__ = "password_reset_otps"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, index=True)
    otp_code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at
