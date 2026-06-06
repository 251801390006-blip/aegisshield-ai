"""
Cyber Squad AI – Scan History Model
"""

from datetime import datetime, timezone
import json

from cybersquad.extensions import db


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    scan_type = db.Column(db.String(30), nullable=False)   # spam | phishing | password | malware
    input_data = db.Column(db.Text, nullable=True)          # truncated input (email text, URL, filename…)
    result = db.Column(db.String(30), nullable=False)       # SPAM | SAFE | PHISHING | WEAK | STRONG | etc.
    confidence = db.Column(db.Float, nullable=True)
    risk_score = db.Column(db.Float, nullable=True)
    is_threat = db.Column(db.Boolean, default=False)
    details = db.Column(db.Text, nullable=True)             # JSON-encoded extra details
    recommendation = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def set_details(self, data: dict):
        self.details = json.dumps(data)

    def get_details(self) -> dict:
        if self.details:
            try:
                return json.loads(self.details)
            except Exception:
                return {}
        return {}

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_type": self.scan_type,
            "input_data": self.input_data,
            "result": self.result,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "is_threat": self.is_threat,
            "recommendation": self.recommendation,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None,
            "details": self.get_details(),
        }

    def __repr__(self):
        return f"<ScanHistory {self.scan_type}:{self.result}>"
