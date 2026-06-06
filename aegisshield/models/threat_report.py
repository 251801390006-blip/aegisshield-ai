"""
AegisShield AI – Threat Report Model
"""

from datetime import datetime, timezone
import json

from aegisshield.extensions import db


class ThreatReport(db.Model):
    __tablename__ = "threat_reports"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    scan_history_id = db.Column(db.Integer, db.ForeignKey("scan_history.id"), nullable=True)

    report_title = db.Column(db.String(200), nullable=False)
    report_type = db.Column(db.String(30), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="LOW")  # LOW | MEDIUM | HIGH | CRITICAL
    summary = db.Column(db.Text, nullable=True)
    report_data = db.Column(db.Text, nullable=True)        # JSON full report payload
    pdf_path = db.Column(db.String(512), nullable=True)    # path to generated PDF
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    scan = db.relationship("ScanHistory", backref="reports", foreign_keys=[scan_history_id])

    def set_report_data(self, data: dict):
        self.report_data = json.dumps(data)

    def get_report_data(self) -> dict:
        if self.report_data:
            try:
                return json.loads(self.report_data)
            except Exception:
                return {}
        return {}

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "report_title": self.report_title,
            "report_type": self.report_type,
            "severity": self.severity,
            "summary": self.summary,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None,
        }

    def __repr__(self):
        return f"<ThreatReport {self.report_title}>"
