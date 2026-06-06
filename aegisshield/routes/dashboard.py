"""
AegisShield AI – Dashboard Blueprint
"""

from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user

from aegisshield.extensions import db
from aegisshield.models.scan_history import ScanHistory

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    stats = current_user.get_scan_stats()
    recent_scans = (
        ScanHistory.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(10)
        .all()
    )

    # Weekly activity for chart
    weekly_data = _get_weekly_activity(current_user.id)

    return render_template(
        "dashboard/index.html",
        title="Dashboard",
        stats=stats,
        recent_scans=recent_scans,
        weekly_data=weekly_data,
    )


@dashboard_bp.route("/stats")
@login_required
def stats_api():
    stats = current_user.get_scan_stats()
    weekly = _get_weekly_activity(current_user.id)
    return jsonify({"stats": stats, "weekly": weekly})


def _get_weekly_activity(user_id: int) -> dict:
    """Get scan counts per day for the past 7 days."""
    labels = []
    spam_data = []
    phishing_data = []
    password_data = []
    malware_data = []

    today = datetime.now(timezone.utc).date()
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        labels.append(day.strftime("%a"))
        day_start = datetime.combine(day, datetime.min.time()).replace(tzinfo=timezone.utc)
        day_end = datetime.combine(day, datetime.max.time()).replace(tzinfo=timezone.utc)

        base = ScanHistory.query.filter_by(user_id=user_id).filter(
            ScanHistory.created_at >= day_start,
            ScanHistory.created_at <= day_end,
        )
        spam_data.append(base.filter_by(scan_type="spam").count())
        phishing_data.append(base.filter_by(scan_type="phishing").count())
        password_data.append(base.filter_by(scan_type="password").count())
        malware_data.append(base.filter_by(scan_type="malware").count())

    return {
        "labels": labels,
        "spam": spam_data,
        "phishing": phishing_data,
        "password": password_data,
        "malware": malware_data,
    }
