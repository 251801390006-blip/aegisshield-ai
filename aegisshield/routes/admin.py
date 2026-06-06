"""
AegisShield AI – Admin Analytics Blueprint
"""

from flask import Blueprint, render_template, abort, flash, redirect, url_for
from flask_login import login_required, current_user

from aegisshield.extensions import db
from aegisshield.models.user import User
from aegisshield.models.scan_history import ScanHistory

admin_bp = Blueprint("admin", __name__)


@admin_bp.before_request
@login_required
def require_admin():
    """Ensure that only administrators can access this blueprint."""
    if current_user.role != "admin":
        abort(403)


@admin_bp.route("/")
def index():
    """Admin Dashboard Home."""
    # Query all users
    users = User.query.order_by(User.created_at.desc()).all()
    
    # Query all scan histories
    scans = ScanHistory.query.order_by(ScanHistory.created_at.desc()).all()
    
    # Calculate statistics
    total_scans = len(scans)
    threat_scans = sum(1 for s in scans if s.is_threat)
    safe_scans = total_scans - threat_scans
    threat_rate = (threat_scans / total_scans * 100) if total_scans > 0 else 0.0
    
    stats = {
        "total_users": len(users),
        "total_scans": total_scans,
        "threat_scans": threat_scans,
        "safe_scans": safe_scans,
        "threat_rate": round(threat_rate, 1)
    }
    
    return render_template(
        "admin/index.html",
        title="Admin Analytics Console",
        users=users,
        scans=scans,
        stats=stats
    )


@admin_bp.route("/reset-database", methods=["POST"])
def reset_database():
    """Clears all users (except demo/admin) and scan histories from the database."""
    from aegisshield.models.user import User
    from aegisshield.models.scan_history import ScanHistory
    from aegisshield.models.threat_report import ThreatReport
    
    try:
        # Delete threat reports first (references scan_history and users)
        ThreatReport.query.delete()
        # Then delete scan history (references users)
        ScanHistory.query.delete()
        
        # Delete users except demo/admin
        User.query.filter(
            User.email != "admin@aegisshield.io", 
            User.email != "demo@aegisshield.io"
        ).delete()
        
        db.session.commit()
        flash("Database cleared successfully! All custom user accounts and scan logs have been deleted.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error resetting database: {str(e)}", "danger")
        
    return redirect(url_for("admin.index"))
