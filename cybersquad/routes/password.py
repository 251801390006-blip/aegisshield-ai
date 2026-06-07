"""
Cyber Squad AI – Password Strength Analyzer Blueprint
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from cybersquad.extensions import db, limiter
from cybersquad.models.scan_history import ScanHistory
from cybersquad.services.password_service import analyze_password

password_bp = Blueprint("password", __name__)


@password_bp.route("/")
@login_required
def index():
    recent = (
        ScanHistory.query.filter_by(user_id=current_user.id, scan_type="password")
        .order_by(ScanHistory.created_at.desc())
        .limit(5)
        .all()
    )
    return render_template("modules/password.html", title="Password Strength Analyzer", recent_scans=recent)


@password_bp.route("/analyze", methods=["POST"])
@login_required
@limiter.limit("2000 per hour")
def analyze():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Please provide a password to analyze."}), 400
    if len(password) > 128:
        return jsonify({"error": "Password too long (max 128 characters)."}), 400

    result = analyze_password(password)

    # Generate real-time AI summary
    from cybersquad.services.gemini_service import get_ai_summary
    result["summary"] = get_ai_summary("password", password, result)

    # Store in history (NEVER store the actual password)
    masked = "*" * min(len(password), 8) + f" ({len(password)} chars)"
    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="password",
        input_data=masked,
        result=result["strength"],
        confidence=float(result["score"]),
        risk_score=result.get("risk_score"),
        is_threat=result.get("is_threat", False),
        recommendation="; ".join(result.get("recommendations", [])),
        ip_address=request.remote_addr,
    )
    scan.set_details({
        "score": result["score"],
        "entropy": result["entropy"],
        "length": result["length"],
        "crack_time": result["crack_time"],
        "characteristics": result.get("characteristics", {}),
        "summary": result.get("summary"),
    })
    db.session.add(scan)
    db.session.commit()

    result["scan_id"] = scan.id
    return jsonify(result)


@password_bp.route("/realtime", methods=["POST"])
@login_required
@limiter.limit("5000 per minute")
def realtime():
    """Real-time analysis without saving to history."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password or len(password) > 128:
        return jsonify({"score": 0, "strength": "VERY WEAK", "strength_class": "danger"})
    result = analyze_password(password)
    return jsonify({
        "score": result["score"],
        "strength": result["strength"],
        "strength_class": result["strength_class"],
        "entropy": result["entropy"],
        "crack_time": result["crack_time"],
    })
