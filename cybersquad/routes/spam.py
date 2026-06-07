"""
Cyber Squad AI – Spam Detection Blueprint
"""

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
import bleach

from cybersquad.extensions import db, limiter
from cybersquad.models.scan_history import ScanHistory
from cybersquad.ml.spam_model import get_spam_detector

spam_bp = Blueprint("spam", __name__)


@spam_bp.route("/")
@login_required
def index():
    recent = (
        ScanHistory.query.filter_by(user_id=current_user.id, scan_type="spam")
        .order_by(ScanHistory.created_at.desc())
        .limit(5)
        .all()
    )
    return render_template("modules/spam.html", title="Spam Detection", recent_scans=recent)


@spam_bp.route("/analyze", methods=["POST"])
@login_required
@limiter.limit("1000 per hour")
def analyze():
    data = request.get_json(silent=True) or {}
    email_text = data.get("email_text", "").strip()

    if not email_text:
        return jsonify({"error": "Please provide email text to analyze."}), 400
    if len(email_text) > 10000:
        return jsonify({"error": "Email text too long (max 10,000 characters)."}), 400

    # Sanitize input
    clean_text = bleach.clean(email_text, tags=[], strip=True)

    # Run ML prediction
    detector = get_spam_detector()
    result = detector.predict(clean_text)

    # Generate real-time AI summary
    from cybersquad.services.gemini_service import get_ai_summary
    result["summary"] = get_ai_summary("spam", clean_text, result)

    # Save to history
    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="spam",
        input_data=clean_text[:500],
        result=result["result"],
        confidence=result.get("confidence"),
        risk_score=result.get("risk_score"),
        is_threat=result.get("is_threat", False),
        recommendation=result.get("recommendation"),
        ip_address=request.remote_addr,
    )
    scan.set_details({
        "spam_probability": result.get("spam_probability"),
        "ham_probability": result.get("ham_probability"),
        "indicators": result.get("indicators", []),
        "summary": result.get("summary"),
    })
    db.session.add(scan)
    db.session.commit()

    result["scan_id"] = scan.id
    return jsonify(result)
