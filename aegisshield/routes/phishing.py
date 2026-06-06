"""
AegisShield AI – Phishing URL Detection Blueprint
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
import re

from aegisshield.extensions import db, limiter
from aegisshield.models.scan_history import ScanHistory
from aegisshield.ml.phishing_model import get_phishing_detector

phishing_bp = Blueprint("phishing", __name__)

URL_PATTERN = re.compile(
    r"^(https?://)?"
    r"(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})"
    r"(:\d+)?"
    r"(/[^\s]*)?"
    r"(\?[^\s]*)?"
    r"(#[^\s]*)?$"
)


@phishing_bp.route("/")
@login_required
def index():
    recent = (
        ScanHistory.query.filter_by(user_id=current_user.id, scan_type="phishing")
        .order_by(ScanHistory.created_at.desc())
        .limit(5)
        .all()
    )
    return render_template("modules/phishing.html", title="Phishing URL Scanner", recent_scans=recent)


@phishing_bp.route("/analyze", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def analyze():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please provide a URL to analyze."}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL too long (max 2048 characters)."}), 400

    # Basic URL format validation
    test_url = url if "://" in url else "http://" + url
    if not URL_PATTERN.match(test_url):
        return jsonify({"error": "Invalid URL format. Please enter a valid URL."}), 400

    detector = get_phishing_detector()
    result = detector.predict(url)

    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="phishing",
        input_data=url[:500],
        result=result["result"],
        confidence=result.get("phishing_probability"),
        risk_score=result.get("risk_score"),
        is_threat=result.get("is_threat", False),
        recommendation=result.get("recommendation"),
        ip_address=request.remote_addr,
    )
    scan.set_details({
        "domain": result.get("domain"),
        "phishing_probability": result.get("phishing_probability"),
        "safe_probability": result.get("safe_probability"),
        "indicators": result.get("indicators", []),
        "features": result.get("features", {}),
    })
    db.session.add(scan)
    db.session.commit()

    result["scan_id"] = scan.id
    return jsonify(result)
