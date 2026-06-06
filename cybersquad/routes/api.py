"""
Cyber Squad AI – REST API v1 Blueprint

Provides programmatic JSON access to all detection modules.
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from cybersquad.extensions import limiter
from cybersquad.ml.spam_model import get_spam_detector
from cybersquad.ml.phishing_model import get_phishing_detector
from cybersquad.services.password_service import analyze_password
from cybersquad.models.scan_history import ScanHistory
from cybersquad.extensions import db
import bleach

api_bp = Blueprint("api", __name__)


def _api_response(data: dict, status: int = 200):
    return jsonify({"status": "success" if status < 400 else "error", "data": data}), status


# ── Health check ────────────────────────────────────────────────────────────

@api_bp.route("/health")
def health():
    return jsonify({"status": "ok", "service": "Cyber Squad AI", "version": "1.0.0"})


# ── Spam API ────────────────────────────────────────────────────────────────

@api_bp.route("/spam/analyze", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def api_spam():
    data = request.get_json(silent=True) or {}
    text = data.get("email_text", "").strip()
    if not text:
        return _api_response({"message": "email_text is required"}, 400)
    clean = bleach.clean(text, tags=[], strip=True)
    result = get_spam_detector().predict(clean)
    return _api_response(result)


# ── Phishing API ────────────────────────────────────────────────────────────

@api_bp.route("/phishing/analyze", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def api_phishing():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return _api_response({"message": "url is required"}, 400)
    result = get_phishing_detector().predict(url)
    return _api_response(result)


# ── Password API ────────────────────────────────────────────────────────────

@api_bp.route("/password/analyze", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def api_password():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return _api_response({"message": "password is required"}, 400)
    result = analyze_password(password)
    return _api_response(result)


# ── Dashboard stats API ──────────────────────────────────────────────────────

@api_bp.route("/dashboard/stats")
@login_required
def api_stats():
    stats = current_user.get_scan_stats()
    return _api_response(stats)


# ── History API ──────────────────────────────────────────────────────────────

@api_bp.route("/history")
@login_required
def api_history():
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)
    scan_type = request.args.get("type")

    query = ScanHistory.query.filter_by(user_id=current_user.id)
    if scan_type:
        query = query.filter_by(scan_type=scan_type)

    pagination = query.order_by(ScanHistory.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return _api_response({
        "scans": [s.to_dict() for s in pagination.items],
        "total": pagination.total,
        "pages": pagination.pages,
        "page": page,
    })
