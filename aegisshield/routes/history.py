"""
AegisShield AI – Scan History Blueprint
"""

import csv
import io
from flask import Blueprint, render_template, request, jsonify, make_response
from flask_login import login_required, current_user

from aegisshield.extensions import db
from aegisshield.models.scan_history import ScanHistory

history_bp = Blueprint("history", __name__)


@history_bp.route("/")
@login_required
def index():
    page = request.args.get("page", 1, type=int)
    per_page = 20
    scan_type = request.args.get("type", "")
    search = request.args.get("search", "")
    result_filter = request.args.get("result", "")

    query = ScanHistory.query.filter_by(user_id=current_user.id)

    if scan_type:
        query = query.filter_by(scan_type=scan_type)
    if result_filter == "threats":
        query = query.filter_by(is_threat=True)
    elif result_filter == "safe":
        query = query.filter_by(is_threat=False)
    if search:
        query = query.filter(ScanHistory.input_data.ilike(f"%{search}%"))

    pagination = query.order_by(ScanHistory.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template(
        "history.html",
        title="Scan History",
        scans=pagination.items,
        pagination=pagination,
        scan_type=scan_type,
        search=search,
        result_filter=result_filter,
    )


@history_bp.route("/export/csv")
@login_required
def export_csv():
    scans = (
        ScanHistory.query.filter_by(user_id=current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Scan Type", "Input", "Result", "Risk Score", "Is Threat", "Timestamp"])
    for s in scans:
        writer.writerow([
            s.id, s.scan_type, s.input_data or "", s.result,
            s.risk_score or "", s.is_threat, s.created_at,
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=aegisshield_scan_history.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


@history_bp.route("/delete/<int:scan_id>", methods=["DELETE"])
@login_required
def delete_scan(scan_id):
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    db.session.delete(scan)
    db.session.commit()
    return jsonify({"message": "Scan deleted successfully."})


@history_bp.route("/api/list")
@login_required
def api_list():
    scans = (
        ScanHistory.query.filter_by(user_id=current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(50)
        .all()
    )
    return jsonify([s.to_dict() for s in scans])
