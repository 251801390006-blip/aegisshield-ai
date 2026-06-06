"""
Cyber Squad AI – Reports Blueprint (PDF Generation)
"""

from flask import Blueprint, render_template, request, make_response, jsonify
from flask_login import login_required, current_user

from cybersquad.models.scan_history import ScanHistory
from cybersquad.models.threat_report import ThreatReport
from cybersquad.services.report_service import generate_scan_report
from cybersquad.extensions import db

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/")
@login_required
def index():
    reports = (
        ThreatReport.query.filter_by(user_id=current_user.id)
        .order_by(ThreatReport.created_at.desc())
        .limit(50)
        .all()
    )
    return render_template("reports.html", title="Security Reports", reports=reports)


@reports_bp.route("/generate/<int:scan_id>")
@login_required
def generate(scan_id):
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()

    scan_data = scan.to_dict()
    scan_data["indicators"] = scan.get_details().get("indicators", [])

    user_data = {"username": current_user.username, "email": current_user.email}

    pdf_bytes = generate_scan_report(scan_data, user_data)

    # Save report record
    report = ThreatReport(
        user_id=current_user.id,
        scan_history_id=scan.id,
        report_title=f"{scan.scan_type.title()} Scan Report – {scan.result}",
        report_type=scan.scan_type,
        severity=_get_severity(scan),
        summary=scan.recommendation,
    )
    db.session.add(report)
    db.session.commit()

    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = (
        f"attachment; filename=cybersquad_report_{scan_id}.pdf"
    )
    return response


@reports_bp.route("/preview/<int:scan_id>")
@login_required
def preview(scan_id):
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return render_template("report_preview.html", scan=scan, title="Report Preview")


def _get_severity(scan: ScanHistory) -> str:
    score = scan.risk_score or 0
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"
