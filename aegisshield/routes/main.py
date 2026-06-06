"""
AegisShield AI – Main Blueprint (Landing Page, About, etc.)
"""

from flask import Blueprint, render_template
from flask_login import current_user

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def landing():
    return render_template("landing.html", title="AegisShield AI – Cyber Crime Detection Platform")


@main_bp.route("/about")
def about():
    return render_template("about.html", title="About AegisShield AI")
