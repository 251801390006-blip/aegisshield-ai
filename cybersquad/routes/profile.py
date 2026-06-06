"""
Cyber Squad AI – Profile Blueprint
"""

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user

from cybersquad.extensions import db
from cybersquad.forms import ProfileForm, ChangePasswordForm

profile_bp = Blueprint("profile", __name__)


@profile_bp.route("/")
@login_required
def index():
    stats = current_user.get_scan_stats()
    profile_form = ProfileForm(obj=current_user)
    password_form = ChangePasswordForm()
    return render_template(
        "profile.html",
        title="My Profile",
        stats=stats,
        profile_form=profile_form,
        password_form=password_form,
    )


@profile_bp.route("/update", methods=["POST"])
@login_required
def update():
    form = ProfileForm()
    if form.validate_on_submit():
        # Check uniqueness
        from cybersquad.models.user import User
        existing = User.query.filter_by(username=form.username.data).first()
        if existing and existing.id != current_user.id:
            flash("Username already taken.", "danger")
            return redirect(url_for("profile.index"))
        current_user.username = form.username.data.strip()
        current_user.bio = form.bio.data.strip()
        db.session.commit()
        flash("Profile updated successfully.", "success")
    return redirect(url_for("profile.index"))


@profile_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("profile.index"))
        current_user.set_password(form.new_password.data)
        db.session.commit()
        flash("Password changed successfully.", "success")
    return redirect(url_for("profile.index"))


@profile_bp.route("/settings")
@login_required
def settings():
    return render_template("settings.html", title="Settings")
