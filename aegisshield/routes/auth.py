"""
AegisShield AI – Authentication Blueprint
"""

from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message

from aegisshield.extensions import db, mail, limiter
from aegisshield.models.user import User
from aegisshield.forms import LoginForm, RegistrationForm, ForgotPasswordForm, ResetPasswordForm

auth_bp = Blueprint("auth", __name__)


# ── Registration ─────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("1000 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form, title="Create Account")


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("2000 per hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user and user.check_password(form.password.data) and user.is_active:
            login_user(user, remember=form.remember.data)
            user.update_last_login()
            next_page = request.args.get("next")
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(next_page or url_for("dashboard.index"))
        flash("Invalid email or password.", "danger")

    return render_template("auth/login.html", form=form, title="Sign In")


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("main.landing"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("200 per hour")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user:
            token = user.get_reset_token()
            reset_url = url_for("auth.reset_password", token=token, _external=True)
            sent = _send_reset_email(user, reset_url)
            return render_template(
                "auth/forgot_password.html",
                form=form,
                title="Forgot Password",
                success=True,
                reset_url=reset_url,
                email=user.email,
                sent=sent
            )
        else:
            form.email.errors.append("This email address is not registered in our system.")

    return render_template("auth/forgot_password.html", form=form, title="Forgot Password")


# ── Reset Password ────────────────────────────────────────────────────────────

@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    user = User.verify_reset_token(token)
    if not user:
        flash("The reset link is invalid or has expired.", "danger")
        return redirect(url_for("auth.forgot_password"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash("Your password has been reset. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", form=form, title="Reset Password")


# ── Emergency Reset ───────────────────────────────────────────────────────────

@auth_bp.route("/emergency-reset-db", methods=["GET"])
def emergency_reset():
    """Emergency reset via secure query parameter (/?secret=AegisReset2026) to clear custom data and presets."""
    secret = request.args.get("secret")
    if secret != "AegisReset2026":
        from flask import abort
        abort(403)
        
    from aegisshield.models.scan_history import ScanHistory
    from aegisshield.models.threat_report import ThreatReport
    from aegisshield.__init__ import _seed_demo_data
    from flask import current_app
    
    try:
        # Delete threat reports first (references scan_history and users)
        ThreatReport.query.delete()
        # Then delete scan histories (references users)
        ScanHistory.query.delete()
        # Finally delete users
        User.query.delete()
        db.session.commit()
        
        # Re-seed demo users
        _seed_demo_data(current_app)
        flash("Emergency database reset successful! Presets and admin accounts have been re-seeded.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error resetting database: {str(e)}", "danger")
        
    return redirect(url_for("auth.login"))



def _send_reset_email(user: User, reset_url: str) -> bool:
    try:
        msg = Message(
            subject="AegisShield AI – Password Reset Request",
            recipients=[user.email],
            html=render_template("email/reset_password.html", user=user, reset_url=reset_url),
        )
        mail.send(msg)
        return True
    except Exception:
        return False
