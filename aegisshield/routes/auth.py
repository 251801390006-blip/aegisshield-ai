"""
AegisShield AI – Authentication Blueprint
"""

from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message

from aegisshield.extensions import db, mail, limiter
from aegisshield.models.user import User
from aegisshield.models.otp import PasswordResetOTP
from aegisshield.forms import LoginForm, RegistrationForm, ForgotPasswordForm, ResetPasswordForm, OTPResetForm
import random
from datetime import timedelta

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


# ── Forgot Password ───────────────────────────────────────────────────────────

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("200 per hour")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user:
            # Generate 6-digit OTP code
            otp_code = str(random.randint(100000, 999999))
            
            # Delete any existing OTP records for this email
            PasswordResetOTP.query.filter_by(email=user.email).delete()
            
            # Create new OTP record (expires in 15 minutes)
            expires_at = datetime.utcnow() + timedelta(minutes=15)
            otp_record = PasswordResetOTP(
                email=user.email,
                otp_code=otp_code,
                expires_at=expires_at
            )
            db.session.add(otp_record)
            db.session.commit()
            
            # Send OTP email
            sent = _send_reset_otp_email(user, otp_code)
            
            return render_template(
                "auth/forgot_password.html",
                form=form,
                title="Forgot Password",
                success=True,
                otp_code=otp_code,
                email=user.email,
                sent=sent
            )
        else:
            form.email.errors.append("This email address is not registered in our system.")

    return render_template("auth/forgot_password.html", form=form, title="Forgot Password")


# ── Reset Password (OTP) ──────────────────────────────────────────────────────

@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = OTPResetForm()
    
    # Prefill email if provided in query params (GET request)
    if request.method == "GET" and "email" in request.args:
        form.email.data = request.args.get("email")

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        otp_code = form.otp_code.data.strip()
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            form.email.errors.append("This email address is not registered in our system.")
            return render_template("auth/reset_password.html", form=form, title="Reset Password")
            
        # Find latest OTP record for this email
        otp_record = PasswordResetOTP.query.filter_by(email=email).order_by(PasswordResetOTP.created_at.desc()).first()
        
        if not otp_record or otp_record.otp_code != otp_code:
            form.otp_code.errors.append("Invalid OTP code. Please check and try again.")
            return render_template("auth/reset_password.html", form=form, title="Reset Password")
            
        if otp_record.is_expired():
            form.otp_code.errors.append("This OTP code has expired. Please request a new one.")
            return render_template("auth/reset_password.html", form=form, title="Reset Password")
            
        # OTP is valid! Reset password
        user.set_password(form.password.data)
        
        # Clean up the OTP record
        PasswordResetOTP.query.filter_by(email=email).delete()
        db.session.commit()
        
        flash("Your password has been reset successfully! Please log in with your new password.", "success")
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
        # Delete OTP records
        PasswordResetOTP.query.delete()
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


# ── Helper ────────────────────────────────────────────────────────────────────

def _send_reset_otp_email(user: User, otp_code: str) -> bool:
    try:
        msg = Message(
            subject="AegisShield AI – Password Reset OTP",
            recipients=[user.email],
            html=f"<p>Hello {user.username},</p><p>Your password reset OTP is: <strong>{otp_code}</strong></p><p>This OTP will expire in 15 minutes.</p>",
        )
        mail.send(msg)
        return True
    except Exception:
        return False
