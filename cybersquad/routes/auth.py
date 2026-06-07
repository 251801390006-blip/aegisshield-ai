"""
Cyber Squad AI – Authentication Blueprint
"""

from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message

from cybersquad.extensions import db, mail, limiter
from cybersquad.models.user import User
from cybersquad.models.otp import PasswordResetOTP
from cybersquad.forms import LoginForm, RegistrationForm, ForgotPasswordForm, ResetPasswordForm, OTPResetForm
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
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        if not user:
            # Auto-register unregistered email address on-the-fly for testing/convenience
            base_username = email.split('@')[0]
            username = base_username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1
            user = User(
                username=username,
                email=email,
                role="user"
            )
            user.set_password("TempPassword@1234")
            db.session.add(user)
            db.session.commit()

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

    return render_template("auth/forgot_password.html", form=form, title="Forgot Password")


# ── Reset Password (OTP) ──────────────────────────────────────────────────────

@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = OTPResetForm()
    
    # Prefill email and otp_code if provided in query params (GET request)
    if request.method == "GET":
        if "email" in request.args:
            form.email.data = request.args.get("email")
        if "otp_code" in request.args:
            form.otp_code.data = request.args.get("otp_code")

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


# ── Account Switching ──────────────────────────────────────────────────────────

@auth_bp.route("/switch-account/<role>", methods=["GET", "POST"])
def switch_account(role):
    # Log out current user
    if current_user.is_authenticated:
        logout_user()
    
    # Determine target email based on role
    if role == "admin":
        email = "251801390006@cutmap.ac.in"
    elif role == "demo":
        email = "demo@cybersquad.io"
    else:
        flash("Invalid role for quick access.", "danger")
        return redirect(url_for("auth.login"))
        
    user = User.query.filter_by(email=email).first()
    if not user:
        # Seed users if they are missing
        from cybersquad.__init__ import _seed_demo_data
        from flask import current_app
        _seed_demo_data(current_app)
        user = User.query.filter_by(email=email).first()
        if not user:
            if role == "admin":
                user = User(
                    username="admin_user",
                    email=email,
                    role="admin"
                )
                user.set_password("Vanjith@2008")
            else:
                user = User(
                    username="demo_user",
                    email=email,
                    role="user"
                )
                user.set_password("Demo@1234")
            db.session.add(user)
            db.session.commit()
        
    if user:
        login_user(user)
        user.update_last_login()
        flash(f"Switched account to {user.username} ({user.role.capitalize()})", "success")
        return redirect(url_for("dashboard.index"))
        
    flash("Demo accounts could not be loaded. Please run DB reset.", "danger")
    return redirect(url_for("auth.login"))


# ── Emergency Reset ───────────────────────────────────────────────────────────

@auth_bp.route("/emergency-reset-db", methods=["GET"])
def emergency_reset():
    """Emergency reset via secure query parameter (/?secret=AegisReset2026) to clear custom data and presets."""
    secret = request.args.get("secret")
    if secret != "AegisReset2026":
        from flask import abort
        abort(403)
        
    from cybersquad.models.scan_history import ScanHistory
    from cybersquad.models.threat_report import ThreatReport
    from cybersquad.__init__ import _seed_demo_data
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
            subject="Cyber Squad AI – Password Reset OTP",
            recipients=[user.email],
            html=f"<p>Hello {user.username},</p><p>Your password reset OTP is: <strong>{otp_code}</strong></p><p>This OTP will expire in 15 minutes.</p>",
        )
        mail.send(msg)
        return True
    except Exception as e:
        import sys
        print(f"\n[EMAIL SIMULATION] To: {user.email}", file=sys.stderr)
        print(f"Subject: Cyber Squad AI – Password Reset OTP", file=sys.stderr)
        print(f"Body: Hello {user.username}, your password reset OTP is {otp_code}", file=sys.stderr)
        print(f"Error details: {str(e)}\n", file=sys.stderr)
        return False
