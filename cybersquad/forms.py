"""
Cyber Squad AI – WTForms Form Definitions
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Regexp
from cybersquad.models.user import User


# ── Authentication Forms ─────────────────────────────────────────────────────

class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=80),
            Regexp(r"^[A-Za-z0-9_]+$", message="Username may only contain letters, numbers, and underscores."),
        ],
    )
    email = StringField(
        "Email",
        validators=[
            DataRequired(),
            Regexp(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", message="Invalid email address format.")
        ]
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters."),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Create Account")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError("Username already taken. Choose a different one.")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError("An account with this email already exists.")


class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[
            DataRequired(),
            Regexp(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", message="Invalid email address format.")
        ]
    )
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")


class ForgotPasswordForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[
            DataRequired(),
            Regexp(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", message="Invalid email address format.")
        ]
    )
    submit = SubmitField("Send Reset Link")


class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        "New Password",
        validators=[DataRequired(), Length(min=8)],
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Reset Password")


class OTPResetForm(FlaskForm):
    email = StringField(
        "Email Address",
        validators=[
            DataRequired(),
            Regexp(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", message="Invalid email address format.")
        ]
    )
    otp_code = StringField("6-Digit OTP Code", validators=[DataRequired(), Length(min=6, max=6, message="OTP must be exactly 6 digits.")])
    password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters."),
        ],
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Reset Password & Sign In")



# ── Profile Form ──────────────────────────────────────────────────────────────

class ProfileForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    bio = TextAreaField("Bio", validators=[Length(max=500)])
    submit = SubmitField("Update Profile")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("new_password")],
    )
    submit = SubmitField("Change Password")
