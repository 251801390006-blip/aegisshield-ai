"""
Cyber Squad AI – Feedback and Suggestions Blueprint
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from cybersquad.extensions import db
from cybersquad.models.feedback import FeedbackItem, FeedbackReply
from cybersquad.models.user import User

feedback_bp = Blueprint("feedback", __name__)


@feedback_bp.route("/")
@login_required
def index():
    # Admins see all private support tickets; regular users see only their own.
    if current_user.role == "admin":
        support_tickets = FeedbackItem.query.filter(FeedbackItem.is_public == False).order_by(FeedbackItem.created_at.desc()).all()
    else:
        support_tickets = FeedbackItem.query.filter(FeedbackItem.is_public == False, FeedbackItem.user_id == current_user.id).order_by(FeedbackItem.created_at.desc()).all()

    # All users see all public suggestions.
    suggestions = FeedbackItem.query.filter(FeedbackItem.is_public == True).order_by(FeedbackItem.created_at.desc()).all()

    return render_template(
        "feedback/index.html",
        title="Support & Feedback",
        support_tickets=support_tickets,
        suggestions=suggestions,
    )


@feedback_bp.route("/submit", methods=["GET", "POST"])
@login_required
def submit():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not category or not content:
            flash("All fields are required.", "danger")
            return redirect(url_for("feedback.submit"))

        if category not in ["suggestion", "bug", "issue", "feature_request"]:
            flash("Invalid feedback category selected.", "danger")
            return redirect(url_for("feedback.submit"))

        # Suggestions are public; bugs, technical issues, and feature requests are private.
        is_public = (category == "suggestion")

        item = FeedbackItem(
            user_id=current_user.id,
            title=title,
            category=category,
            content=content,
            is_public=is_public,
            status="open",
        )
        db.session.add(item)
        db.session.commit()

        flash("Thank you for your submission!", "success")
        return redirect(url_for("feedback.detail", item_id=item.id))

    return render_template("feedback/submit.html", title="Submit Feedback")


@feedback_bp.route("/<int:item_id>", methods=["GET", "POST"])
@login_required
def detail(item_id):
    item = db.get_or_404(FeedbackItem, item_id)

    # Permission checks:
    # 1. Public suggestions are visible to all users.
    # 2. Private support tickets (bugs, issues, feature requests) are only visible to the creator and admin.
    if not item.is_public and current_user.role != "admin" and item.user_id != current_user.id:
        abort(403)

    if request.method == "POST":
        reply_content = request.form.get("content", "").strip()
        if not reply_content:
            flash("Reply content cannot be empty.", "danger")
            return redirect(url_for("feedback.detail", item_id=item_id))

        reply = FeedbackReply(
            feedback_item_id=item.id,
            user_id=current_user.id,
            content=reply_content,
        )
        db.session.add(reply)
        db.session.commit()

        flash("Comment posted successfully.", "success")
        return redirect(url_for("feedback.detail", item_id=item_id))

    return render_template(
        "feedback/detail.html",
        title=item.title,
        item=item,
    )


@feedback_bp.route("/<int:item_id>/status", methods=["POST"])
@login_required
def update_status(item_id):
    item = db.get_or_404(FeedbackItem, item_id)

    # Only the creator of the feedback item or an admin can change its status.
    if current_user.role != "admin" and item.user_id != current_user.id:
        abort(403)

    new_status = request.form.get("status", "").strip()
    if new_status in ["open", "resolved"]:
        item.status = new_status
        db.session.commit()
        flash(f"Status successfully updated to {new_status.capitalize()}.", "success")
    else:
        flash("Invalid status value.", "danger")

    return redirect(url_for("feedback.detail", item_id=item.id))
