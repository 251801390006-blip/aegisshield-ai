"""
Cyber Squad AI – Feedback and Suggestions Models
"""

from datetime import datetime, timezone
from cybersquad.extensions import db


class FeedbackItem(db.Model):
    __tablename__ = "feedback_items"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)  # suggestion, bug, issue, feature_request
    is_public = db.Column(db.Boolean, nullable=False, default=False)
    status = db.Column(db.String(20), nullable=False, default="open")  # open, resolved
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    user = db.relationship("User", backref=db.backref("feedback_items", lazy="dynamic"))
    replies = db.relationship("FeedbackReply", backref="feedback_item", cascade="all, delete-orphan", order_by="FeedbackReply.created_at")

    def __repr__(self):
        return f"<FeedbackItem {self.category}:{self.id} {self.title[:20]}>"


class FeedbackReply(db.Model):
    __tablename__ = "feedback_replies"

    id = db.Column(db.Integer, primary_key=True)
    feedback_item_id = db.Column(db.Integer, db.ForeignKey("feedback_items.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    user = db.relationship("User", backref=db.backref("feedback_replies", lazy="dynamic"))

    def __repr__(self):
        return f"<FeedbackReply {self.id} for Item {self.feedback_item_id}>"
