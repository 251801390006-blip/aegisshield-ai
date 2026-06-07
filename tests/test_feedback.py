"""
Cyber Squad AI – Feedback System Unit Tests
"""

import pytest
from cybersquad import create_app
from cybersquad.extensions import db
from config import TestingConfig
from cybersquad.models.user import User
from cybersquad.models.feedback import FeedbackItem, FeedbackReply


@pytest.fixture
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def users(app):
    """Create test users: a standard user, another standard user, and an admin."""
    with app.app_context():
        u1 = User(username="user1", email="user1@example.com", role="user")
        u1.set_password("Pass@1234")
        u2 = User(username="user2", email="user2@example.com", role="user")
        u2.set_password("Pass@1234")
        admin = User(username="admin", email="admin@example.com", role="admin")
        admin.set_password("Pass@1234")

        db.session.add_all([u1, u2, admin])
        db.session.commit()

        return {
            "user1": {"id": u1.id, "email": u1.email, "username": u1.username, "password": "Pass@1234"},
            "user2": {"id": u2.id, "email": u2.email, "username": u2.username, "password": "Pass@1234"},
            "admin": {"id": admin.id, "email": admin.email, "username": admin.username, "password": "Pass@1234"},
        }


def login(client, email, password):
    return client.post('/auth/login', data={
        'email': email,
        'password': password
    }, follow_redirects=True)


class TestFeedbackRoutes:
    def test_requires_login(self, client):
        resp = client.get('/feedback/')
        assert resp.status_code == 302
        assert '/auth/login' in resp.location

    def test_suggestions_visible_to_all(self, client, users):
        # 1. Create a public suggestion by user1
        login(client, users["user1"]["email"], users["user1"]["password"])
        resp = client.post('/feedback/submit', data={
            'title': 'Awesome suggestion',
            'category': 'suggestion',
            'content': 'We should add dark mode.'
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'Awesome suggestion' in resp.data

        # Logout user1
        client.get('/auth/logout')

        # 2. Login as user2, suggestion should be visible
        login(client, users["user2"]["email"], users["user2"]["password"])
        resp = client.get('/feedback/')
        assert resp.status_code == 200
        assert b'Awesome suggestion' in resp.data

    def test_support_tickets_private(self, client, users):
        # 1. Create a private bug ticket by user1
        login(client, users["user1"]["email"], users["user1"]["password"])
        resp = client.post('/feedback/submit', data={
            'title': 'Critical Bug in scanner',
            'category': 'bug',
            'content': 'App crashes on large inputs'
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'Critical Bug in scanner' in resp.data

        # Get user1's ticket ID
        with client.application.app_context():
            ticket = FeedbackItem.query.filter_by(title='Critical Bug in scanner').first()
            ticket_id = ticket.id
            assert ticket.is_public is False

        # Logout user1
        client.get('/auth/logout')

        # 2. Login as user2, ticket should NOT be visible in dashboard, and direct access should be Forbidden
        login(client, users["user2"]["email"], users["user2"]["password"])
        resp = client.get('/feedback/')
        assert b'Critical Bug in scanner' not in resp.data

        resp_detail = client.get(f'/feedback/{ticket_id}')
        assert resp_detail.status_code == 403

        # Logout user2
        client.get('/auth/logout')

        # 3. Login as admin, ticket SHOULD be visible and accessible
        login(client, users["admin"]["email"], users["admin"]["password"])
        resp_admin = client.get('/feedback/')
        assert b'Critical Bug in scanner' in resp_admin.data

        resp_admin_detail = client.get(f'/feedback/{ticket_id}')
        assert resp_admin_detail.status_code == 200
        assert b'Critical Bug in scanner' in resp_admin_detail.data

    def test_reply_to_feedback(self, client, users):
        # 1. Create a suggestion
        login(client, users["user1"]["email"], users["user1"]["password"])
        client.post('/feedback/submit', data={
            'title': 'Test Suggestion',
            'category': 'suggestion',
            'content': 'Test suggestion content.'
        })

        with client.application.app_context():
            item = FeedbackItem.query.filter_by(title='Test Suggestion').first()
            item_id = item.id

        # 2. Post a reply
        resp = client.post(f'/feedback/{item_id}', data={
            'content': 'I agree with this!'
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'I agree with this!' in resp.data

        # Verify reply was added to DB
        with client.application.app_context():
            replies = FeedbackReply.query.filter_by(feedback_item_id=item_id).all()
            assert len(replies) == 1
            assert replies[0].content == 'I agree with this!'

    def test_status_update(self, client, users):
        # 1. Create a ticket
        login(client, users["user1"]["email"], users["user1"]["password"])
        client.post('/feedback/submit', data={
            'title': 'Bug to close',
            'category': 'bug',
            'content': 'Test bug to close.'
        })

        with client.application.app_context():
            item = FeedbackItem.query.filter_by(title='Bug to close').first()
            item_id = item.id
            assert item.status == 'open'

        # 2. Standard user (creator) can change status
        resp = client.post(f'/feedback/{item_id}/status', data={
            'status': 'resolved'
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'Resolved' in resp.data or b'RESOLVED' in resp.data

        with client.application.app_context():
            item = db.session.get(FeedbackItem, item_id)
            assert item.status == 'resolved'

        # Logout user1
        client.get('/auth/logout')

        # 3. Another user cannot toggle status (Forbidden)
        login(client, users["user2"]["email"], users["user2"]["password"])
        resp = client.post(f'/feedback/{item_id}/status', data={
            'status': 'open'
        })
        assert resp.status_code == 403
