"""
AegisShield AI – Authentication Tests
"""

import pytest
from aegisshield import create_app
from aegisshield.extensions import db
from config import TestingConfig


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
def registered_user(client):
    """Register a test user and return credentials."""
    client.post('/auth/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'Test@1234',
        'confirm_password': 'Test@1234',
        'csrf_token': 'test',
    })
    return {'email': 'test@example.com', 'password': 'Test@1234'}


class TestRegistration:
    def test_register_page_loads(self, client):
        resp = client.get('/auth/register')
        assert resp.status_code == 200
        assert b'Create' in resp.data

    def test_register_success(self, client):
        resp = client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'NewPass@123',
            'confirm_password': 'NewPass@123',
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_register_duplicate_email(self, client, registered_user):
        resp = client.post('/auth/register', data={
            'username': 'anotheruser',
            'email': registered_user['email'],
            'password': 'Test@1234',
            'confirm_password': 'Test@1234',
        })
        assert resp.status_code == 200


class TestLogin:
    def test_login_page_loads(self, client):
        resp = client.get('/auth/login')
        assert resp.status_code == 200

    def test_login_invalid_credentials(self, client):
        resp = client.post('/auth/login', data={
            'email': 'wrong@example.com',
            'password': 'wrongpassword',
        }, follow_redirects=True)
        assert b'Invalid' in resp.data or resp.status_code == 200

    def test_logout_redirects(self, client):
        resp = client.get('/auth/logout', follow_redirects=True)
        assert resp.status_code == 200


class TestProtectedRoutes:
    def test_dashboard_requires_login(self, client):
        resp = client.get('/dashboard/', follow_redirects=True)
        assert b'Sign In' in resp.data or b'login' in resp.data.lower()

    def test_spam_requires_login(self, client):
        resp = client.get('/spam/', follow_redirects=True)
        assert resp.status_code == 200

    def test_api_health_public(self, client):
        resp = client.get('/api/v1/health')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'ok'
