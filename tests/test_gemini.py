"""
Cyber Squad AI – Gemini Summary Service Unit Tests
"""

import pytest
from flask import Flask
from config import TestingConfig
from cybersquad.services.gemini_service import get_ai_summary, get_local_summary


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config.from_object(TestingConfig)
    return app


class TestGeminiService:
    def test_local_spam_summary(self):
        result_data = {
            "is_threat": True,
            "confidence": 98.4,
            "indicators": ["Money/prize offer detected", "Urgency language detected"],
        }
        summary = get_local_summary("spam", "Win a free gift card now!", result_data)
        assert "SPAM" in summary
        assert "98.4%" in summary
        assert "lottery" in summary or "monetary" in summary

    def test_local_phishing_summary(self):
        result_data = {
            "is_threat": True,
            "risk_score": 95.0,
            "domain": "secure-paypal-verify.xyz",
            "indicators": ["Domain mimics a trusted brand name", "Insecure HTTP connection (no HTTPS)"],
        }
        summary = get_local_summary("phishing", "http://secure-paypal-verify.xyz/login", result_data)
        assert "PHISHING" in summary
        assert "95.0/100" in summary
        assert "secure-paypal-verify.xyz" in summary

    def test_local_password_summary(self):
        result_data = {
            "strength": "WEAK",
            "score": 15,
            "entropy": 10.5,
            "crack_time": "Instantly",
            "characteristics": {"is_common_password": True, "has_sequential_chars": True},
        }
        summary = get_local_summary("password", "abc123", result_data)
        assert "WEAK" in summary
        assert "15/100" in summary
        assert "Instantly" in summary

    def test_local_malware_summary(self):
        result_data = {
            "risk_level": "CRITICAL",
            "risk_score": 95,
            "extension": ".exe",
            "file_size_human": "12.0 KB",
            "indicators": ["Double extension detected (e.g., file.pdf.exe) – classic masquerade technique"],
        }
        summary = get_local_summary("malware", "invoice.pdf.exe", result_data)
        assert "CRITICAL" in summary
        assert "95/100" in summary
        assert "masquerade" in summary or "double-extension" in summary

    def test_get_ai_summary_fallback_without_key(self, app):
        with app.app_context():
            result_data = {
                "is_threat": False,
                "confidence": 99.0,
                "indicators": [],
            }
            summary = get_ai_summary("spam", "Hi John, how are you?", result_data)
            assert "SAFE" in summary
            assert "99.0%" in summary

    def test_get_ai_summary_handles_api_exception(self, app):
        with app.app_context():
            # Force set an invalid/dummy API key to trigger request lookup
            app.config["GEMINI_API_KEY"] = "invalid_dummy_key"
            result_data = {
                "is_threat": True,
                "confidence": 98.0,
                "indicators": ["Money/prize offer detected"],
            }
            # Should not raise exception, but fallback gracefully to local summary
            summary = get_ai_summary("spam", "Get rich quick!", result_data)
            assert "SPAM" in summary
            assert "98.0%" in summary
