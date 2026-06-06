"""
Cyber Squad AI – ML Model Unit Tests
"""

import pytest
from cybersquad.ml.spam_model import get_spam_detector
from cybersquad.ml.phishing_model import get_phishing_detector, extract_url_features
from cybersquad.services.password_service import analyze_password
from cybersquad.services.malware_service import analyze_file


class TestSpamDetector:
    def test_spam_detection(self):
        detector = get_spam_detector()
        result = detector.predict("Congratulations! You've won $1000. Click now!")
        assert result['result'] in ('SPAM', 'SAFE')
        assert 0 <= result['confidence'] <= 100
        assert isinstance(result['is_threat'], bool)

    def test_ham_detection(self):
        detector = get_spam_detector()
        result = detector.predict("Hi, could we schedule a meeting at 3pm tomorrow?")
        assert result['result'] == 'SAFE'
        assert result['is_threat'] == False

    def test_obvious_spam(self):
        detector = get_spam_detector()
        result = detector.predict("FREE GIFT CARD WIN MONEY NOW CLICK URGENT")
        assert result['is_threat'] == True

    def test_returns_indicators(self):
        detector = get_spam_detector()
        result = detector.predict("Test message")
        assert isinstance(result['indicators'], list)


class TestPhishingDetector:
    def test_safe_url(self):
        detector = get_phishing_detector()
        result = detector.predict("https://www.google.com/search?q=test")
        assert result['result'] in ('PHISHING', 'SAFE')
        assert 0 <= result['risk_score'] <= 100

    def test_phishing_url(self):
        detector = get_phishing_detector()
        result = detector.predict("http://paypal-secure-login.xyz/verify/account")
        assert result['is_threat'] == True

    def test_ip_url_high_risk(self):
        detector = get_phishing_detector()
        result = detector.predict("http://192.168.1.1/banking/login.php")
        assert result['risk_score'] > 50

    def test_feature_extraction(self):
        features = extract_url_features("https://google.com")
        assert len(features) == 20
        assert all(isinstance(f, (int, float)) for f in features)


class TestPasswordService:
    def test_common_password(self):
        result = analyze_password("password")
        assert result['strength'] in ('VERY WEAK', 'WEAK')
        assert result['is_threat'] == True

    def test_strong_password(self):
        result = analyze_password("X9#mK!zL2$pQ8@nR")
        assert result['strength'] in ('STRONG', 'VERY STRONG')
        assert result['score'] >= 60

    def test_returns_recommendations(self):
        result = analyze_password("weak")
        assert len(result['recommendations']) > 0

    def test_entropy_calculation(self):
        short = analyze_password("abc")
        long = analyze_password("abcdefghijklmnop")
        assert long['entropy'] > short['entropy']

    def test_crack_time_string(self):
        result = analyze_password("password")
        assert isinstance(result['crack_time'], str)


class TestMalwareService:
    def test_exe_critical(self):
        result = analyze_file("malware.exe", 1024, b"MZ\x90\x00")
        assert result['risk_level'] == 'CRITICAL'
        assert result['is_threat'] == True

    def test_txt_low_risk(self):
        result = analyze_file("readme.txt", 512, b"Hello world")
        assert result['risk_level'] in ('LOW', 'MEDIUM')

    def test_double_extension_detected(self):
        result = analyze_file("invoice.pdf.exe", 2048, b"MZ")
        assert any('Double extension' in i for i in result['indicators'])

    def test_returns_sha256(self):
        result = analyze_file("test.txt", 100, b"test content")
        assert result['sha256'] is not None
        assert len(result['sha256']) == 64

    def test_pdf_safe(self):
        result = analyze_file("report.pdf", 50000, b"%PDF-1.7")
        assert result['extension'] == '.pdf'
        assert result['risk_level'] in ('LOW', 'MEDIUM')
