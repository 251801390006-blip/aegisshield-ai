"""
AegisShield AI – Phishing URL Detection ML Model

Feature-based detection combining URL heuristics with ML classification.
"""

import os
import re
import math
import logging
import joblib
import numpy as np
from urllib.parse import urlparse, parse_qs

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)

_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(_DIR, "saved_models", "phishing_model.joblib")

# ── Known suspicious TLDs & patterns ────────────────────────────────────────
SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".click", ".download", ".gq", ".ru"}
TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "github.com", "stackoverflow.com", "linkedin.com", "twitter.com", "youtube.com",
    "paypal.com", "netflix.com", "adobe.com", "dropbox.com", "slack.com",
}
PHISHING_KEYWORDS = [
    "login", "secure", "update", "verify", "account", "banking", "confirm",
    "password", "signin", "paypal", "ebay", "amazon", "apple", "microsoft",
    "support", "suspended", "blocked", "unlock", "urgent", "alert",
]

# ── Training data generation ─────────────────────────────────────────────────

def _generate_training_data():
    """Generate synthetic training data from URL feature extraction."""
    phishing_urls = [
        "http://paypal-secure-login.xyz/verify/account",
        "http://192.168.1.1/banking/login.php",
        "http://google.com.phishing-site.ru/accounts",
        "http://secure-apple-id-verify.tk/login",
        "http://amazon-update-billing.click/payment",
        "http://microsoft-support-alert.ga/windows/update",
        "http://ebay.com.account-verify.xyz/signin",
        "http://paypa1.com/account/suspended",
        "http://amaz0n-prime.xyz/login/verify",
        "https://secure-login-bank.cf/auth/verify",
        "http://update-your-password-now.tk/account",
        "http://facebook-login-verify.ml/signin",
        "http://chase-bank-secure.xyz/online/login",
        "http://netflix-billing-update.click/payment",
        "http://apple-id-locked-verify.gq/login",
        "http://bit.ly/3xM9pQr",
        "http://tinyurl.com/verify-account-2024",
        "http://194.27.131.45/login",
        "http://secure-paypal.com-login.tk/verify",
        "http://walmart-gift-card-claim.xyz/free",
        "https://netflix-account.verify.click/update/billing",
        "http://login.amazon.com.account-check.ru/signin",
        "http://support-microsoft-alert.xyz/windows",
        "https://bankofamerica.secure-login.ml/access",
        "http://irs-refund-verify.tk/tax/return",
    ]

    legitimate_urls = [
        "https://www.google.com/search?q=cybersecurity",
        "https://github.com/user/repository",
        "https://stackoverflow.com/questions/12345678",
        "https://www.linkedin.com/in/username",
        "https://docs.python.org/3/library/os.html",
        "https://flask.palletsprojects.com/en/3.0.x/",
        "https://www.amazon.com/product/dp/B08N5WRWNW",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://twitter.com/username/status/123456",
        "https://www.microsoft.com/en-us/microsoft-365",
        "https://support.apple.com/en-us/HT204074",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://www.cloudflare.com/learning/",
        "https://news.ycombinator.com/item?id=12345",
        "https://medium.com/@author/article-title",
        "https://www.paypal.com/us/webapps/mpp/home",
        "https://www.netflix.com/browse",
        "https://accounts.google.com/signin",
        "https://login.microsoftonline.com/",
        "https://www.reddit.com/r/netsec/",
        "https://arxiv.org/abs/2401.12345",
        "https://www.facebook.com/groups/security",
        "https://www.dropbox.com/home",
        "https://slack.com/workspace/channel",
        "https://www.adobe.com/products/acrobat.html",
    ]

    all_urls = phishing_urls + legitimate_urls
    labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)

    # Augment
    all_urls = all_urls * 30
    labels = labels * 30

    features = [extract_url_features(u) for u in all_urls]
    return np.array(features), np.array(labels)


def extract_url_features(url: str) -> list:
    """Extract numerical features from a URL for ML classification."""
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return [0] * 20

    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = url.lower()

    # Feature list
    f = []

    # 1. URL length
    f.append(len(url))
    # 2. Domain length
    f.append(len(domain))
    # 3. Path length
    f.append(len(path))
    # 4. Number of dots in domain
    f.append(domain.count("."))
    # 5. Number of hyphens in domain
    f.append(domain.count("-"))
    # 6. Has IP address
    f.append(1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 0)
    # 7. Uses HTTP (not HTTPS)
    f.append(1 if parsed.scheme == "http" else 0)
    # 8. Number of slashes in path
    f.append(path.count("/"))
    # 9. Number of query params
    f.append(len(parse_qs(parsed.query)))
    # 10. Has suspicious TLD
    tld = "." + domain.split(".")[-1] if "." in domain else ""
    f.append(1 if tld in SUSPICIOUS_TLDS else 0)
    # 11. Phishing keyword count
    kw_count = sum(1 for kw in PHISHING_KEYWORDS if kw in full_url)
    f.append(kw_count)
    # 12. Domain contains digits
    f.append(1 if re.search(r"\d", domain) else 0)
    # 13. URL entropy
    f.append(_entropy(url))
    # 14. Has @ symbol (URL redirection trick)
    f.append(1 if "@" in url else 0)
    # 15. Has double slash in path
    f.append(1 if "//" in path else 0)
    # 16. Is URL shortener
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
    f.append(1 if any(s in domain for s in shorteners) else 0)
    # 17. Domain mimics trusted brand
    f.append(1 if _mimics_brand(domain) else 0)
    # 18. Special char count
    special = sum(1 for c in url if c in "!#$%^&*()_+=[]{}|;':\"<>?,")
    f.append(special)
    # 19. Subdomain count
    parts = [p for p in domain.split(".") if p]
    f.append(max(0, len(parts) - 2))
    # 20. Has hex encoding
    f.append(1 if re.search(r"%[0-9a-fA-F]{2}", url) else 0)

    return f


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def _mimics_brand(domain: str) -> bool:
    brands = ["paypal", "amazon", "google", "microsoft", "apple", "facebook",
              "netflix", "ebay", "chase", "wellsfargo", "bankofamerica"]
    clean = domain.replace("-", "").replace(".", "")
    for brand in brands:
        if brand in clean and not any(domain == td or domain.endswith("." + td) for td in TRUSTED_DOMAINS):
            return True
    return False


# ── Model class ────────────────────────────────────────────────────────────────

class PhishingDetector:
    def __init__(self):
        self._model = None
        self._loaded = False
        self._load_or_train()

    def _load_or_train(self):
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        if os.path.exists(MODEL_PATH):
            try:
                self._model = joblib.load(MODEL_PATH)
                self._loaded = True
                logger.info("Phishing model loaded from disk.")
                return
            except Exception as e:
                logger.warning(f"Failed to load phishing model: {e}. Retraining.")
        self._train()

    def _train(self):
        X, y = _generate_training_data()
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

        self._model = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)),
        ])
        self._model.fit(X_train, y_train)

        accuracy = self._model.score(X_test, y_test)
        logger.info(f"Phishing model trained. Test accuracy: {accuracy:.3f}")

        joblib.dump(self._model, MODEL_PATH)
        self._loaded = True

    def predict(self, url: str) -> dict:
        if not self._loaded:
            return {"result": "ERROR", "risk_score": 0, "is_threat": False}

        features = extract_url_features(url)
        X = np.array(features).reshape(1, -1)
        proba = self._model.predict_proba(X)[0]
        phishing_prob = float(proba[1])
        is_phishing = bool(phishing_prob >= 0.5)
        risk_score = float(round(phishing_prob * 100, 2))

        indicators = self._get_indicators(url, features)
        domain = urlparse(url if "://" in url else "http://" + url).netloc

        return {
            "result": "PHISHING" if is_phishing else "SAFE",
            "risk_score": risk_score,
            "phishing_probability": float(round(phishing_prob * 100, 2)),
            "safe_probability": float(round((1 - phishing_prob) * 100, 2)),
            "is_threat": is_phishing,
            "domain": domain,
            "indicators": indicators,
            "features": {
                "url_length": int(features[0]),
                "domain_length": int(features[1]),
                "has_ip": bool(features[5]),
                "uses_http": bool(features[6]),
                "suspicious_tld": bool(features[9]),
                "phishing_keywords": int(features[10]),
                "entropy": float(round(features[12], 2)),
                "mimics_brand": bool(features[16]),
                "is_shortener": bool(features[15]),
            },
            "recommendation": self._get_recommendation(is_phishing, indicators, risk_score),
        }

    def _get_indicators(self, url: str, features: list) -> list:
        flags = []
        if features[5]: flags.append("IP address used instead of domain name")
        if features[6]: flags.append("Insecure HTTP connection (no HTTPS)")
        if features[9]: flags.append("Suspicious top-level domain detected")
        if features[10] >= 2: flags.append(f"{features[10]} phishing keywords found in URL")
        if features[12] > 4.5: flags.append("High URL entropy (obfuscated URL)")
        if features[13]: flags.append("@ symbol in URL (redirection trick)")
        if features[15]: flags.append("URL shortener detected (destination unknown)")
        if features[16]: flags.append("Domain mimics a trusted brand name")
        if features[18] > 2: flags.append("Excessive subdomain levels detected")
        if features[0] > 100: flags.append("Unusually long URL")
        return flags

    def _get_recommendation(self, is_phishing: bool, indicators: list, score: float) -> str:
        if not is_phishing:
            return f"URL appears legitimate (risk score: {score}%). Verify the domain before entering credentials."
        recs = ["Do NOT visit this URL.", "Do NOT enter any personal information."]
        if "Insecure HTTP connection" in " ".join(indicators):
            recs.append("This site does not use HTTPS encryption.")
        if "mimics" in " ".join(indicators):
            recs.append("The domain appears to impersonate a trusted website.")
        recs.append("Report this URL to your IT security team.")
        return " ".join(recs)


_detector: PhishingDetector | None = None


def get_phishing_detector() -> PhishingDetector:
    global _detector
    if _detector is None:
        _detector = PhishingDetector()
    return _detector
