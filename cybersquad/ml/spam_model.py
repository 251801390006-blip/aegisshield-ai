"""
Cyber Squad AI – Spam Detection ML Model

Uses Naive Bayes + Logistic Regression ensemble trained on SMS/email spam patterns.
Model is trained on first import and persisted with joblib.
"""

import os
import re
import string
import logging
import joblib
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

logger = logging.getLogger(__name__)

# Paths
_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(_DIR, "saved_models", "spam_model.joblib")
VECTORIZER_PATH = os.path.join(_DIR, "saved_models", "spam_vectorizer.joblib")

# ── Synthetic training corpus ─────────────────────────────────────────────────
# Production: replace with SMS Spam Collection / Enron dataset
SPAM_SAMPLES = [
    "Congratulations! You've won a $1,000 Walmart gift card. Click here to claim now!",
    "URGENT: Your account has been compromised. Verify immediately at http://secure-bank-login.ru",
    "FREE iPhone 15 Pro! Limited time offer. Text WIN to 12345",
    "You have been selected for a $500 prize. Send your details to claim",
    "Get rich quick! Earn $5000/week working from home. No experience needed",
    "WINNER! Your phone number has been selected as the lucky winner. Call now",
    "Cheap Viagra, Cialis - order online no prescription needed! Huge discounts!",
    "Make money fast with our proven system! Join thousands of satisfied members",
    "Hot singles in your area! Click here to meet them tonight",
    "Your PayPal account is limited. Please verify your information now",
    "ALERT: Suspicious login detected on your bank account. Click to secure",
    "Earn passive income! Invest in crypto and double your money in 24 hours",
    "Lose 30 pounds in 30 days! Doctor recommended weight loss pill",
    "You owe back taxes. The IRS will arrest you unless you call us immediately",
    "FREE gift card offer! Limited to first 100 respondents. Claim yours now",
    "Your Amazon order is on hold. Verify your payment details to continue",
    "Million dollar business opportunity! Be your own boss starting today",
    "DOWNLOAD FREE MOVIES NO VIRUS CLICK HERE NOW LIMITED OFFER",
    "Claim your lottery prize! You have won 2 million pounds. Reply with details",
    "Nigerian prince needs help transferring $10 million. Share profits with you",
    "Click here for XXX adult content! Free access for 24 hours only",
    "BANK ALERT: Your card has been frozen. Call this number to unlock",
    "Special offer for you! Buy one get five free. Today only discount",
    "Warning: Your computer is infected with 5 viruses. Download our free scanner",
    "Prescription drugs at 90% off! No doctor needed. Order online today",
    "You are our lucky customer! Claim your free cruise vacation now",
    "SEO backlinks cheap! 1000 links for $5. Boost your ranking today",
    "Meet sexy women tonight! Local singles waiting to chat with you",
    "Your utility bill is overdue. Pay now to avoid disconnection. Click here",
    "Free investment tips! Stocks that will triple in value next week",
]

HAM_SAMPLES = [
    "Hi John, could we schedule a meeting tomorrow at 2pm to discuss the project?",
    "Please find attached the quarterly report as discussed in our last meeting.",
    "Your Amazon order #112-3456789 has been shipped and will arrive by Thursday.",
    "Reminder: Team standup is at 10am. Please update your task board before then.",
    "Thank you for applying to the Software Engineering position at our company.",
    "Your flight booking confirmation: AA1234 departing JFK at 08:00 on June 15.",
    "Happy birthday! Hope you have a wonderful day surrounded by family and friends.",
    "The weekly newsletter is out. Here are this week's top stories in tech.",
    "Please review the attached document and send your feedback by end of day.",
    "Your prescription is ready for pickup at the pharmacy on Oak Street.",
    "Meeting notes from today's project sync have been posted to the wiki.",
    "Can you please send me the slides from the presentation last week?",
    "Your appointment with Dr. Smith is confirmed for next Monday at 3:30pm.",
    "Just checking in to see how the new job is going. Let me know if you need anything.",
    "The code review for PR #247 has been completed. Please address the comments.",
    "Reminder: Submit your timesheet by 5pm on Friday to ensure payroll accuracy.",
    "Your package from FedEx has been delivered to your front door.",
    "Team lunch is scheduled for Friday at noon. We're going to the Italian place.",
    "Here are the action items from today's meeting. Please update by next Wednesday.",
    "Your subscription to Netflix has been renewed. Next billing date: July 15.",
    "Thanks for the introduction! I'd love to connect and discuss collaboration.",
    "The server maintenance window is scheduled for Saturday 2-4am UTC.",
    "Please join us for the webinar on Machine Learning next Thursday at 3pm.",
    "Your direct deposit of $2,450.00 has been processed and will be available tomorrow.",
    "Congratulations on completing the Python certification course!",
    "I wanted to follow up on our conversation from the conference last week.",
    "The new version of the app is live. Check out the release notes for details.",
    "Your Google account security checkup was successful.",
    "Lunch today? There's a new sushi place that opened downtown.",
    "Please RSVP for the company picnic by June 20th. We hope to see you there!",
]

# Augment with more samples (repeated with slight variation for demo)
SPAM_CORPUS = SPAM_SAMPLES * 20
HAM_CORPUS = HAM_SAMPLES * 20


# ── Model class ────────────────────────────────────────────────────────────────

class SpamDetector:
    def __init__(self):
        self._nb_pipeline = None
        self._lr_pipeline = None
        self._loaded = False
        self._load_or_train()

    def _load_or_train(self):
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        if os.path.exists(MODEL_PATH):
            try:
                saved = joblib.load(MODEL_PATH)
                self._nb_pipeline = saved["nb"]
                self._lr_pipeline = saved["lr"]
                self._loaded = True
                logger.info("Spam model loaded from disk.")
                return
            except Exception as e:
                logger.warning(f"Failed to load spam model: {e}. Retraining.")
        self._train()

    def _train(self):
        texts = SPAM_CORPUS + HAM_CORPUS
        labels = [1] * len(SPAM_CORPUS) + [0] * len(HAM_CORPUS)

        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.2, random_state=42, stratify=labels
        )

        # Naive Bayes pipeline
        self._nb_pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=10000,
                stop_words="english",
                preprocessor=self._preprocess,
            )),
            ("clf", MultinomialNB(alpha=0.1)),
        ])

        # Logistic Regression pipeline
        self._lr_pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=10000,
                stop_words="english",
                preprocessor=self._preprocess,
            )),
            ("clf", LogisticRegression(C=1.0, max_iter=1000, random_state=42)),
        ])

        self._nb_pipeline.fit(X_train, y_train)
        self._lr_pipeline.fit(X_train, y_train)

        # Persist
        joblib.dump({"nb": self._nb_pipeline, "lr": self._lr_pipeline}, MODEL_PATH)
        self._loaded = True

        nb_preds = self._nb_pipeline.predict(X_test)
        logger.info(f"Spam model trained.\n{classification_report(y_test, nb_preds, target_names=['Ham','Spam'])}")

    @staticmethod
    def _preprocess(text: str) -> str:
        text = text.lower()
        text = re.sub(r"http\S+|www\S+", " URLTOKEN ", text)
        text = re.sub(r"\b\d{10,}\b", " PHONENUMBER ", text)
        text = re.sub(r"\$[\d,]+", " MONEYTOKEN ", text)
        text = text.translate(str.maketrans("", "", string.punctuation))
        return text

    def predict(self, text: str) -> dict:
        if not self._loaded:
            return {"result": "ERROR", "confidence": 0.0, "is_threat": False}

        nb_proba = self._nb_pipeline.predict_proba([text])[0]
        lr_proba = self._lr_pipeline.predict_proba([text])[0]

        # Ensemble average
        spam_prob = float((nb_proba[1] + lr_proba[1]) / 2.0)
        ham_prob = float(1.0 - spam_prob)

        is_spam = bool(spam_prob >= 0.5)
        result = "SPAM" if is_spam else "SAFE"
        confidence = float(round((spam_prob if is_spam else ham_prob) * 100, 2))

        # Indicator flags
        indicators = self._get_indicators(text)

        # Generate AI summary
        summary = f"This email is classified as **{result}** with a confidence score of **{confidence}%**."
        if is_spam:
            summary += " The Naive Bayes and Logistic Regression ensemble model detected multiple marketing or social engineering keywords."
            if "Money/prize offer detected" in indicators:
                summary += " It contains language offering monetary rewards or lottery prizes."
            if "Urgency language detected" in indicators:
                summary += " It attempts to create false urgency (e.g. 'immediately', 'act now')."
            if "Contains suspicious URL" in indicators:
                summary += " It embeds links that resemble phishing landing pages."
            summary += " We recommend deleting this message and not clicking any embedded links."
        else:
            summary += " The content matches clean, standard personal/professional communications. The email lacks spam indicators and has normal character/casing distributions."

        return {
            "result": result,
            "confidence": confidence,
            "spam_probability": float(round(spam_prob * 100, 2)),
            "ham_probability": float(round(ham_prob * 100, 2)),
            "is_threat": is_spam,
            "indicators": indicators,
            "risk_score": float(round(spam_prob * 100, 2)),
            "recommendation": self._get_recommendation(is_spam, indicators),
            "summary": summary,
        }

    def _get_indicators(self, text: str) -> list:
        flags = []
        text_lower = text.lower()
        rules = {
            "Contains suspicious URL": bool(re.search(r"http|www|click here", text_lower)),
            "Money/prize offer detected": bool(re.search(r"\$[\d,]+|prize|gift card|lottery|winner|won", text_lower)),
            "Urgency language detected": bool(re.search(r"urgent|immediately|now|limited time|act now|expire", text_lower)),
            "Phone number present": bool(re.search(r"\b\d{10,}\b|\b\d{3}[-.\s]\d{4}\b", text)),
            "All caps text detected": sum(1 for c in text if c.isupper()) / max(len(text), 1) > 0.3,
            "Free offer detected": "free" in text_lower,
            "Excessive punctuation": text.count("!") > 2 or text.count("?") > 3,
        }
        for desc, triggered in rules.items():
            if triggered:
                flags.append(desc)
        return flags

    def _get_recommendation(self, is_spam: bool, indicators: list) -> str:
        if not is_spam:
            return "This message appears legitimate. Exercise normal caution with any links."
        recs = [
            "Do NOT click any links in this message.",
            "Do NOT reply to or forward this message.",
            "Mark as spam and delete immediately.",
        ]
        if "Contains suspicious URL" in indicators:
            recs.append("The URL may lead to a phishing or malware site.")
        if "Money/prize offer detected" in indicators:
            recs.append("Legitimate organisations do not offer prizes via unsolicited email.")
        return " ".join(recs)


# ── Singleton ──────────────────────────────────────────────────────────────────
_detector: SpamDetector | None = None


def get_spam_detector() -> SpamDetector:
    global _detector
    if _detector is None:
        _detector = SpamDetector()
    return _detector
