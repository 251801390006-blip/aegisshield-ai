# 🛡️ Cyber Squad AI – Cyber Crime Detection Platform

> **AI-Powered Cybersecurity SaaS Platform** | Full-Stack Flask Application | Production-Ready Internship Project

[![Python](https://img.shields.io/badge/Python-3.11+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.5-f7931e?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5-7952b3?style=for-the-badge&logo=bootstrap&logoColor=white)](https://getbootstrap.com)
[![Render](https://img.shields.io/badge/Deploy-Render-46e3b7?style=for-the-badge)](https://render.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

---

## 🚀 Live Demo

**Deployment URL:** [https://aegisshield-ai.onrender.com/](https://aegisshield-ai.onrender.com/)

**Demo Credentials:**
* **Standard User:**
  - Email: `demo@cybersquad.io`
  - Password: `Demo@1234`
* **Admin Account:**
  - Email: `251801390006@cutmap.ac.in`
  - Password: `Vanjith@2008`

---

## ✨ Key Features

### 🔍 AI/ML Cyber Crime Detection Modules

* **📧 Spam Email Detector:** Powered by an ensemble of Naive Bayes + Logistic Regression (~98% accuracy) classifying suspicious messaging and marketing spam.
* **🎣 Phishing URL Scanner:** Utilizes a Gradient Boosting classifier analyzing 20+ structural and domain-level URL features (~96% accuracy).
* **🔐 Password Strength Analyzer:** Computes Shannon Entropy and applies customized heuristic rule-checking to measure crack time and strength.
* **🦠 Malware Risk Analyzer:** Performs static analysis, checking file magic bytes, double extensions, and size limits to detect malicious uploads.

### 🛡️ Platform Security & Architecture
* **Cross-Site Request Forgery (CSRF) Protection** (via Flask-WTF)
* **Secure Password Hashing** (via PBKDF2/SHA256 hashes using Werkzeug)
* **Rate Limiting** (via Flask-Limiter to defend against brute force and DDoS)
* **XSS Defense & Sanitization** (via Bleach input sanitization)
* **Secure HTTP Security Headers** (CSP, X-Content-Type-Options, HSTS)
* **SQL Injection Prevention** (strict database operations via SQLAlchemy ORM)

### 📊 Interactive Analytics Dashboard
* **Real-time Statistics:** Summary counts of total, safe, and threat scans.
* **Scan Visualization:** Weekly activity progression and threat distribution charts using Chart.js.
* **Audit History:** Full log search, type filtering, and single-click CSV export options.
* **Professional PDF Reports:** Automatic generation of structured cybersecurity assessment PDFs with risk gauges, recommendations, and evidence tables (ReportLab integration).

---

## 💬 Community Suggestions & Support Portal

Cyber Squad AI includes a centralized **Support & Feedback Hub** designed to handle user requests transparently and securely:

* **💡 Community Suggestions (Public):** A collaborative space visible to all users and administrators. Users can post ideas, view community feedback, and reply to discussions.
* **🔒 Support & Bug Tickets (Private):** Secure tickets for bugs, technical issues, or feature requests. Tickets and replies are **only visible to the submitting user and the Admin team**.
* **👑 Admin Ticket Watch & Control:** Admins can view all tickets, post replies, and toggle status between `Open` and `Resolved`. Submitting users can also close/resolve their own tickets once answered.
* **⚡ Real-time Privacy Safeguards:** Form categories dynamically display safety banners confirming if the feedback will be public or private.

---

## 🏗 Directory Structure

```
cybersquad/
├── app.py                    # Application entry point
├── config.py                 # Dev/Test/Prod configurations
├── requirements.txt          # Python dependencies
├── Procfile                  # WSGI process for deployment
├── render.yaml               # Render Blueprint config
│
├── cybersquad/              # Main application package
│   ├── __init__.py           # Flask App factory & database seed logic
│   ├── extensions.py         # Database, login, CSRF, and mail extensions
│   ├── forms.py              # WTForms classes
│   │
│   ├── models/               # SQLAlchemy Models
│   │   ├── user.py           # User accounts & metrics
│   │   ├── scan_history.py   # Detection log database
│   │   ├── threat_report.py  # Generated threat reports data
│   │   ├── otp.py            # Password reset OTP codes
│   │   └── feedback.py       # Feedback & Support tickets
│   │
│   ├── routes/               # Blueprints & Controllers
│   │   ├── auth.py           # Sign Up, Sign In, switching accounts
│   │   ├── admin.py          # Admin logs and account management
│   │   ├── dashboard.py      # User dashboard analytics
│   │   ├── spam.py           # Spam module
│   │   ├── phishing.py       # Phishing module
│   │   ├── password.py       # Password strength module
│   │   ├── malware.py        # Malware static file scanner
│   │   ├── history.py        # History search and CSV export
│   │   ├── reports.py        # PDF report generator
│   │   ├── profile.py        # Profile edits & password resets
│   │   ├── feedback.py       # Suggestions & support portal routes
│   │   └── api.py            # REST API v1 endpoints
│   │
│   ├── ml/                   # AI/ML Code & Model files
│   │   ├── spam_model.py     # Ensemble spam classifier
│   │   ├── phishing_model.py # URL parser & Gradient Boosting classifier
│   │   └── saved_models/     # Persisted classifiers (.joblib)
│   │
│   └── services/             # Core business logic
│       ├── password_service.py
│       ├── malware_service.py
│       └── report_service.py
│
├── static/                   # Static resources
│   ├── css/main.css          # Premium glassmorphism dark theme CSS
│   └── js/                   # Module-specific JS files
│
├── templates/                # Jinja2 template folder
│   ├── auth/                 # Sign In, Sign Up, and OTP layouts
│   ├── feedback/             # Feedback index, submit, and detail templates
│   ├── dashboard_base.html   # Main sidebar responsive layout
│   └── ...                   # Module views
│
└── tests/                    # Unit testing suite
    ├── test_auth.py          # Account creation & route authorization tests
    ├── test_feedback.py      # Support ticket privacy & suggestion tests
    └── test_models.py        # AI module classification verification tests
```

---

## ⚡ Quick Start

### 📋 Prerequisites
* Python 3.11+
* SQLite (local development) or PostgreSQL (production)

### ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/cybersquad-ai.git
   cd cybersquad-ai
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows (PowerShell/CMD):
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables:**
   Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
   *Note: In development, default variables (SQLite database) will be automatically initialized.*

5. **Run the application:**
   ```bash
   python app.py
   ```
   The application will start at: **http://localhost:5000**

---

## 🧪 Testing

We use `pytest` for unit testing the application modules, routing constraints, and security.

### Run all tests:
```bash
pytest
```

### Run specific test suites:
```bash
# Test AI models
pytest tests/test_models.py -v

# Test authentication
pytest tests/test_auth.py -v

# Test Suggestions & Support request portal
pytest tests/test_feedback.py -v
```

---

## 🌐 API Documentation

All analysis modules are exposed via a RESTful API under `/api/v1`.

### 1. Health Check
* **Endpoint:** `GET /api/v1/health`
* **Response:**
  ```json
  {"status": "ok", "app": "Cyber Squad AI", "version": "1.0.0"}
  ```

### 2. Spam Detection
* **Endpoint:** `POST /api/v1/spam/analyze`
* **Payload:**
  ```json
  {"email_text": "Claim your free money prize now!"}
  ```
* **Response:**
  ```json
  {
    "status": "success",
    "data": {
      "result": "SPAM",
      "confidence": 98.4,
      "is_threat": true,
      "indicators": ["Urgency keywords", "Spam indicators detected"]
    }
  }
  ```

### 3. Phishing Scan
* **Endpoint:** `POST /api/v1/phishing/analyze`
* **Payload:**
  ```json
  {"url": "http://secure-bank-login-update.xyz"}
  ```
* **Response:**
  ```json
  {
    "status": "success",
    "data": {
      "result": "PHISHING",
      "risk_score": 92.5,
      "is_threat": true,
      "indicators": ["Suspicious TLD", "IP address mismatch"]
    }
  }
  ```

---

## 🚀 Deployment

### Render (Recommended)
This repository is configured for one-click deployment on [Render](https://render.com) using the included `render.yaml` file:

1. Fork this repository on GitHub.
2. Sign up on Render.
3. Click **New +** → **Blueprint**.
4. Connect your forked GitHub repository.
5. Render will automatically detect the configuration and provision:
   - Web Service running Gunicorn.
   - PostgreSQL Database instance.
6. Configure the following environment variables on the Render dashboard:
   - `SECRET_KEY`: A secure random key.
   - `FLASK_ENV`: `production`
7. Click **Deploy**.

---

## 📄 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

Built as a premium cybersecurity SaaS internship showcase project.
