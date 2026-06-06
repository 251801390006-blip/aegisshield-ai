# 🛡 AegisShield AI – Cyber Crime Detection Platform

> **AI-Powered Cybersecurity SaaS Platform** | Full-Stack Flask Application | Production-Ready Internship Project

[![Python](https://img.shields.io/badge/Python-3.11-3776ab?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.5-f7931e?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5-7952b3?style=flat-square&logo=bootstrap&logoColor=white)](https://getbootstrap.com)
[![Render](https://img.shields.io/badge/Deploy-Render-46e3b7?style=flat-square)](https://render.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

---

## 🚀 Live Demo

**Deployment:** `https://your-app.onrender.com`

**Demo Account:**
- Email: `demo@aegisshield.io`
- Password: `Demo@1234`

---

## 📸 Screenshots

> Landing Page → Dashboard → Detection Modules → PDF Reports

---

## ✨ Features

### 🔍 Detection Modules

| Module | Algorithm | Accuracy |
|--------|-----------|----------|
| 📧 Spam Email Detector | Naive Bayes + Logistic Regression (ensemble) | ~98% |
| 🎣 Phishing URL Scanner | Gradient Boosting + 20 URL features | ~96% |
| 🔐 Password Analyzer | Shannon Entropy + Heuristics | Rule-based |
| 🦠 Malware Risk Analyzer | Static Analysis + Magic Bytes | Heuristic |

### 🛡 Security Features
- CSRF Protection (Flask-WTF)
- Password Hashing (Werkzeug/bcrypt)
- Rate Limiting (Flask-Limiter)
- XSS Prevention (Bleach sanitization)
- Secure HTTP Headers
- SQL Injection Prevention (SQLAlchemy ORM)
- Input Validation (WTForms)

### 📊 Dashboard & Analytics
- Real-time statistics
- Weekly activity chart (Chart.js)
- Threat distribution breakdown
- Scan history with search/filter
- CSV export

### 📄 PDF Report Generation
- Professional cybersecurity reports
- Risk score gauges
- Threat indicator tables
- Security recommendations
- Generated with ReportLab

---

## 🏗 Architecture

```
aegisshield/
├── app.py                    # Application entry point
├── config.py                 # Dev/Test/Prod configurations
├── requirements.txt
├── Procfile                  # Gunicorn deployment
├── render.yaml               # Render deployment config
│
├── aegisshield/              # Main application package
│   ├── __init__.py           # App factory
│   ├── extensions.py         # Flask extensions
│   ├── forms.py              # WTForms definitions
│   │
│   ├── models/               # SQLAlchemy models
│   │   ├── user.py
│   │   ├── scan_history.py
│   │   └── threat_report.py
│   │
│   ├── routes/               # Flask blueprints
│   │   ├── auth.py           # Login/Register/Reset
│   │   ├── dashboard.py      # Main dashboard
│   │   ├── spam.py           # Spam detection
│   │   ├── phishing.py       # URL scanning
│   │   ├── password.py       # Password analysis
│   │   ├── malware.py        # File analysis
│   │   ├── history.py        # Scan history
│   │   ├── reports.py        # PDF generation
│   │   ├── profile.py        # User profile
│   │   └── api.py            # REST API v1
│   │
│   ├── ml/                   # AI/ML models
│   │   ├── spam_model.py     # NB + LR ensemble
│   │   ├── phishing_model.py # GB classifier
│   │   └── saved_models/     # Persisted models (joblib)
│   │
│   └── services/             # Business logic
│       ├── password_service.py
│       ├── malware_service.py
│       └── report_service.py
│
├── static/
│   ├── css/main.css          # Dark cybersecurity theme
│   └── js/                   # Module-specific JS
│
├── templates/                # Jinja2 HTML templates
└── tests/                    # Pytest test suite
```

---

## ⚡ Quick Start

### Prerequisites
- Python 3.11+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/aegisshield-ai.git
cd aegisshield-ai

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Mac/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
copy .env.example .env

# Run the application
python app.py
```

The app will be available at: **http://localhost:5000**

### Running Tests

```bash
# Install pytest
pip install pytest

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_models.py -v
```

---

## 🌐 API Documentation

### Base URL
```
https://your-app.onrender.com/api/v1
```

### Endpoints

#### Health Check
```http
GET /api/v1/health
```

#### Spam Analysis
```http
POST /api/v1/spam/analyze
Content-Type: application/json
Authorization: Session cookie required

{
  "email_text": "Your email text here"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "result": "SPAM",
    "confidence": 94.7,
    "spam_probability": 94.7,
    "ham_probability": 5.3,
    "is_threat": true,
    "indicators": ["Contains suspicious URL", "Urgency language detected"],
    "recommendation": "Do NOT click any links..."
  }
}
```

#### Phishing URL Analysis
```http
POST /api/v1/phishing/analyze
Content-Type: application/json

{
  "url": "http://example.com/login"
}
```

#### Password Analysis
```http
POST /api/v1/password/analyze
Content-Type: application/json

{
  "password": "MyP@ssw0rd123!"
}
```

#### Dashboard Statistics
```http
GET /api/v1/dashboard/stats
```

#### Scan History
```http
GET /api/v1/history?page=1&per_page=20&type=spam
```

---

## 🚀 Deployment

### Render (Recommended)

1. Fork this repository on GitHub
2. Sign up at [render.com](https://render.com)
3. Click "New +" → "Web Service"
4. Connect your GitHub repository
5. Render will auto-detect `render.yaml`
6. Add environment variables:
   - `SECRET_KEY` → generate a random key
   - `FLASK_ENV` → `production`
7. Click "Create Web Service"

Your app will be live at: `https://your-service-name.onrender.com`

### Environment Variables for Production

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Random secret key (min 32 chars) |
| `FLASK_ENV` | `production` |
| `DATABASE_URL` | PostgreSQL connection string (auto-provided by Render) |
| `MAIL_USERNAME` | Gmail address for password resets |
| `MAIL_PASSWORD` | Gmail app password |

---

## 🧪 Technology Stack

| Category | Technology |
|----------|------------|
| Language | Python 3.11 |
| Framework | Flask 3.x + Blueprints |
| Database | SQLite (dev) / PostgreSQL (prod) |
| ORM | Flask-SQLAlchemy |
| Auth | Flask-Login + Werkzeug |
| Forms | Flask-WTF + WTForms |
| AI/ML | Scikit-Learn, NumPy, Pandas, Joblib |
| PDF | ReportLab |
| Frontend | Bootstrap 5, Chart.js, Vanilla JS |
| Security | Flask-Limiter, Bleach, CSRFProtect |
| Deployment | Gunicorn, Render, Vercel |

---

## 📝 Internship Project Description

**AegisShield AI** is a production-ready cybersecurity SaaS platform demonstrating:

- **Full-Stack Development**: Complete Flask application with blueprints, models, forms, and templates
- **Machine Learning**: Ensemble spam detection (98% accuracy), URL phishing classification (20+ features), password entropy analysis
- **Security Engineering**: CSRF protection, rate limiting, input sanitization, secure session management
- **Professional UI/UX**: Dark cybersecurity theme with glassmorphism, Chart.js dashboards, responsive design
- **DevOps**: Render deployment with PostgreSQL, environment configuration, Gunicorn WSGI server
- **Software Engineering**: Test-driven development, clean architecture, RESTful API design

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push: `git push origin feature/amazing-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

Built with ❤️ as an internship showcase project.

**Stack Highlights:** Python · Flask · Scikit-Learn · Bootstrap 5 · Chart.js · ReportLab · Render
