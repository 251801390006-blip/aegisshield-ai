# 🚀 Deploy AegisShield AI to Render (Complete Guide)

## Prerequisites
- GitHub account with this project pushed
- Free Render account at https://render.com

## Step 1: Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit: AegisShield AI"
git remote add origin https://github.com/YOUR_USERNAME/aegisshield-ai.git
git push -u origin main
```

## Step 2: Create Render Account
1. Go to https://render.com
2. Sign up with GitHub
3. Authorize Render to access your repositories

## Step 3: Deploy Web Service
1. Click "New +" → "Web Service"
2. Connect your `aegisshield-ai` repository
3. Render will auto-detect the `render.yaml` file

**Manual Settings (if not using render.yaml):**
- **Name:** aegisshield-ai
- **Runtime:** Python 3
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`

## Step 4: Add Environment Variables
In the Render dashboard → Environment:

| Key | Value |
|-----|-------|
| `FLASK_ENV` | `production` |
| `SECRET_KEY` | Click "Generate" for a random value |
| `DATABASE_URL` | Auto-populated when you add a database |

## Step 5: Add PostgreSQL Database
1. Click "New +" → "PostgreSQL"
2. Name: `aegisshield-db`
3. Plan: Free
4. Copy the "Internal Database URL"
5. Paste as `DATABASE_URL` in your web service environment

## Step 6: Deploy
1. Click "Create Web Service"
2. Wait 2-5 minutes for the build
3. Your site will be live at: `https://aegisshield-ai.onrender.com`

## Troubleshooting

**Build fails with import error:**
```bash
# Ensure all dependencies are in requirements.txt
pip freeze > requirements.txt
```

**Database connection error:**
- Verify DATABASE_URL is set correctly
- Check the database is in the same Render region

**Static files not loading:**
- Render serves static files automatically
- Ensure `static/` folder is committed to git

## Custom Domain (Optional)
1. Dashboard → Settings → Custom Domain
2. Add your domain
3. Configure DNS with your registrar

## Verify Deployment
```
https://your-app.onrender.com/api/v1/health
```
Should return:
```json
{"status": "ok", "service": "AegisShield AI", "version": "1.0.0"}
```
