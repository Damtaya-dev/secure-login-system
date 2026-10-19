# My Web App — Secure Login and User Management

Third-year Computer & Information Security coursework demonstration built with Flask, SQLite, Bootstrap, Argon2id and time-based one-time passwords (TOTP).

## Features
- Username/password authentication; Argon2id with unique salts and an HMAC-SHA256 pepper.
- Google Authenticator-compatible TOTP; QR enrollment, encrypted stored secrets, one-time-step replay checks.
- Four roles: **inputer** (own records), **manager** (add inputers), **admin** (delete inputers), **administrator** (manage all users except last administrator cannot be deleted).
- Protected routes, session management, CSRF tokens, basic login/2FA throttling, parameterized SQLite queries.
- Responsive Bootstrap templates and local-only Flask server.

## Requirements
Windows 11 with Python 3.11+ and VS Code. Python 3.15 may work, but package compatibility varies. Internet is needed once to install Python packages and to load Bootstrap from its CDN; the app/database run locally afterwards. To make styling fully offline, download Bootstrap CSS locally and update the stylesheet link.

## Quick start (Windows)
1. Extract ZIP, open **my web app** folder in VS Code.
2. Double-click `setup_windows.bat` (or execute it from Windows Explorer). It creates `.venv`, installs dependencies, creates private `.env` and asks you to choose passwords for four demo accounts.
3. Double-click `run_windows.bat` or run `.venv\Scripts\python.exe app.py` from the project directory.
4. Visit `http://127.0.0.1:5000`.
5. Sign in as `administrator_demo`, `manager_demo`, `admin_demo`, or `inputer_demo` with the password you chose during setup.
6. On first login, scan the QR code using Google Authenticator (tap **+** → Scan a QR code). Enter a code to activate; enter a fresh code to complete login.
7. Use Dashboard, My Records, and User Management according to your role.

Manual alternative: `py -3 -m venv .venv`, `.venv\Scripts\python.exe -m pip install -r requirements.txt`, `.venv\Scripts\python.exe setup.py`, `.venv\Scripts\python.exe app.py`.

**Never share** `.env`, `users.db`, actual passwords, setup QR codes or 2FA secrets. If `.env` is lost, encrypted TOTP data and existing password hashes cannot be recovered without original keys. Back up locally if needed.

## Testing
Run `.venv\Scripts\python.exe -m pytest -q` from the project directory. Tests cover hashing, encrypted TOTP storage, failed password/2FA, CSRF, authorization and protected routes. Also test all four roles manually in the browser.

## Publish to GitHub
Create a new empty GitHub repository named `my-web-app`. From the project folder run:

```powershell
git init
git add .
git status
git commit -m "Add secure login coursework project"
git branch -M main
git remote add origin YOUR_GITHUB_REPOSITORY_URL
git push -u origin main
```

Before pushing, confirm `.env`, `users.db`, `.venv/`, `__pycache__/` are NOT in `git status`. The repository contains source code and setup instructions; visitors must initialize their own local database and 2FA. GitHub does not run this Flask application as a live website.

## Security limitations (local academic prototype)
- Flask's built-in server is development-only; no TLS/HTTPS. Enable `SESSION_COOKIE_SECURE=True` under HTTPS.
- Rate limiting is process-local and can be reset by restarting the server; production needs a shared persistent store and IP/user policy.
- Bootstrap CSS is loaded from a CDN; local copy needed for completely offline frontend.
- User-created initial passwords are chosen by the manager and must be conveyed securely; production would use invitation/one-time reset flows.
- User records are illustrative, not a real business data model. The demo does not include password reset, audit logs, backup/recovery or hardened deployment.
- Sessions use signed cookies and are valid while the browser holds them; consider session lifetime and revocation controls for real systems.

## Structure
`app.py` Flask routes; `database.py` schema; `security.py` cryptography; `setup.py` setup and accounts; `templates/` UI; `static/` CSS/JS; `tests/` automated tests; `docs/` report and presentation guide.
