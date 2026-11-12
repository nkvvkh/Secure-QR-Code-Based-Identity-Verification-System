# Secure QR Code-Based Identity Verification System

College project for **Cryptography and Network Security (CNS)**.
Stack: Python Flask, SQLite, HTML/CSS/JavaScript, `qrcode` + Pillow, HMAC-SHA256, `secrets`.

> **Disclaimer:** This is a college demonstration. It has not had a professional security review
> and needs one (plus HTTPS, a production web server, proper logging, backups, etc.) before any real-world use.

## How the security works

1. **Registration:** the server makes a random token with `secrets.token_urlsafe(32)` (256 bits).
2. **Signing:** it computes `HMAC-SHA256(QR_HMAC_KEY, token)`.
3. **QR content:** only `CNSQR1.<token>.<signature>`. No name, ID or department is inside the QR.
4. **Storage:** SQLite stores user details and the **SHA-256 hash** of the token, never the token itself.
5. **Verification (server side):** checks the format, then the signature using `hmac.compare_digest` (constant time), then looks up the token hash, then checks revoked status, then expiry. Personal details shown on a VALID result come from the **database**, never from the QR.
6. **Other protections:** Werkzeug password hashing, parameterized SQL, session-based admin protection, CSRF tokens on every POST, input validation, Jinja auto-escaping, Content-Security-Policy and other headers, HttpOnly + SameSite session cookies, 30-minute session timeout, login and verify rate limiting.

## Project structure

```
secure-qr-id/
├── app.py              Flask routes and verification logic
├── database.py         SQLite tables and queries (run it to create the DB + admin)
├── security.py         Tokens, HMAC, validation, CSRF, rate limiter
├── requirements.txt    Python packages
├── .env.example        Template for your secret settings
├── .gitignore
├── templates/          base, index, login, register, qr, verify, dashboard, history, error
├── static/css/style.css
├── static/js/script.js Scanner, upload and result display
├── static/js/jsQR.js   QR-reading library (Apache-2.0, bundled so it works offline)
└── tests/              33 automated tests
```

## Setup on Windows (VS Code)

Requirements: **Python 3.10 or newer** (python.org, tick "Add Python to PATH") and VS Code.

1. Unzip the project and open the folder in VS Code (**File > Open Folder**).
2. Open the terminal: **Terminal > New Terminal** (use **PowerShell**).
3. Create and activate a virtual environment:
   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks it, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and activate again.
   (Command Prompt alternative: `.venv\Scripts\activate.bat`.) You should see `(.venv)` in the prompt.
4. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
5. Create your `.env` file:
   ```powershell
   copy .env.example .env
   ```
   Generate two secret keys (run this command twice):
   ```powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
   Open `.env` and paste one value as `FLASK_SECRET_KEY` and the other as `QR_HMAC_KEY`.
   Change `ADMIN_PASSWORD` too. This is the demo admin password (default username `admin`).
6. Create the database and demo admin account:
   ```powershell
   python database.py
   ```
7. Run the app:
   ```powershell
   python app.py
   ```
8. Open **http://127.0.0.1:5000** in Chrome or Edge. Stop the server with `Ctrl + C`.

(The app also creates the database automatically on start, so step 6 is optional but shows the setup working.)

## Step-by-step demo

1. **Log in:** click *Admin Login* and use the username/password from `.env`.
2. **Register a user:** *Register User*. Example: name `Asha Rao`, user ID `CS-2026-001`, department `Computer Science`, a future expiry date.
3. **Get the QR code:** the QR page appears. Click **Download PNG** (it is shown only once; the server stores just a hash).
4. **Scan it:** open *Verify QR*.
   - **Webcam:** click *Start camera*, allow access, show the QR on another screen or a printout.
   - **Upload:** choose the downloaded PNG. Result: green **VALID** with the details from the database.
5. **Test INVALID codes:**
   - Paste `hello` into "Paste QR text" and click *Verify text*: INVALID (bad format).
   - Take a real payload (see tip below), change one character of the signature: INVALID (signature check failed).
   - Upload any other QR image (for example a website link): INVALID.
6. **Test REVOKED:** *Dashboard > Revoke* next to the user, confirm, then scan the same QR again: **REVOKED**.
7. **Test EXPIRED:** register a user, then set their expiry to a past date (command below) and scan: **EXPIRED**.
8. **New QR:** on the dashboard, *New QR* issues a fresh QR for an ACTIVE user and the old one becomes INVALID.
9. **History:** *History* lists every scan with time, result, identity and reason; filter by result.
10. **Logout:** use the *Logout* button.

Tip to see a payload text: download a QR, scan it with your phone's camera app, and copy the text `CNSQR1.xxx.yyy`.

Making a user expired for the demo (PowerShell, from the project folder):
```powershell
python -c "import sqlite3; c=sqlite3.connect('identity.db'); c.execute(\"UPDATE users SET expiry_date='2020-01-01' WHERE user_id='CS-2026-001'\"); c.commit()"
```

## Run the tests

```powershell
python -m pytest -v
```
Tests use a temporary database and fake keys; your real data is untouched. They cover token randomness,
HMAC signing and tamper detection, input validation, CSRF, admin protection, password hashing,
VALID / INVALID / EXPIRED / REVOKED results, QR replacement and logging.

## Common errors and fixes

| Problem | Fix |
|---|---|
| `python` is not recognized | Reinstall Python and tick "Add Python to PATH", or try `py` instead of `python`. |
| Activation script is blocked | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again. |
| `ModuleNotFoundError: flask` (or qrcode, dotenv) | The virtual environment is not active. Activate it, then `pip install -r requirements.txt`. In VS Code: `Ctrl+Shift+P` > *Python: Select Interpreter* > `.venv`. |
| `RuntimeError: FLASK_SECRET_KEY is missing...` | You have no `.env`, or the keys are shorter than 32 characters. Redo step 5. |
| Cannot log in | Username/password come from `.env` **when the database is first created**. Changing `.env` later does not change an existing admin. Delete `identity.db` and run `python database.py` again. |
| "Invalid or missing security token" | The page was open too long or cookies are blocked. Reload the page and retry. |
| Camera does not start | Allow camera permission. Use `http://127.0.0.1:5000` or `localhost` (browsers block cameras on plain-HTTP network addresses). Close other apps using the camera, or use image upload. |
| Every old QR became INVALID | `QR_HMAC_KEY` was changed. Signatures depend on the key; re-issue QR codes. |
| `Address already in use` (port 5000) | Close the other program, or change `port=5000` at the bottom of `app.py`. |
| `sqlite3.OperationalError: unable to open database` | Run from the project folder, or set a valid `DATABASE_PATH` in `.env`. |

## Limitations

- A QR code is a **bearer credential**: anyone with a copy of the image can present it until it is revoked or replaced. Real systems add short-lived codes, a second factor, or a photo check at the checkpoint.
- The verify page is public so any guard can use it; it only reveals details for VALID results and is rate limited (in memory, per IP, reset on restart).
- Revocation is permanent in this demo (no un-revoke or edit-expiry feature).
- One shared HMAC key: if it leaks, an attacker can forge signatures for new tokens, but they are still rejected because those tokens are not in the database. That database check is why a signature alone is never trusted.
- No HTTPS, no account lockout beyond rate limiting, no admin management UI, no audit log of admin actions, no key rotation.
- SQLite and Flask's development server are fine for a lab, not for production.
- Camera scanning depends on browser support and lighting; upload and paste are fallbacks.

## Credits

Browser-side QR decoding uses [jsQR](https://github.com/cozmo/jsQR) (Apache-2.0), included as `static/js/jsQR.js`.
