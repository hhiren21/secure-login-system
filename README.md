# Secure Login System

A self-contained Node.js/Express web app implementing a secure username +
password login flow with optional TOTP two-factor authentication.

## Stack

- **Express** – server & routing
- **better-sqlite3** – embedded SQL database, accessed only through
  parameterized/prepared statements (never string-built queries)
- **argon2** – password hashing (Argon2id, OWASP's current recommendation)
- **express-session** + **connect-sqlite3** – server-side session storage
- **speakeasy** + **qrcode** – TOTP-based 2FA and its setup QR code
- **helmet** – security response headers (CSP, etc.)
- **express-validator** – input validation/sanitization
- **express-rate-limit** – brute-force / abuse throttling
- Plain HTML/CSS/JS frontend (no framework, no build step)

## Setup

```bash
npm install
cp .env.example .env
# edit .env and set SESSION_SECRET to a real random value:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

npm start
# -> http://localhost:3000
```

The SQLite database files are created automatically under `data/` on first run.

## How each requirement is met

**Hashed passwords (Argon2)**
`routes/auth.js` hashes every password with `argon2.hash(..., { type: argon2.argon2id })`
before it's stored, and verifies with `argon2.verify`. Argon2 salts automatically
and is memory-hard, which makes GPU/ASIC cracking far more expensive than
with bcrypt or (worse) unsalted SHA-family hashes.

**Input validation & SQL injection protection**
- `middleware/validate.js` enforces field-level rules (length, character sets,
  a real email shape, a minimum-strength password) with `express-validator`,
  and rejects the request with `400` before any handler runs.
- `db.js` and `routes/auth.js` use `better-sqlite3` **prepared statements**
  exclusively (`db.prepare("... WHERE username = ?")`). User input is always
  passed as a bound parameter, never concatenated into SQL text, so it can
  never change the query's structure — this is what actually blocks SQL
  injection, independent of the input-validation layer.

**Session management with logout**
- `express-session` backed by `connect-sqlite3` for persistent, server-side
  sessions (not sensitive data in the cookie itself).
- Cookies are `httpOnly` (unreachable from JS, mitigating XSS token theft),
  `sameSite: strict` (mitigates CSRF), and `secure` in production (HTTPS-only).
- The session ID is regenerated on every successful login (`req.session.regenerate`)
  to prevent session fixation.
- `POST /api/auth/logout` destroys the session server-side and clears the cookie.

**Two-Factor Authentication (optional, TOTP)**
- `POST /api/auth/2fa/setup` generates a per-user secret and a QR code
  (scannable by Google Authenticator, Authy, 1Password, etc.).
- `POST /api/auth/2fa/verify` confirms the first code and flips `totp_enabled` on.
- Once enabled, `POST /api/auth/login` requires a valid 6-digit `token` in
  addition to the password before a session is issued.
- `POST /api/auth/2fa/disable` turns it back off.

**Other hardening included**
- Per-account lockout: 5 failed password attempts locks the account for
  15 minutes (`failed_attempts` / `locked_until` columns).
- Rate limiting on `/register` and `/login` specifically, plus a looser
  global limiter on the whole app.
- Generic, non-enumerating error messages ("Invalid username or password")
  so failed logins don't reveal whether the *username* or *password* was wrong.
- `helmet` sets a restrictive Content-Security-Policy and related headers.
- Request bodies are size-capped (`limit: "10kb"`) to blunt large-payload abuse.

## API summary

| Method | Route | Purpose |
|---|---|---|
| POST | `/api/auth/register` | Create an account |
| POST | `/api/auth/login` | Log in (may return `twoFactorRequired: true`) |
| POST | `/api/auth/logout` | Destroy the current session |
| GET | `/api/auth/me` | Current logged-in user (requires session) |
| POST | `/api/auth/2fa/setup` | Generate a TOTP secret + QR code |
| POST | `/api/auth/2fa/verify` | Confirm a code and enable 2FA |
| POST | `/api/auth/2fa/disable` | Turn 2FA off |

## What this doesn't cover

This is a solid baseline, not a finished production system. Before shipping
for real users you'd also want: email verification, a password-reset flow
(with expiring signed tokens), CSRF tokens for extra defense-in-depth on top
of `sameSite`, audit logging, and a managed database with backups rather
than a single SQLite file.

## Deployment notes

- Set `NODE_ENV=production` so session cookies require HTTPS.
- Put the app behind a reverse proxy / load balancer that terminates TLS.
- Keep `.env` (and the `data/` directory) out of version control — see `.gitignore`.
