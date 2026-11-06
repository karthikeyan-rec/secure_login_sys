# 🔐 Secure Login System

A production-ready secure login web application built with **Node.js**, **Express**, and **SQLite**.

## ✨ Features

| Feature | Implementation |
|---|---|
| Password Hashing | bcrypt (cost factor 12) |
| SQL Injection Protection | Parameterized statements via `better-sqlite3` |
| Input Validation | `express-validator` with strict rules |
| Session Management | Server-side sessions with SQLite store |
| CSRF Protection | `csurf` token on every form |
| Rate Limiting | 20 auth requests / 15 min per IP |
| Brute-Force Protection | Account lockout after 5 failed attempts |
| Secure Headers | `helmet` (CSP, HSTS, etc.) |
| Two-Factor Auth (2FA) | TOTP via `speakeasy` + QR code |
| Audit Log | Per-user activity history |
| Session Regeneration | New session ID on login (session fixation prevention) |
| Timing-Safe Login | bcrypt runs even for unknown usernames |

## 🚀 Getting Started

### Prerequisites

- Node.js 18+
- npm

### Installation

```bash
# 1. Clone / navigate to the project
cd secure_login_system

# 2. Install dependencies
npm install

# 3. Set up environment (edit .env to change secrets)
cp .env.example .env

# 4. Start the server
npm start
# or for development with auto-reload:
npm run dev
```

The app will be available at **http://localhost:3000**

## 📁 Project Structure

```
secure_login_system/
├── server.js              # Express app entry point
├── src/
│   ├── database.js        # SQLite setup & all DB queries
│   ├── middleware.js       # Auth guards & flash locals
│   ├── validators.js      # Input validation rules
│   └── routes/
│       ├── auth.js        # Register, login, logout, 2FA
│       └── dashboard.js   # Protected dashboard
├── views/
│   ├── partials/
│   │   └── layout.ejs     # Shared HTML shell
│   ├── register.ejs
│   ├── login.ejs
│   ├── dashboard.ejs
│   ├── 2fa-setup.ejs
│   ├── 2fa-verify.ejs
│   └── error.ejs
├── public/
│   ├── css/style.css
│   ├── js/auth.js
│   └── favicon.svg
├── data/                  # Auto-created: SQLite databases
├── .env                   # Environment configuration
└── package.json
```

## 🔒 Security Architecture

### Password Hashing
Passwords are hashed with **bcrypt** (12 rounds) before storage. Plain-text passwords never touch the database.

### SQL Injection Prevention
All database queries use **prepared statements** (`better-sqlite3`). There is zero string interpolation into SQL anywhere in the codebase.

### Session Security
- Sessions stored server-side in SQLite (not in a cookie)
- Cookie flags: `HttpOnly`, `SameSite=Strict`, 30-minute TTL
- Session ID regenerated after every successful login (prevents session fixation)

### CSRF Protection
Every form includes a hidden `_csrf` token validated by `csurf`. Invalid tokens return a 403 error.

### Rate Limiting & Lockout
- IP-based rate limiting: 20 requests per 15-minute window
- Account lockout: locked after 5 consecutive failed login attempts

### Two-Factor Authentication (TOTP)
- Compatible with **Google Authenticator**, **Authy**, **1Password**, etc.
- QR code displayed during setup; manual key also shown
- Uses ±1 window (30 sec tolerance) for clock skew

## 🌐 Routes

| Method | Path | Description |
|---|---|---|
| GET | `/` | Redirect to dashboard or login |
| GET | `/register` | Registration form |
| POST | `/register` | Create account |
| GET | `/login` | Login form |
| POST | `/login` | Authenticate |
| POST | `/logout` | Destroy session |
| GET | `/dashboard` | Protected user dashboard |
| GET | `/auth/2fa/setup` | 2FA enrollment (QR code) |
| POST | `/auth/2fa/setup` | Confirm 2FA token & enable |
| GET | `/auth/2fa/verify` | 2FA challenge after login |
| POST | `/auth/2fa/verify` | Verify TOTP token |
| POST | `/auth/2fa/disable` | Remove 2FA from account |

## ⚙️ Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `NODE_ENV` | `development` | Environment (use `production` for HTTPS) |
| `SESSION_SECRET` | _(change me)_ | Secret key for session signing |
| `DB_PATH` | `./data/secure_login.db` | SQLite database path |
| `BCRYPT_ROUNDS` | `12` | bcrypt cost factor |

## 🔧 Production Checklist

- [ ] Change `SESSION_SECRET` to a random 64+ character string
- [ ] Set `NODE_ENV=production`
- [ ] Serve behind HTTPS (enables `Secure` cookie flag)
- [ ] Consider using a persistent session store (Redis) for multi-instance deployments
- [ ] Set up regular database backups

