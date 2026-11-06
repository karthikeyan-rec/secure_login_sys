/**
 * Secure Login System — Express server entry point
 *
 * Security measures applied:
 *  - Helmet: sets secure HTTP headers (CSP, HSTS, X-Frame-Options, etc.)
 *  - express-rate-limit: brute-force protection on auth endpoints
 *  - express-session with SQLite store: tamper-evident, server-side sessions
 *  - CSRF protection via double-submit session token (custom middleware)
 *  - bcrypt password hashing (see src/routes/auth.js)
 *  - parameterized SQL queries (see src/database.js)
 *  - Input validation & sanitisation (see src/validators.js)
 *  - Account lockout after 5 consecutive failed login attempts
 *  - Timing-safe login (bcrypt runs even on unknown usernames)
 *  - Session regeneration after successful login
 *  - TOTP-based 2FA via speakeasy
 */

require('dotenv').config();

const express      = require('express');
const path         = require('path');
const fs           = require('fs');
const helmet       = require('helmet');
const morgan       = require('morgan');
const session      = require('express-session');
const SQLiteStore  = require('connect-sqlite3')(session);
const rateLimit    = require('express-rate-limit');
const crypto       = require('crypto');

const database        = require('./src/database');
const { localUser }   = require('./src/middleware');
const authRoutes      = require('./src/routes/auth');
const dashboardRoutes = require('./src/routes/dashboard');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────── Data directory ───────────────────────────────

const DATA_DIR = path.resolve(
  process.env.DB_PATH ? path.dirname(process.env.DB_PATH) : (process.env.VERCEL ? '/tmp' : './data')
);
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ──────────────────────────── View engine ─────────────────────────────────

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─────────────────────────── Static assets ────────────────────────────────

app.use(express.static(path.join(__dirname, 'public')));

// ───────────────────────── Security middleware ─────────────────────────────

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:'],
      fontSrc:    ["'self'"],
      objectSrc:  ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
}));

// ──────────────────────────── Rate limiting ───────────────────────────────
// Only apply rate limiting to sensitive POST submissions (login, register, 2FA verify)
// NEVER rate limit normal page views (GET /dashboard, GET /login, static files, etc.)

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, // Generous limit for development & normal user interactions
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login/registration attempts from this IP, please try again in 15 minutes.',
});

// Export rate limiter so routes can selectively apply it to POST endpoints
app.set('authLimiter', authLimiter);

// ─────────────────────────── Request parsing ──────────────────────────────

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ──────────────────────────── HTTP logging ────────────────────────────────

if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('dev'));
}

// ───────────────────────── Session configuration ──────────────────────────

app.use(session({
  store: new SQLiteStore({
    db:  'sessions.db',
    dir: DATA_DIR,
  }),
  secret:            process.env.SESSION_SECRET || 'fallback-dev-secret-change-me',
  resave:            false,
  saveUninitialized: false,
  name:              'sid',
  cookie: {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge:   30 * 60 * 1000,
  },
}));

// ─────────────────────────── CSRF protection ──────────────────────────────
// Double-submit session token pattern:
// 1. On first visit, generate a random token stored in the session.
// 2. All POST/PUT/PATCH/DELETE requests must supply _csrf matching the session token.
// 3. SameSite=strict cookie already blocks cross-origin form submissions; this
//    adds an extra explicit layer of protection.

function csrfMiddleware(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;

  const unsafe = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (unsafe.includes(req.method)) {
    const bodyToken   = req.body._csrf;
    const sessionToken = req.session.csrfToken;
    if (!bodyToken || !sessionToken || bodyToken !== sessionToken) {
      return res.status(403).render('error', {
        title:   'Forbidden',
        message: 'Invalid or expired form token. Please go back and try again.',
        status:  403,
        user:    res.locals.user || null,
        flashError:   null,
        flashSuccess: null,
        flashInfo:    null,
      });
    }
  }
  next();
}

app.use(csrfMiddleware);

// ─────────────────────── Flash / user locals ──────────────────────────────

app.use(localUser);

// ──────────────────────────────── Routes ──────────────────────────────────

app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.redirect('/login');
});

app.use(authRoutes);
app.use(dashboardRoutes);

// ─────────────────────────── Error handlers ───────────────────────────────

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).render('error', {
    title:   'Error',
    message: process.env.NODE_ENV === 'production'
      ? 'Something went wrong. Please try again.'
      : err.message,
    status:  err.status || 500,
    user:    res.locals.user || null,
    flashError: null, flashSuccess: null, flashInfo: null,
  });
});

app.use((req, res) => {
  res.status(404).render('error', {
    title:   'Page Not Found',
    message: 'The page you are looking for does not exist.',
    status:  404,
    user:    res.locals.user || null,
    flashError: null, flashSuccess: null, flashInfo: null,
  });
});

// ───────────────────────────── Start server ───────────────────────────────

database.ready
  .then(() => {
    app.listen(PORT, () => {
      console.log(`\n🔐 Secure Login System running at http://localhost:${PORT}`);
      console.log(`   Environment : ${process.env.NODE_ENV || 'development'}`);
      console.log(`   Press Ctrl+C to stop.\n`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });

module.exports = app;
