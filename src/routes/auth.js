/**
 * Auth routes: register, login, logout, 2FA setup/verify.
 * All DB calls are async (sqlite3 Promise wrappers).
 */

const express   = require('express');
const bcrypt    = require('bcryptjs');
const speakeasy = require('speakeasy');
const qrcode    = require('qrcode');
const rateLimit = require('express-rate-limit');
const { validationResult } = require('express-validator');

const db = require('../database');
const { requireAuth, redirectIfAuth } = require('../middleware');
const { registerRules, loginRules, totpVerifyRules } = require('../validators');

const router = express.Router();
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);

// Rate limiter applied ONLY to POST submissions to prevent brute forcing
const submissionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: 'Too many attempts from this IP. Please try again after 15 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
});

// ───────────────────────────────── Register ────────────────────────────────

router.get('/register', redirectIfAuth, (req, res) => {
  res.render('register', { title: 'Register', errors: [], old: {} });
});

router.post('/register', submissionLimiter, redirectIfAuth, registerRules, async (req, res) => {
  const errors = validationResult(req);
  const old = { username: req.body.username, email: req.body.email };

  if (!errors.isEmpty()) {
    return res.render('register', { title: 'Register', errors: errors.array(), old });
  }

  const { username, email, password } = req.body;

  try {
    if (await db.findUserByUsername(username)) {
      return res.render('register', {
        title: 'Register',
        errors: [{ msg: 'Username is already taken.' }],
        old,
      });
    }
    if (await db.findUserByEmail(email)) {
      return res.render('register', {
        title: 'Register',
        errors: [{ msg: 'An account with that email already exists.' }],
        old,
      });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await db.createUser({ username, email, passwordHash });
    await db.logAudit({
      userId: null, username,
      ip: req.ip, userAgent: req.headers['user-agent'], event: 'REGISTER',
    });

    req.session.flashSuccess = 'Account created! Please log in.';
    res.redirect('/login');
  } catch (err) {
    console.error('Registration error:', err);
    res.render('register', {
      title: 'Register',
      errors: [{ msg: 'An unexpected error occurred. Please try again.' }],
      old,
    });
  }
});

// ───────────────────────────────── Login ──────────────────────────────────

router.get('/login', redirectIfAuth, (req, res) => {
  res.render('login', { title: 'Login', errors: [], old: {} });
});

router.post('/login', submissionLimiter, redirectIfAuth, loginRules, async (req, res, next) => {
  const errors = validationResult(req);
  const old = { username: req.body.username };

  if (!errors.isEmpty()) {
    return res.render('login', { title: 'Login', errors: errors.array(), old });
  }

  const { username, password } = req.body;
  const genericError = [{ msg: 'Invalid username or password.' }];

  try {
    const user = await db.findUserByUsername(username);

    if (!user) {
      // Timing-safe: run bcrypt even for unknown usernames
      await bcrypt.hash(password, BCRYPT_ROUNDS);
      await db.logAudit({ userId: null, username, ip: req.ip, userAgent: req.headers['user-agent'], event: 'LOGIN_FAIL_NO_USER' });
      return res.render('login', { title: 'Login', errors: genericError, old });
    }

    if (user.is_locked) {
      await db.logAudit({ userId: user.id, username, ip: req.ip, userAgent: req.headers['user-agent'], event: 'LOGIN_FAIL_LOCKED' });
      return res.render('login', {
        title: 'Login',
        errors: [{ msg: 'Account locked due to too many failed attempts. Please contact support.' }],
        old,
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      await db.incrementFailedAttempts(user.id);
      await db.logAudit({ userId: user.id, username, ip: req.ip, userAgent: req.headers['user-agent'], event: 'LOGIN_FAIL_BAD_PASS' });
      const updated   = await db.findUserById(user.id);
      const remaining = Math.max(0, 5 - (updated ? updated.failed_attempts : 5));
      const msg = remaining > 0
        ? `Invalid username or password. ${remaining} attempt(s) remaining before lockout.`
        : 'Account locked due to too many failed attempts. Contact support.';
      return res.render('login', { title: 'Login', errors: [{ msg }], old });
    }

    // Password correct — reset failed counter
    await db.resetFailedAttempts(user.id);

    // If 2FA is enabled, store partial session and redirect to TOTP verify
    if (user.totp_enabled) {
      req.session.pendingUserId   = user.id;
      req.session.pendingUsername = user.username;
      return res.redirect('/auth/2fa/verify');
    }

    // Fully authenticated — regenerate session to prevent session fixation
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId   = user.id;
      req.session.username = user.username;
      db.logAudit({ userId: user.id, username, ip: req.ip, userAgent: req.headers['user-agent'], event: 'LOGIN_SUCCESS' });
      const returnTo = req.session.returnTo || '/dashboard';
      delete req.session.returnTo;
      res.redirect(returnTo);
    });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────── 2FA Verify ───────────────────────────────────

router.get('/auth/2fa/verify', (req, res) => {
  if (!req.session.pendingUserId) return res.redirect('/login');
  res.render('2fa-verify', { title: 'Two-Factor Authentication', errors: [] });
});

router.post('/auth/2fa/verify', submissionLimiter, totpVerifyRules, async (req, res, next) => {
  if (!req.session.pendingUserId) return res.redirect('/login');

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('2fa-verify', { title: 'Two-Factor Authentication', errors: errors.array() });
  }

  try {
    const { token } = req.body;
    const user = await db.findUserById(req.session.pendingUserId);
    if (!user) return res.redirect('/login');

    const verified = speakeasy.totp.verify({
      secret:   user.totp_secret,
      encoding: 'base32',
      token,
      window:   1,
    });

    if (!verified) {
      await db.logAudit({ userId: user.id, username: user.username, ip: req.ip, userAgent: req.headers['user-agent'], event: '2FA_FAIL' });
      return res.render('2fa-verify', {
        title: 'Two-Factor Authentication',
        errors: [{ msg: 'Invalid or expired code. Please try again.' }],
      });
    }

    const userId   = req.session.pendingUserId;
    const username = req.session.pendingUsername;
    delete req.session.pendingUserId;
    delete req.session.pendingUsername;

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId   = userId;
      req.session.username = username;
      db.logAudit({ userId, username, ip: req.ip, userAgent: req.headers['user-agent'], event: '2FA_SUCCESS' });
      res.redirect('/dashboard');
    });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────── 2FA Setup ────────────────────────────────────

router.get('/auth/2fa/setup', requireAuth, async (req, res, next) => {
  try {
    const user = await db.findUserById(req.session.userId);
    if (user.totp_enabled) {
      req.session.flashInfo = '2FA is already enabled on your account.';
      return res.redirect('/dashboard');
    }

    const secret = speakeasy.generateSecret({
      name:   `SecureLogin (${user.username})`,
      length: 20,
    });
    await db.saveTotpSecret({ id: user.id, secret: secret.base32 });

    const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);
    res.render('2fa-setup', {
      title: 'Set Up Two-Factor Authentication',
      qrDataUrl,
      secret: secret.base32,
      errors: [],
    });
  } catch (err) {
    next(err);
  }
});

router.post('/auth/2fa/setup', requireAuth, totpVerifyRules, async (req, res, next) => {
  const errors = validationResult(req);

  try {
    const user = await db.findUserById(req.session.userId);

    const renderSetup = async (errs) => {
      if (!user.totp_secret) return res.redirect('/auth/2fa/setup');
      const otpauthUrl = speakeasy.otpauthURL({
        secret:   user.totp_secret,
        label:    encodeURIComponent(`SecureLogin (${user.username})`),
        encoding: 'base32',
      });
      const qrDataUrl = await qrcode.toDataURL(otpauthUrl);
      res.render('2fa-setup', {
        title: 'Set Up Two-Factor Authentication',
        qrDataUrl,
        secret: user.totp_secret,
        errors: errs,
      });
    };

    if (!errors.isEmpty()) return renderSetup(errors.array());

    const { token } = req.body;
    const verified = speakeasy.totp.verify({
      secret:   user.totp_secret,
      encoding: 'base32',
      token,
      window:   1,
    });

    if (!verified) return renderSetup([{ msg: 'Code did not match. Please try again.' }]);

    await db.enableTotp(user.id);
    await db.logAudit({ userId: user.id, username: user.username, ip: req.ip, userAgent: req.headers['user-agent'], event: '2FA_ENABLED' });
    req.session.flashSuccess = '2FA enabled successfully!';
    res.redirect('/dashboard');
  } catch (err) {
    next(err);
  }
});

router.post('/auth/2fa/disable', requireAuth, async (req, res, next) => {
  try {
    await db.disableTotp(req.session.userId);
    await db.logAudit({ userId: req.session.userId, username: req.session.username, ip: req.ip, userAgent: req.headers['user-agent'], event: '2FA_DISABLED' });
    req.session.flashSuccess = '2FA has been disabled.';
    res.redirect('/dashboard');
  } catch (err) {
    next(err);
  }
});

// ───────────────────────────────── Logout ─────────────────────────────────

router.post('/logout', requireAuth, (req, res) => {
  const { userId, username } = req.session;
  db.logAudit({ userId, username, ip: req.ip, userAgent: req.headers['user-agent'], event: 'LOGOUT' });

  req.session.destroy((err) => {
    if (err) console.error('Session destroy error:', err);
    res.clearCookie('sid');
    res.redirect('/login');
  });
});

module.exports = router;
