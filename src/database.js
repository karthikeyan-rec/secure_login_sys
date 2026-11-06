/**
 * Database initialization and helper module.
 * Uses sqlite3 (prebuilt binaries available, no native build needed).
 * All queries use parameterized statements — no raw string interpolation.
 *
 * We wrap the callback-based sqlite3 API in simple Promises so the rest
 * of the app can use async/await.
 */

const sqlite3 = require('sqlite3').verbose();
const path    = require('path');
const fs      = require('fs');

const DB_PATH = process.env.DB_PATH || './data/secure_login.db';

// Ensure the data directory exists
const dbDir = path.dirname(path.resolve(DB_PATH));
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new sqlite3.Database(DB_PATH);

// ─────────────────── Promise wrappers ─────────────────────────

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function exec(sql) {
  return new Promise((resolve, reject) => {
    db.exec(sql, (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

// ─────────────────────────── Schema ────────────────────────────

const initDB = exec(`
  PRAGMA journal_mode=WAL;
  PRAGMA foreign_keys=ON;

  CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,
    totp_secret     TEXT,
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    is_locked       INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_at  INTEGER,
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS login_audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username   TEXT,
    ip_address TEXT,
    user_agent TEXT,
    event      TEXT    NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );
`);

// ──────────────────────────── API ─────────────────────────────

module.exports = {
  ready: initDB,  // await this before the server starts accepting requests

  findUserByUsername(username) {
    return get('SELECT * FROM users WHERE username = ? LIMIT 1', [username]);
  },

  findUserByEmail(email) {
    return get('SELECT * FROM users WHERE email = ? LIMIT 1', [email]);
  },

  findUserById(id) {
    return get('SELECT * FROM users WHERE id = ? LIMIT 1', [id]);
  },

  createUser({ username, email, passwordHash }) {
    return run(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [username, email, passwordHash]
    );
  },

  async incrementFailedAttempts(userId) {
    // Fetch current count first, then decide whether to lock
    const user = await get('SELECT failed_attempts FROM users WHERE id = ?', [userId]);
    const newCount = (user ? user.failed_attempts : 0) + 1;
    const locked   = newCount >= 5 ? 1 : 0;
    return run(
      `UPDATE users
       SET failed_attempts = ?,
           is_locked       = ?,
           last_failed_at  = strftime('%s','now'),
           updated_at      = strftime('%s','now')
       WHERE id = ?`,
      [newCount, locked, userId]
    );
  },

  resetFailedAttempts(userId) {
    return run(
      `UPDATE users
       SET failed_attempts = 0,
           is_locked       = 0,
           updated_at      = strftime('%s','now')
       WHERE id = ?`,
      [userId]
    );
  },

  saveTotpSecret({ id, secret }) {
    return run(
      `UPDATE users SET totp_secret = ?, totp_enabled = 0, updated_at = strftime('%s','now') WHERE id = ?`,
      [secret, id]
    );
  },

  enableTotp(userId) {
    return run(
      `UPDATE users SET totp_enabled = 1, updated_at = strftime('%s','now') WHERE id = ?`,
      [userId]
    );
  },

  disableTotp(userId) {
    return run(
      `UPDATE users SET totp_enabled = 0, totp_secret = NULL, updated_at = strftime('%s','now') WHERE id = ?`,
      [userId]
    );
  },

  logAudit({ userId, username, ip, userAgent, event }) {
    return run(
      'INSERT INTO login_audit (user_id, username, ip_address, user_agent, event) VALUES (?, ?, ?, ?, ?)',
      [userId || null, username, ip, userAgent, event]
    );
  },

  getAuditForUser(userId) {
    return all(
      `SELECT event, ip_address, user_agent,
              datetime(created_at,'unixepoch','localtime') AS ts
       FROM login_audit
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT 20`,
      [userId]
    );
  },
};
