// db.js
// SQLite database setup. All queries elsewhere in the app use parameterized
// statements (?) rather than string concatenation, which is what actually
// prevents SQL injection — never build queries by interpolating user input.

const path = require("path");
const Database = require("better-sqlite3");

const db = new Database(path.join(__dirname, "data", "app.db"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE,
    email          TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    totp_secret    TEXT,
    totp_enabled   INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until   INTEGER,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

module.exports = db;