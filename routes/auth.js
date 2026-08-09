// routes/auth.js
const express = require("express");
const argon2 = require("argon2");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const rateLimit = require("express-rate-limit");

const db = require("../db");
const { requireAuth } = require("../middleware/auth");
const {
  handleValidationErrors,
  registerRules,
  loginRules,
} = require("../middleware/validate");

const router = express.Router();

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

// Slows down brute-force / credential-stuffing attempts against login.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Please try again later." },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many accounts created from this IP. Try again later." },
});

// Prepared statements — parameters are bound, never string-concatenated,
// so user input can never change the shape of the SQL query (SQL injection).
const getUserByUsername = db.prepare("SELECT * FROM users WHERE username = ?");
const getUserByEmailOrUsername = db.prepare(
  "SELECT * FROM users WHERE username = ? OR email = ?"
);
const getUserById = db.prepare(
  "SELECT id, username, email, totp_enabled, created_at FROM users WHERE id = ?"
);
const insertUser = db.prepare(
  "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"
);
const updateFailedAttempts = db.prepare(
  "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?"
);
const resetFailedAttempts = db.prepare(
  "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?"
);
const setTotpSecret = db.prepare(
  "UPDATE users SET totp_secret = ? WHERE id = ?"
);
const enableTotp = db.prepare(
  "UPDATE users SET totp_enabled = 1 WHERE id = ?"
);
const disableTotp = db.prepare(
  "UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?"
);

// ---------- Register ----------
router.post(
  "/register",
  registerLimiter,
  registerRules,
  handleValidationErrors,
  async (req, res) => {
    const { username, email, password } = req.body;
    try {
      const existing = getUserByEmailOrUsername.get(username, email);
      if (existing) {
        // Deliberately vague: don't reveal which field collided.
        return res.status(409).json({ error: "Username or email already in use" });
      }

      // Argon2id: the current OWASP-recommended default (memory-hard,
      // resistant to GPU/ASIC cracking). Salting is handled automatically.
      const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

      insertUser.run(username, email, passwordHash);
      return res.status(201).json({ message: "Account created. You can now log in." });
    } catch (err) {
      console.error("Register error:", err);
      return res.status(500).json({ error: "Something went wrong. Please try again." });
    }
  }
);

// ---------- Login ----------
router.post(
  "/login",
  loginLimiter,
  loginRules,
  handleValidationErrors,
  async (req, res) => {
    const { username, password, token } = req.body;
    const genericError = { error: "Invalid username or password" };

    try {
      const user = getUserByUsername.get(username);
      if (!user) {
        // Same error/timing shape as a real user with a wrong password,
        // so the response doesn't leak which usernames exist.
        await argon2.hash(password).catch(() => {});
        return res.status(401).json(genericError);
      }

      if (user.locked_until && user.locked_until > Date.now()) {
        const minutes = Math.ceil((user.locked_until - Date.now()) / 60000);
        return res.status(423).json({
          error: `Account temporarily locked. Try again in ${minutes} minute(s).`,
        });
      }

      const validPassword = await argon2.verify(user.password_hash, password);
      if (!validPassword) {
        const attempts = user.failed_attempts + 1;
        const lockedUntil =
          attempts >= MAX_FAILED_ATTEMPTS ? Date.now() + LOCKOUT_MS : null;
        updateFailedAttempts.run(attempts, lockedUntil, user.id);
        return res.status(401).json(genericError);
      }

      // Correct password — reset any prior failed-attempt counter.
      resetFailedAttempts.run(user.id);

      if (user.totp_enabled) {
        if (!token) {
          // Password confirmed, but a second factor is still required.
          return res.status(200).json({ twoFactorRequired: true });
        }
        const verified = speakeasy.totp.verify({
          secret: user.totp_secret,
          encoding: "base32",
          token,
          window: 1,
        });
        if (!verified) {
          return res.status(401).json({ error: "Invalid authentication code" });
        }
      }

      // Regenerate the session ID on login to prevent session fixation.
      req.session.regenerate((err) => {
        if (err) {
          console.error("Session regenerate error:", err);
          return res.status(500).json({ error: "Login failed. Please try again." });
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        return res.status(200).json({
          message: "Logged in successfully",
          user: { id: user.id, username: user.username },
        });
      });
    } catch (err) {
      console.error("Login error:", err);
      return res.status(500).json({ error: "Something went wrong. Please try again." });
    }
  }
);

// ---------- Logout ----------
router.post("/logout", requireAuth, (req, res) => {
  const cookieName = "sid";
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ error: "Could not log out. Please try again." });
    }
    res.clearCookie(cookieName);
    return res.status(200).json({ message: "Logged out successfully" });
  });
});

// ---------- Current user / session check ----------
router.get("/me", requireAuth, (req, res) => {
  const user = getUserById.get(req.session.userId);
  if (!user) return res.status(401).json({ error: "Not authenticated" });
  return res.json({ user });
});

// ---------- 2FA: begin setup (generate secret + QR code) ----------
router.post("/2fa/setup", requireAuth, async (req, res) => {
  const user = getUserById.get(req.session.userId);
  const secret = speakeasy.generateSecret({
    name: `SecureLogin (${user.username})`,
  });

  setTotpSecret.run(secret.base32, user.id);

  try {
    const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);
    return res.json({ qrCode: qrDataUrl, manualEntryKey: secret.base32 });
  } catch (err) {
    console.error("2FA setup error:", err);
    return res.status(500).json({ error: "Could not generate 2FA setup" });
  }
});

// ---------- 2FA: confirm setup with a code from the authenticator app ----------
router.post("/2fa/verify", requireAuth, (req, res) => {
  const { token } = req.body;
  if (!token || !/^\d{6}$/.test(token)) {
    return res.status(400).json({ error: "Enter the 6-digit code from your app" });
  }

  const user = getUserById.get(req.session.userId);
  const fullUser = getUserByUsername.get(user.username);

  const verified = speakeasy.totp.verify({
    secret: fullUser.totp_secret,
    encoding: "base32",
    token,
    window: 1,
  });

  if (!verified) {
    return res.status(401).json({ error: "Invalid code. Please try again." });
  }

  enableTotp.run(user.id);
  return res.json({ message: "Two-factor authentication enabled" });
});

// ---------- 2FA: disable ----------
router.post("/2fa/disable", requireAuth, (req, res) => {
  disableTotp.run(req.session.userId);
  return res.json({ message: "Two-factor authentication disabled" });
});

module.exports = router;