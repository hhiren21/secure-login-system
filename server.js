// server.js
require("dotenv").config();

const path = require("path");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const authRoutes = require("./routes/auth");

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET) {
  console.error(
    "FATAL: SESSION_SECRET is not set. Copy .env.example to .env and set a real secret."
  );
  process.exit(1);
}

// Trust the first proxy hop (needed for secure cookies / correct IPs when
// deployed behind a reverse proxy like Render, Railway, Nginx, etc.)
app.set("trust proxy", 1);

// Security headers: CSP, no-sniff, frameguard, HSTS in prod, etc.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
  })
);

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

// Global rate limit as a baseline defense against abusive traffic; the
// auth routes layer tighter, endpoint-specific limits on top of this.
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(
  session({
    store: new SQLiteStore({ db: "sessions.db", dir: path.join(__dirname, "data") }),
    name: "sid", // don't advertise "connect.sid" / the framework in use
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // not readable from client-side JS -> mitigates XSS token theft
      secure: IS_PROD, // only sent over HTTPS in production
      sameSite: "strict", // mitigates CSRF
      maxAge: 1000 * 60 * 60 * 2, // 2 hours
    },
  })
);

app.use("/api/auth", authRoutes);

// Static frontend
app.use(express.static(path.join(__dirname, "public")));

// Fallback 404 for unmatched API routes
app.use("/api", (req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Central error handler — never leak stack traces to the client.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`Secure login server running on http://localhost:${PORT}`);
});