// middleware/validate.js
// Centralized input validation. express-validator sanitizes/validates
// before any value reaches a database query, which is the first line of
// defense (the second is that db.js only ever uses parameterized queries).

const { body, validationResult } = require("express-validator");

function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: "Validation failed",
      details: errors.array().map((e) => ({ field: e.path, message: e.msg })),
    });
  }
  next();
}

const registerRules = [
  body("username")
    .trim()
    .isLength({ min: 3, max: 32 })
    .withMessage("Username must be 3-32 characters")
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage("Username may only contain letters, numbers, and underscores")
    .escape(),
  body("email")
    .trim()
    .isEmail()
    .withMessage("Must be a valid email address")
    .normalizeEmail(),
  body("password")
    .isLength({ min: 10 })
    .withMessage("Password must be at least 10 characters")
    .matches(/[A-Z]/)
    .withMessage("Password must contain an uppercase letter")
    .matches(/[a-z]/)
    .withMessage("Password must contain a lowercase letter")
    .matches(/[0-9]/)
    .withMessage("Password must contain a number")
    .matches(/[^A-Za-z0-9]/)
    .withMessage("Password must contain a symbol"),
];

const loginRules = [
  body("username").trim().notEmpty().withMessage("Username is required").escape(),
  body("password").notEmpty().withMessage("Password is required"),
  body("token").optional({ checkFalsy: true }).trim().isLength({ min: 6, max: 6 }).isNumeric(),
];

module.exports = { handleValidationErrors, registerRules, loginRules };