/**
 * Input validation rules using express-validator.
 * All rules are shared between routes to keep things DRY.
 */

const { body } = require('express-validator');

const USERNAME_REGEX = /^[a-zA-Z0-9_]{3,30}$/;
const PASSWORD_MIN   = 8;

const registerRules = [
  body('username')
    .trim()
    .notEmpty().withMessage('Username is required.')
    .matches(USERNAME_REGEX).withMessage('Username must be 3–30 alphanumeric characters or underscores.'),

  body('email')
    .trim()
    .notEmpty().withMessage('Email is required.')
    .isEmail().withMessage('Please enter a valid email address.')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required.')
    .isLength({ min: PASSWORD_MIN }).withMessage(`Password must be at least ${PASSWORD_MIN} characters.`)
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter.')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter.')
    .matches(/[0-9]/).withMessage('Password must contain at least one number.')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain at least one special character.'),

  body('confirmPassword')
    .notEmpty().withMessage('Please confirm your password.')
    .custom((value, { req }) => {
      if (value !== req.body.password) throw new Error('Passwords do not match.');
      return true;
    }),
];

const loginRules = [
  body('username')
    .trim()
    .notEmpty().withMessage('Username is required.')
    .escape(),

  body('password')
    .notEmpty().withMessage('Password is required.'),
];

const totpVerifyRules = [
  body('token')
    .trim()
    .notEmpty().withMessage('Authentication code is required.')
    .isLength({ min: 6, max: 6 }).withMessage('Code must be exactly 6 digits.')
    .isNumeric().withMessage('Code must be numeric.'),
];

module.exports = { registerRules, loginRules, totpVerifyRules };

