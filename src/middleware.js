/**
 * Authentication middleware helpers.
 */

/** Redirect to /login if the user is not authenticated. */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  req.session.returnTo = req.originalUrl;
  res.redirect('/login');
}

/** Redirect to /dashboard if the user is already logged in. */
function redirectIfAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return res.redirect('/dashboard');
  }
  next();
}

/** Expose session user data to all templates. */
function localUser(req, res, next) {
  res.locals.user = req.session.userId
    ? { id: req.session.userId, username: req.session.username }
    : null;
  res.locals.flashError   = req.session.flashError   || null;
  res.locals.flashSuccess = req.session.flashSuccess || null;
  res.locals.flashInfo    = req.session.flashInfo    || null;
  delete req.session.flashError;
  delete req.session.flashSuccess;
  delete req.session.flashInfo;
  next();
}

module.exports = { requireAuth, redirectIfAuth, localUser };

