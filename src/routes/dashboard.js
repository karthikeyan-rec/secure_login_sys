/**
 * Protected dashboard routes.
 */

const express = require('express');
const { requireAuth } = require('../middleware');
const db = require('../database');

const router = express.Router();

router.get('/dashboard', requireAuth, async (req, res, next) => {
  try {
    const user   = await db.findUserById(req.session.userId);
    const audits = await db.getAuditForUser(req.session.userId);

    // Format memberSince reliably with fallback
    let memberSince = 'Recently';
    if (user && user.created_at) {
      const ts = typeof user.created_at === 'number'
        ? user.created_at * (user.created_at < 1e11 ? 1000 : 1)
        : Date.parse(user.created_at) || Date.now();
      const d = new Date(ts);
      if (!isNaN(d.getTime())) {
        memberSince = d.toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'long',
          day: 'numeric',
        });
      }
    }

    res.render('dashboard', { title: 'Dashboard', user, memberSince, audits });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
