var express = require('express');
var passport = require('passport');
var LocalStrategy = require('passport-local');
var crypto = require('crypto');
var db = require('../db');


passport.use(new LocalStrategy(function verify(username, password, cb) {
  db.get('SELECT * FROM users WHERE username = ?', [ username ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(null, false, { message: 'Incorrect username or password.' }); }
  
      crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function(err, hashedPassword) {
        if (err) { return cb(err); }
        if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
          return cb(null, false, { message: 'Incorrect username or password.' });
        }
        return cb(null, row);
      });
    });
  }));

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, is_admin: user.is_admin });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

var router = express.Router();
/* After inputting login info, posts to this endpoint, where it is authenticated and redirected*/
router.post('/login', passport.authenticate('local', {
  successRedirect: '/index',
  failureRedirect: '/'
}));

/* On logout, posts here to end session, then redirects to logout page */
router.post('/logout', function(req, res, next) {
  req.session.destroy(function (err) {
      res.redirect('/logout'); 
  });
});

/* Logout page */
router.get('/logout', function(req, res, next) {
  req.session.destroy(function (err) {
    res.render('logout')
  })
});

module.exports = router;