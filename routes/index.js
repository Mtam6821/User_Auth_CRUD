var express = require('express');
var crypto = require('crypto');
var db = require('../db');

var router = express.Router();
const adminErrMsg = "Admin permission needed";
const loginErrMsg = "You are not logged in";

function checkAdmin(req, res, next) {
  if (!req.user.is_admin) {
    return res.redirect('/index');
  }
  next();
}

function checkLogin(req, res, next) {
  if (!req.user) { 
    return res.redirect('/');
  }
  next();
}

function fetchUsers(req, res, next) {
  db.all('SELECT * FROM users', function(err, rows) {
    if (err) { return next(err); }
    console.log(rows);
    var all_users = rows.map(function(row) {
      
      const _hashedPassword = Buffer.from(row.hashed_password).toString('base64');
      const _salt           = Buffer.from(row.salt).toString('base64');

      return {
        id: row.id,
        username: row.username,
        hashedPassword: _hashedPassword,
        salt: _salt,
        isAdmin: (row.is_admin == 1)
      }
    });
    res.locals.all_users = all_users;
    next();
  });
}

/* Display Pages ----------------------------------------------------------------------*/

/* GET home page with login button */
router.get('/', function(req, res, next) {  
  res.render('home');
});

/* arrival page on successful login */
router.get('/index', checkLogin,
  function(req, res, next) {
    res.render('index', { user: req.user });
  });

/* report page */
router.get('/report', checkLogin,
  function(req, res, next) {
    res.render('report', { user: req.user });
  });

/* ADMIN ONLY page, html table of all users */
router.get('/userstable', checkLogin, checkAdmin, fetchUsers,
  function(req, res, next) {
    res.render('users', { user: req.user});
  });

/* CRUD METHODS---------------------------------------------------------------------------------*/

/* ADMIN ONLY, read all as json*/
router.get('/users', checkLogin, checkAdmin, fetchUsers,
  function(req, res, next) {
    res.send(res.locals.all_users);
  });

/* ADMIN ONLY, make a new user */
router.post('/users', checkLogin, checkAdmin, 
  function(req, res, next) {

    var salt = crypto.randomBytes(16);

    crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
        if (err) { return next(err); }

        db.run('INSERT INTO users (username, hashed_password, salt, is_admin) VALUES (?, ?, ?, ?)', [
          req.body.username,
          hashedPassword,
          salt,
          req.body.is_admin
        ], function(err) {
          if (err) { return next(err); }
          return res.redirect('/userstable');
        });
  });
});

/* ADMIN ONLY, update a user */
router.put('/users/:id', checkLogin, checkAdmin,
  function(req, res, next) {

    var salt = crypto.randomBytes(16);
    crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
      if (err) { return next(err); }
      db.all('UPDATE users SET username = ?, hashed_password = ?, salt = ?, is_admin = ? WHERE id = ? OR username = ?', [
        req.body.username,
        hashedPassword,
        salt,
        req.body.is_admin,
        req.params.id,
      ], function(err) {
        if (err) { return next(err); }
        return;
      });
    });
  });

/* ADMIN ONLY, get one user */
router.get('/users/:id', checkLogin, checkAdmin,
  function(req, res, next) {
    db.all('SELECT * FROM users WHERE id = ?', [
      req.params.id
    ], function(err, row) {
      if (err) { return next(err); }
      return res.send(row);
    });
  });

/* ADMIN ONLY, delete one user */
router.delete('/users/:id', checkLogin, checkAdmin,
  function(req, res, next) {
    db.run('DELETE FROM users WHERE id = ?', [
      req.params.id
    ], function(err) {
      if (err) { return next(err); }
      return res.send({"deleted" : req.params.id});
    });
  });

module.exports = router;
