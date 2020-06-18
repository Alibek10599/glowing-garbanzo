const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, VERIFICATION_SID } = process.env;
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const twilio = require('twilio')(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
const User = require('../models/User');
const { forwardAuthenticated } = require('../config/auth');

// Login Page
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

router.get('/verify', forwardAuthenticated, (req, res) => res.render('verify'));

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'));

// Register
router.post('/register', (req, res) => {
  const { name, phoneNumber, password, password2 } = req.body;
  let errors = [];

  if (!name || !phoneNumber || !password || !password2) {
    errors.push({ msg: 'Please enter all fields' });
  }

  if (password != password2) {
    errors.push({ msg: 'Passwords do not match' });
  }

  if (password.length < 6) {
    errors.push({ msg: 'Password must be at least 6 characters' });
  }

  if (errors.length > 0) {
    res.render('register', {
      errors,
      name,
      phoneNumber,
      password,
      password2
    });
  } else {
    User.findOne({ phoneNumber: phoneNumber }).then(user => {
      if (user) {
        errors.push({ msg: 'Email already exists' });
        res.render('register', {
          errors,
          name,
          phoneNumber,
          password,
          password2
        });
      } else {
        const newUser = new User({
          name,
          phoneNumber,
          password
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser.save().then(user => {
                req.flash(
                  'success_msg',
                  'You are now registered and can log in'
                );
                twilio.verify.services('VA8e19432bd14e7d0d7a3af03ccbeafcc8')
                 .verifications.create({to: phoneNumber, channel: 'sms'}).then(verification => {
                     console.log(verification.sid);
                     res.redirect('/users/login');
                 });
              })
              .catch(err => console.log(err));
          });
        });
      }
    });
  }
});

router.post('/verify', (req, res, next) => {
    const { code, phoneNumber } = req.body;
    twilio.verify.services("VA8e19432bd14e7d0d7a3af03ccbeafcc8")
      .verificationChecks.create({ code, to: phoneNumber }).then(verification => {
          console.log(verification.sid);
          res.redirect('/');
    });
});

// Login
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
  })(req, res, next);
});

// Logout
router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/users/login');
});

module.exports = router;
