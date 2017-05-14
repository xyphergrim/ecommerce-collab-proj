var express = require("express");
var router = express.Router();
var csrf = require("csurf");
var passport = require("passport");
var nodemailer = require("nodemailer");
var async = require("async");
var crypto = require("crypto");

var csrfProtection = csrf();
router.use(csrfProtection);
var middleware = require("../middleware");

var Cart = require("../models/cart");
var Order = require("../models/order");
var User = require("../models/user");

// get register page
router.get("/register", middleware.notLoggedIn, function (req, res) {
    var messages = req.flash("error");
    res.render("user/register", {csrfToken: req.csrfToken(), messages: messages});
});

// register logic
router.post("/register", middleware.notLoggedIn, passport.authenticate("local.singup", {
    failureRedirect: "/user/register",
    failureFlash: true
}), function (req, res, next) {
    if (req.session.oldUrl) {
        var oldUrl = req.session.oldUrl;
        req.session.oldUrl = null;
        res.redirect(oldUrl);
    } else {
        // send newly registered user welcome email
        var smtpTransporter = nodemailer.createTransport({
            service: "SendPulse",
            auth: {
              // SendPulse SMTP Settings/Credentials
              // user: SMTP Settings Login
              // pass: SMTP Settings Password
                user: "jc.xypher@gmail.com",
                pass: process.env.SENDPULSEPASS
            }
        });
        var mailOptions = {
            to: req.user.email,
            from: "jc.xypher@gmail.com", // SendPulse user
            subject: "E-Commerce Project Welcome Email!",
            text: "Hello, " + req.user.email + "! Thanks for signing up with Node Tours! We hope you enjoy your stay."
        };
        smtpTransporter.sendMail(mailOptions, function(err){
            // req.flash("success", "An e-mail has been sent to " + user.email + " with further instructions.");
            // done(err, "done");
            if(err) {
              console.log(err);
            }
        });

        res.redirect("/user/profile");
    }
});

// get login page
router.get("/login", middleware.notLoggedIn, function (req, res) {
    var messages = req.flash("error");
    res.render("user/login", {csrfToken: req.csrfToken(), messages: messages});
});

// login logic
router.post("/login", middleware.notLoggedIn, passport.authenticate("local.signin", {
    failureRedirect: "/user/login",
    failureFlash: true
}), function (req, res, next) {
    if (req.session.oldUrl) {
        var oldUrl = req.session.oldUrl;
        req.session.oldUrl = null;
        res.redirect(oldUrl);
    } else {
        res.redirect("/user/profile");
    }
});

// logout
router.get("/logout", middleware.isLoggedIn, function (req, res) {
    req.logout();
    req.flash("success", "You have successfully signed out.")
    res.redirect("/");
});

// get profile page
router.get("/profile", middleware.isLoggedIn, function (req, res) {
    Order.find({user: req.user}, function (err, orders) {
        if (err) {
            console.log(err);
            req.flash("error", "Error fetching user orders.");
            return res.redirect("/products");
        }
        var cart;
        orders.forEach(function (order) {
            cart = new Cart(order.cart);
            order.items = cart.generateArray();
        });
        res.render("user/profile", {orders: orders});
    });
});

// get forgot page
router.get("/forgot", middleware.notLoggedIn, function(req, res){
  res.render("user/forgot", {csrfToken: req.csrfToken()});
});

// post forgot page
router.post("/forgot", middleware.notLoggedIn, function(req, res, next){
    async.waterfall([
        function(done){
            crypto.randomBytes(20, function(err, buf){
                var token = buf.toString("hex");
                done(err, token);
            });
        },
        function(token, done){
            User.findOne({email: req.body.email}, function(err, user){
                if(!user) {
                    req.flash("error", "No account with that email address exists.");
                    return res.redirect("/user/forgot");
                }

                user.resetPasswordToken = token;
                user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

                user.save(function(err){
                    done(err, token, user);
                });
            });
        },
        function(token, user, done){
            var smtpTransporter = nodemailer.createTransport({
                service: "SendPulse",
                auth: {
                  // SendPulse SMTP Settings/Credentials
                  // user: SMTP Settings Login
                  // pass: SMTP Settings Password
                    user: "jc.xypher@gmail.com",
                    pass: process.env.SENDPULSEPASS
                }
            });
            var mailOptions = {
                to: user.email,
                from: "jc.xypher@gmail.com", // SendPulse user
                subject: "E-Commerce Project Password Reset",
                text: "You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n" +
                    "Please click on the following link, or paste this into your browser to complete the process:\n\n" +
                    "http://" + req.headers.host + "/user/reset/" + token + "\n\n" +
                    "If you did not request this, please ignore this email and your password will remain unchanged.\n"
            };
            smtpTransporter.sendMail(mailOptions, function(err){
                req.flash("info", "An e-mail has been sent to " + user.email + " with further instructions.");
                done(err, "done");
            });
        }
    ], function(err){
        if(err) return next(err);
        res.redirect("/user/forgot");
    });
});

// get reset page
router.get("/reset/:token", middleware.notLoggedIn, function(req, res){
    User.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: {$gt: Date.now()}}, function(err, user){
        if(!user) {
            req.flash("error", "Password reset token is invalid or has expired.");
            return res.redirect("/user/forgot");
        }
        // console.log(user.resetPasswordToken);
        res.render("user/reset", {user: req.user, resetPasswordToken: req.params.token, csrfToken: req.csrfToken()});
    });
});

// post for reset password
router.post('/reset/:token', middleware.notLoggedIn, function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }

        user.password = req.body.password;
        var confirmPassword = req.body.confirmPassword;

        if(user.password === confirmPassword) {
          user.resetPasswordToken = undefined;
          user.resetPasswordExpires = undefined;
          user.save(function(err) {
            req.logIn(user, function(err) {
              done(err, user);
            });
          });
        } else {
          req.flash("error", "Passwords entered don't match.");
          return res.redirect("/user/reset/"+user.resetPasswordToken);
        }
      });
    },
    function(user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'SendPulse',
        auth: {
          // SendPulse SMTP Settings/Credentials
          // user: SMTP Settings Login
          // pass: SMTP Settings Password
          user: 'jc.xypher@gmail.com',
          pass: process.env.SENDPULSEPASS
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'jc.xypher@gmail.com', // SendPulse user
        subject: 'E-Commerce Project - Password has been changed',
        text: 'Greetings,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success', 'Success! Your password has been changed.');
        done(err);
      });
    }
  ], function(err) {
    res.redirect('/');
  });
});

module.exports = router;
