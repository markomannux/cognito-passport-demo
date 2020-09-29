require('dotenv').config();
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var session = require('express-session');

var passport = require('passport');
var OAuth2Strategy = require('passport-oauth2');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

const AUTH_URL = process.env.AUTH_URL; 
const TOKEN_URL = process.env.TOKEN_URL;
const EXAMPLE_CLIENT_ID = process.env.EXAMPLE_CLIENT_ID;
const EXAMPLE_CLIENT_SECRET = process.env.EXAMPLE_CLIENT_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL;

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true
}))
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

app.use(express.static(path.join(__dirname, 'public')));

passport.use(new OAuth2Strategy({
    authorizationURL: AUTH_URL,
    tokenURL: TOKEN_URL,
    clientID: EXAMPLE_CLIENT_ID,
    clientSecret: EXAMPLE_CLIENT_SECRET,
    callbackURL: CALLBACK_URL
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log('Access token', accessToken)
    console.log('Refresh token', refreshToken)
    console.log('Profile', profile);
    return cb(null, {dummyUser: 'pippo'});
  }
));

app.use('/', indexRouter);
app.use('/users', passport.authenticate('oauth2', { scope: 'email' }), usersRouter);

app.get('/auth/example/callback', passport.authenticate('oauth2', { failureRedirect: '/' }), (req, res) => {
  res.send('Auth completed')
})

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
