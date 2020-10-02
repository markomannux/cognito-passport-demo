require('dotenv').config();
const fetch = require('node-fetch');
const Headers = require('node-fetch').Headers;
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var session = require('express-session');
var jwt = require('jsonwebtoken');

var passport = require('passport');
var OAuth2Strategy = require('passport-oauth2');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
const { post } = require('./routes/index');

var app = express();

const POOL_BASE_URL = process.env.POOL_BASE_URL;
const AUTH_URL = process.env.AUTH_URL; 
const TOKEN_URL = process.env.TOKEN_URL;
const EXAMPLE_CLIENT_ID = process.env.EXAMPLE_CLIENT_ID;
const EXAMPLE_CLIENT_SECRET = process.env.EXAMPLE_CLIENT_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL;

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true
}))
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

app.use(express.static(path.join(__dirname, 'public')));

OAuth2Strategy.prototype.userProfile = async function(accessToken, done) {
var myHeaders = new Headers();
myHeaders.append("Authorization", `Bearer ${accessToken}`);

var requestOptions = {
  method: 'GET',
  headers: myHeaders,
  redirect: 'follow'
};

const profile = await fetch(`${POOL_BASE_URL}/oauth2/userInfo`, requestOptions)
  .then(response => response.text())
  .then(result => done(null, result))
  .catch(error => console.log('error', error));
  return profile;
}

passport.use(new OAuth2Strategy({
    authorizationURL: AUTH_URL,
    tokenURL: TOKEN_URL,
    clientID: EXAMPLE_CLIENT_ID,
    clientSecret: EXAMPLE_CLIENT_SECRET,
    callbackURL: CALLBACK_URL
  },
  function(accessToken, refreshToken, profile, cb) {
    let decoded = jwt.decode(accessToken);
    console.log(profile);
    return cb(null, profile);
  }
));

function isLoggedIn(request, response, next) {
    // passport adds this to the request object
    if (request.isAuthenticated()) {
        return next();
    }
    response.redirect('/login');
}

app.use('/', indexRouter);
app.get('/login', passport.authenticate('oauth2',
    {
      scope: ['openid'],
      successRedirect: '/users',
      failureRedirect: '/'
    }))
app.use('/users', isLoggedIn, usersRouter);

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
