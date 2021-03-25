var createError = require('http-errors');
var express = require('express');
var ejs = require('ejs');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var mongoose = require('mongoose');
require('./models');
var bcrypt = require('bcrypt');
var expressSession = require('express-session');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = mongoose.model('User');

mongoose.connect('mongodb://localhost:27017/sass-tutorial-db', { useNewUrlParser: true, useUnifiedTopology: true });

var app = express();

//VIEW ENGINE
//app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(expressSession({
    secret: "sauhdsfiuhsailuhweiluhw4e8y95342uihewrfjknasdkjlnaskjhsdadkjndsfjklsdjnsdsfjndnfs"
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy({
    usernameField: "email",
    passwordField: "password"
}, function(email, password, next) {
    User.findOne({
        email: email
    }, function(err, user) {
        if(err) return next(err);
        if(!user | !bcrypt.compareSync(password, user.passwordHash)) {
            return next({ message: 'Email or password incorrect' });
        }
        next(null, user);
    })
}));

passport.serializeUser(function(user, next) {
    next(null, user._id);
});

passport.deserializeUser(function(id, next) {
    User.findById(id, function(err, user) {
        next(err, user);
    });
});

app.get('/', function (req, res, next) {
    res.render('index', {title: "SaaS Tutorial"});
});

app.post('/signup', function (req, res, next) {
    User.findOne({
        email: req.body.email
    }, function(err, user) {
        if(err) return next(err);
        if(user) return next({message: "User already exists"});
        let newUser = new User({
            email: req.body.email,
            passwordHash: bcrypt.hashSync(req.body.password, 10)
        })
        newUser.save(function(err) {
            if(err) return next(err);
            res.redirect('/main');
        });
    });
    //console.log(req.body);
});

app.get('/main', function (req, res, next) {
    res.render('main');
});

app.get('/login', function (req, res, next) {
    res.render('login');
});

app.post('/login',
passport.authenticate('local', {failureRedirect: '/login'}),
function (req, res, next) {
    res.redirect('/main');
});

//404
app.use(function(req, res, next) {
    next(createError(404));
});

//ERROR HANDLER
app.use(function(err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    // render the error page
    res.status(err.status || 500);
    res.render('error')
});

app.listen(3000, () => {
    console.log(`Example app listening at http://localhost:3000`);
});