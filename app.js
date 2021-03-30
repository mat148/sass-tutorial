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
var dotenv = require('dotenv');
dotenv.config();

var User = mongoose.model('User');

var Secret_Key = process.env.STRIPE_SECRET_KEY;

const stripe = require('stripe')(Secret_Key);
const bodyParser = require('body-parser');

mongoose.connect('mongodb://localhost:27017/sass-tutorial-db', { useNewUrlParser: true, useUnifiedTopology: true });

var app = express();

//VIEW ENGINE
//app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Match the raw body to content type application/json
app.post('/pay-success', bodyParser.json({type: 'application/json'}), (request, response) => {
    const event = request.body;

    // Handle the event
    switch (event.type) {
        case 'payment_intent.succeeded':
        const paymentIntent = event.data.object;

        break;
        case 'payment_method.attached':
        const paymentMethod = event.data.object;

        break;
        // ... handle other event types
        default:

        User.findOne({
            email: event.data.object.customer_details.email
        }, function(err, user) {
            if (user) {
                user.subscriptionActive = true;
                user.subscriptionId = event.data.object.subscription;
                user.customerId = event.data.object.customer;
                user.save();
            }
        })
    }

    // Return a response to acknowledge receipt of the event
    response.json({received: true});
});

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(expressSession({
    secret: process.env.EXPRESS_SESSION_SECRET
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
        console.log(err);
        console.log(user);
        if(err) return next(err);
        if(!user || !bcrypt.compareSync(password, user.passwordHash)) {
            return next({ message: 'Email or password incorrect' });
        }
        next(null, user);
    })
}));

passport.use('signup-local', new LocalStrategy({
    usernameField: "email",
    passwordField: "password"
}, function(email, password, next) {
    User.findOne({
        email: email
    }, function(err, user) {
        if(err) return next(err);
        if(user) return next({message: "User already exists"});
        let newUser = new User({
            email: email,
            passwordHash: bcrypt.hashSync(password, 10)
        })
        newUser.save(function(err) {
            next(err, newUser);
        });
    });
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

app.get("/billing", async (req, res, next) => {
    const session = await stripe.checkout.sessions.create({
        mode: "subscription",
        payment_method_types: ["card"],
        line_items: [{
            price: process.env.STRIPE_PRICE_KEY,
            quantity: 1
        }],

        success_url: 'http://localhost:3000/billing?session_id={CHECKOUT_SESSION_ID}',
        cancel_url: 'http://localhost:3000/billing',
    }, function(err, session) {
        if (err) return next(err);
        //console.log(session.id);
        res.render('billing', {sessionId: session.id, subscriptionActive: req.user.subscriptionActive, STRIPE_PUBLIC_KEY: process.env.STRIPE_PUBLIC_KEY});
    });
});

app.get('/logout', function (req, res, next) {
    req.logout();
    res.redirect('/');
});

app.get('/main', function (req, res, next) {
    res.render('main');
});

app.post('/login',
passport.authenticate('local', {failureRedirect: '/login'}),
function (req, res, next) {
    res.redirect('/main');
});


app.get('/login', function (req, res, next) {
    res.render('login');
});

app.post('/signup',
passport.authenticate('signup-local', {failureRedirect: '/'}),
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