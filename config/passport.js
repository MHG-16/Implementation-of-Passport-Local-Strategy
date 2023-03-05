
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const connection = require('./database');
const User = connection.models.User;

const customFields = {
    usernameField: 'uname',
    passwordField: 'pw'
}

const verifyCallback = (username, password, cb) => {

    User.findOne({username: username})
    .then(user => {
        if (!user) return cb(null, false);

        const isValid = validPassword(password, user.hash, user.salt);

        if(isValid) return cb(null, user)
        else return cb(null, false)
        }
    ).catch(err => cb(err))
}

const strategy = new LocalStrategy();

passport.use(strategy(customFields, verifyCallback));

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser((userId, done) => {
    User.findById(userId)
        .then(user => done(null, user))
        .catch(err => done(err)) 
})