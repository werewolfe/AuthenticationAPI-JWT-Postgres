const dotenv = require('dotenv');
dotenv.config();
const express = require('express');
const parser = require('body-parser');
const app = new express();

const passport = require('passport');
const passportJWT = require('passport-jwt');
const JwtStrategy = passportJWT.Strategy;
const ExtractJwt = passportJWT.ExtractJwt;
const knex = require('knex')({ client: 'pg', connection: 'postgres://localhost/jwt_test', searchPath: ['knex', 'public'], });
const bookshelf = require('bookshelf');
const securePassword = require('bookshelf-secure-password');
const db = bookshelf(knex);
db.plugin(securePassword);
const jwt = require('jsonwebtoken');

const User = db.Model.extend({
    tableName: 'login_user',
    hasSecurePassword: true
});


const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.SECRET_OR_KEY
};

const strategy = new JwtStrategy(opts, (payload, next) => {
  User.forge({ id: payload.id }).fetch().then(res => {
    next(null, res);
  });   
});

passport.use(strategy);
app.use(passport.initialize());
app.use(parser.urlencoded({
    extended: false
}));
app.use(parser.json());

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.post('/seedUser', (req, res) => {
    if(!req.body.email || !req.body.password) {
        return res.state(401).send('No Fields');
    }
    const user = new User({
        email: req.body.email,
        password: req.body.password
    });
    user.save().then(() => {res.send('OK');});
});

app.post('/getToken', (req, res) => {
    if(!req.body.email || !req.body.password) {
        return res.state(401).send('No Fields');
    }

    User.forge({ email: req.body.email }).fetch().then(result => {
        if(!result) {
            return res.status(400).send('User Not Found');
        }    
        result.authenticate(req.body.password).then(user => {
            const payload = {id: user.id};
            const token = jwt.sign(payload, process.env.SECRET_OR_KEY);
            res.send(token);
        }).catch(err => {
            return res.status(401).send({ err: err });
        });
    });
});

app.get('/protected', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.send('I\'m Protected');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT);