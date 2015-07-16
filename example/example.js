var express = require('express');
var app = express();
var passport = require('passport');
var oidcStrategy = require('../lib/index');
var Cookies = require('cookies');
var cookie = null;

app.all('/*', function(req, res, next) {
	cookie = new Cookies(req, res);
	next();
});

passport.use(new oidcStrategy({
	clientId: "example",
	authority: "",
	cookieHandler: cookie
}, callback1, callback2));

function callback1() {

}

function callback2() {

}

app.get('/login', passport.authenticate('oidc', {
	callback: 'test',
	tenant: '9'
}));

app.listen(3000);