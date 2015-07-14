/**
 * passport-oidc
 * Passport strategy for OpenID Connect consumers
 * MIT Licensed
 */

'use strict';

var passport = require('passport-strategy');
var util = require('util');
var oidc = require('./odic');

function Strategy(options) {
	passport.Strategy.call(this);
	this.name = 'oidc';
}

/**
 * Inherit from `passport.Strategy`
 */

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
	
}

/**
 * Expose `Strategy`
 */

module.exports = Strategy;