/**
 * passport-oidc
 * Passport strategy for OpenID Connect consumers
 * MIT Licensed
 */

'use strict';

/**
 * Module dependencies
 */

var Strategy = require('./strategy');

/**
 * Expose `Strategy` directly from package
 */

exports = module.exports = Strategy;

/**
 * Export constructors
 */

exports.Strategy = Strategy;