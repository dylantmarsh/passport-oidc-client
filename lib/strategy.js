/**
 * passport-oidc
 * Passport strategy for OpenID Connect consumers
 * MIT Licensed
 */

'use strict';

var passport = require('passport-strategy');
var util = require('util');
var OIDCClient = require('odic-client');

function Strategy(options) {
	passport.Strategy.call(this);
	this.name = 'oidc';

	this._scope = options.scope || 'profile roles';
	this._clientId = options.client_id || 'lightning';
	this._callbackURL = options.callbackURL || '/auth/oidc/callback';
	this._authority = options.authority;
	this._responseType = options.response_type || "id_token token";
	this._responseMode = options.response_mode || "form_post";
	this._scopeSeperator = options.scopeSeperator || ' ';

	this._config = {
		scope: this._scope,
		client_id: this._clientId,
		callbackURL: this._callbackURL,
		authority: this._authority,
		response_type: this._responseType, 
		response_mode: this._responseMode,
		scopeSeparator: this._scopeSeperator
	};
}

/**
 * Inherit from `passport.Strategy`
 */

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, res, options, callback) {
	var localOptions = {
		callbackURL: options.callback,
		acr_values: "tenant:" + options.tenant
	};

	var oidcClient = new OIDCClient(req, res, this._config);

	oidcClient.mergeRequestOptions(req, localOptions);
    
    var tokenRequest = oidcClient.createTokenRequestAsync();
    
    tokenRequest.then(function (results) {
      callback(req, res, results.url); // callback to redirect to passed url

    }).catch(function(error){
        console.log('error generating redirect url: ' + error);
    });
};

Strategy.prototype.postback = function(req, res, callback) {
	var oidcClient = new OIDCClient(req, res, this._config);

	var tokenResponse = oidcClient.processResponseAsync(req.body);
    
    tokenResponse.then(function (results) {
      callback(req, res, results);
    
    }).catch(function(error){
        console.log('error parsing token response: ' + error);
    });
};

/**
 * Expose `Strategy`
 */

module.exports = Strategy;