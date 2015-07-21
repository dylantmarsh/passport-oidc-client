/**
 * passport-oidc
 * Passport strategy for OpenID Connect consumers
 * MIT Licensed
 */

'use strict';

var passport = require('passport-strategy');
var util = require('util');
var OIDCClient = require('oidc-client-node');

function Strategy(options, callback) {
	if(!callback) {
		throw new TypeError('OIDC-Client Strategy requires a callback');
	}

	this._config = {
		scope: options.scope || 'profile roles',
		client_id: options.clientId || 'oidc-client',
		callbackURL: options.callbackURL || '/auth/oidc/callback',
		authority: options.authority,
		response_type: options.responseType || "id_token token", 
		response_mode: options.responseMode || "form_post",
		scopeSeparator: options.scopeSeperator || ' ',
		request_state_store: options.cookieHandler,
		verbose_logging: true
	};

	passport.Strategy.call(this);
	this.name = 'oidc';
	
	this._callback = callback;
}

/**
 * Inherit from `passport.Strategy`
 */

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
	var that = this;
	var oidcClient = new OIDCClient(req, null, this._config);

	if(req.body != null && (req.body.access_token != null || req.body.id_token != null || req.body.error != null)) {
		var tokenResponse = oidcClient.processResponseAsync(req.body);
	    
	    tokenResponse.then(function (results) {
	      that._callback(results);
	    
	    }).catch(function(error){
	        console.log('error parsing token response: ' + error);
	    });
	} else {
		var localOptions = {
			callbackURL: options.callback,
			acr_values: "tenant:" + req.tenant
		};

		oidcClient.mergeRequestOptions(req, localOptions);
	    
	    var tokenRequest = oidcClient.createTokenRequestAsync();
	    
	    tokenRequest.then(function (results) {
	    	that.redirect(results.url);

	    }).catch(function(error){
	        console.log('error generating redirect url: ' + error);
	    });
	}
};

/**
 * Expose `Strategy`
 */

module.exports = Strategy;