/**
 * passport-oidc
 * Passport strategy for OpenID Connect consumers
 * MIT Licensed
 */

'use strict';

var passport = require('passport-strategy');
var util = require('util');
var tools = require('./tools');
var OIDCClient = require('oidc-client-node');

function Strategy(options, callback1, callback2) {
	if(!callback1 || !callback2) {
		throw new TypeError('OIDC-Client Strategy requires callbacks for both the get and post');
	}

	this._config = {
		scope: options.scope || 'profile roles',
		client_id: options.client_id || 'oidc-client',
		callbackURL: options.callbackURL || '/auth/oidc/callback',
		authority: options.authority,
		response_type: options.response_type || "id_token token", 
		response_mode: options.response_mode || "form_post",
		scopeSeparator: options.scopeSeperator || ' ',
		request_state_store: options.cookieHandler,
		verbose_logging: true
	};

	passport.Strategy.call(this);
	this.name = 'oidc';
	
	this._callback1 = callback1;
	this._callback2 = callback2;
}

/**
 * Inherit from `passport.Strategy`
 */

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {

	var method = tools.getMethod(req);
	var oidcClient = new OIDCClient(req, this._config);

	if(req.body != null && (req.body.token != null || req.body.error != null)) {
		var tokenResponse = oidcClient.processResponseAsync(req.body);
	    
	    tokenResponse.then(function (results) {
	      this_.callback2(req, results);
	    
	    }).catch(function(error){
	        console.log('error parsing token response: ' + error);
	    });
	} else {
		var localOptions = {
			callbackURL: options.callback,
			acr_values: "tenant:" + options.tenant
		};

		oidcClient.mergeRequestOptions(req, localOptions);
	    
	    var tokenRequest = oidcClient.createTokenRequestAsync();
	    
	    tokenRequest.then(function (results) {
	      this_.callback1(req, results.url); // callback to redirect to passed url

	    }).catch(function(error){
	        console.log('error generating redirect url: ' + error);
	    });
	}
};

/**
 * Expose `Strategy`
 */

module.exports = Strategy;