/**
 * passport-oidc
 * Passport strategy for OpenID Connect consumers
 * MIT Licensed
 */

'use strict';

exports = module.exports = {
	getMethod: function(req) {
		var obj = req.route;
		return obj.stack[0].method;
	} 
};