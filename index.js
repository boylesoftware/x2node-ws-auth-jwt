/**
 * JWT authenticator for the web services module.
 *
 * @module x2node-webservices-auth-jwt
 * @requires module:x2node-common
 */
'use strict';

const jwt = require('jsonwebtoken');
const common = require('x2node-common');


/**
 * JWT authenticator.
 *
 * @implements module:x2node-webservices.Authenticator
 */
class JWTAuthenticator {

	/**
	 * Create new authenticator.
	 *
	 * @param {module:x2node-webservices.ActorsRegistry} actorsRegistry Actors
	 * registry.
	 * @param {string} clientId Client id.
	 * @param {(string|external:Buffer)} clientSecret Client secret key.
	 */
	constructor(actorsRegistry, clientId, clientSecret) {

		this._actorsRegistry = actorsRegistry;
		this._clientId = clientId;
		this._clientSecret = clientSecret;

		this._log = common.getDebugLogger('X2_APP_AUTH');
	}

	// authenticate the call
	authenticate(call) {

		// get the token from the Authorization header
		const match = /^Bearer (.+)/.exec(
			call.httpRequest.headers['authorization']);
		if (match === null)
			return Promise.resolve(null);
		const token = match[1];

		// decode the token
		const decodedToken = jwt.decode(token, { complete: true });
		if (decodedToken === null)
			return Promise.resolve(null);

		// perform actor lookup and token verification in parallel
		return Promise.all([

			// token verification
			new Promise((resolve, reject) => {
				try {
					jwt.verify(token, this._clientSecret, {
						audience: this._clientId,
						subject: decodedToken.payload.sub
					}, (err, verifiedToken) => {
						if (err) {
							this._log(`authentication error: ${err.message}`);
							resolve(null);
						} else {
							resolve(verifiedToken);
						}
					});
				} catch (err) {
					reject(err);
				}
			}),

			// lookup the actor
			this._actorsRegistry.lookupActor(decodedToken.payload.sub)

		]).then(
			(results) => (results[0] && results[1]),
			err => Promise.reject(err)
		);
	}
}

// export the class
module.exports = JWTAuthenticator;
