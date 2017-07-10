/**
 * JWT authenticator for the web services module.
 *
 * @module x2node-ws-auth-jwt
 * @requires module:x2node-common
 */
'use strict';

const jws = require('jws');
const common = require('x2node-common');


/**
 * Symbol used to mark the call as passed through this authenticator.
 *
 * @private
 * @constant {Symbol}
 */
const AUTHED = Symbol('AUTHED_JWT');

/**
 * Supported signature algorithms.
 *
 * @private
 * @constant {Set.<string>}
 */
const VALID_ALGS = new Set(jws.ALGORITHMS);

/**
 * Clock tolerance in seconds for "nbf" and "exp" tests.
 *
 * @private
 * @constant {number}
 */
const CLOCK_TOLERANCE = 2 * 60;

/**
 * JWT authenticator.
 *
 * @implements module:x2node-ws.Authenticator
 */
class JWTAuthenticator {

	/**
	 * Create new authenticator.
	 *
	 * @param {module:x2node-ws.ActorsRegistry} actorsRegistry Actors registry.
	 * @param {(string|external:Buffer|function)} secretOrKey Secret or public
	 * key used to verify the JWT signature. If function, the function receives
	 * decoded JWT object as its only argument and returns the key (string or
	 * buffer) or a promise of it.
	 * @param {Object} [claimsTest] Optional additional tests for the JWT claims
	 * set. Each object element has the name of the tested claim (e.g. "iss",
	 * "aud", "hd", etc.) and the value can be a function, which gets the claim
	 * value as its first argument and the whole claims set object as the second
	 * argument and returns <code>true</code> if valid and <code>false</code> if
	 * invalid, a <code>RegExp</code> object for a valid claim value, or a value
	 * (string, number, etc.) to perform simple equivalency test. Note, that
	 * token "nbf" and "exp" are always automatically tested.
	 * @param {string} [actorHandleClaim] Claim to use as the actor handle in the
	 * actor registry lookup. By default, "sub" claim is used.
	 */
	constructor(actorsRegistry, secretOrKey, claimsTest, actorHandleClaim) {

		this._actorsRegistry = actorsRegistry;
		this._secretOrKey = secretOrKey;
		this._claimsTest = claimsTest;
		this._actorHandleClaim = (actorHandleClaim || 'sub');

		this._log = common.getDebugLogger('X2_APP_AUTH');
	}

	// authenticate the call
	authenticate(call) {

		// mark the call
		call[AUTHED] = true;

		// get the token from the Authorization header
		const match = /^Bearer\s+(.+)/i.exec(
			call.httpRequest.headers['authorization']);
		if (match === null) {
			this._log('no valid Bearer Authorization header');
			return Promise.resolve(null);
		}
		const token = match[1];

		// decode the token
		const decodedToken = jws.decode(token);
		if (!decodedToken) {
			this._log('failed to decode the token');
			return Promise.resolve(null);
		}
		if ((typeof decodedToken.payload) === 'string') {
			try {
				decodedToken.payload = JSON.parse(decodedToken.payload);
			} catch (e) {
				this._log('failed to parse token payload:', e);
				return Promise.resolve(null);
			}
		}

		// get the token payload object
		const payload = decodedToken.payload;
		if ((typeof payload) !== 'object') {
			this._log('token payload is not an object');
			return Promise.resolve(null);
		}

		// validate the signature algorithm
		if (!decodedToken.header || !VALID_ALGS.has(decodedToken.header.alg)) {
			this._log('unsupported token signature algorithm');
			return Promise.resolve(null);
		}

		// make sure the token has signature
		if ((typeof decodedToken.signature) !== 'string') {
			this._log('token signature is not a string');
			return Promise.resolve(null);
		}

		// get current time
		const now = Math.floor(Date.now() / 1000);

		// build token verification promise
		const tokenVerificationPromise = Promise.resolve(
			(typeof this._secretOrKey) === 'function' ?
				this._secretOrKey.call(undefined, decodedToken) :
				this._secretOrKey
		).then(
			secretOrKey => {
				try {

					// did we get the key?
					if (!secretOrKey) {
						this._log('no key for the signature');
						return null;
					}

					// verify the token signature
					if (!jws.verify(
						token, decodedToken.header.alg, secretOrKey)) {
						this._log('invalid token signature');
						return null;
					}

					// validate token "not before"
					if (payload.nbf !== undefined) {
						if ((typeof payload.nbf) !== 'number') {
							this._log('token "nbf" is not a number');
							return null;
						}
						if (payload.nbf > now + CLOCK_TOLERANCE) {
							this._log('token is not yet active');
							return null;
						}
					}

					// validate token expiration
					if (payload.exp !== undefined) {
						if ((typeof payload.exp) !== 'number') {
							this._log('token "exp" is not a number');
							return null;
						}
						if (payload.exp < now - CLOCK_TOLERANCE) {
							this._log('token has expired');
							return null;
						}
					}

					// validate the claims
					if (this._claimsTest)
						for (let claimName in this._claimsTest) {
							const claimTest = this._claimsTest[claimName];
							let claimValid;
							if ((typeof claimTest) === 'function')
								claimValid = claimTest.call(
									undefined, payload[claimName], payload);
							else if (claimTest instanceof RegExp)
								claimValid = claimTest.test(payload[claimName]);
							else
								claimValid = (payload[claimName] === claimTest);
							if (!claimValid) {
								this._log(`claim "${claimName}" test failed`);
								return null;
							}
						}

				} catch (err) {
					return Promise.reject(err);
				}
			},
			err => Promise.reject(err)
		);

		// perform actor lookup and token verification in parallel
		return Promise.all([

			// token verification
			tokenVerificationPromise,

			// lookup the actor
			this._actorsRegistry.lookupActor(payload[this._actorHandleClaim])

		]).then(
			(results) => (results[0] && results[1]),
			err => Promise.reject(err)
		);
	}

	// add response headers
	addResponseHeaders(call, response) {

		if (call[AUTHED] && (response.statusCode === 401))
			response.setHeader('WWW-Authenticate', 'Bearer');
	}
}

// export the class
module.exports = JWTAuthenticator;
