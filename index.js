/**
 * JWT authenticator for the web services module.
 *
 * @module x2node-ws-auth-jwt
 * @requires module:x2node-common
 */
'use strict';

const url = require('url');
const jws = require('jws');
const common = require('x2node-common');


/**
 * The log.
 *
 * @private
 */
const log = common.getDebugLogger('X2_APP_AUTH');


/**
 * JWKS key provider.
 *
 * @private
 */
class JWKSKeyProvider {

	/**
	 * Create new provider.
	 *
	 * @param {string} jwksUri The JWKS URI.
	 */
	constructor(jwksUri) {

		const jwksUrl = new url.URL(jwksUri);
		switch (jwksUrl.protocol) {
		case 'https:':
			this._client = require('https');
			break;
		case 'http:':
			this._client = require('http');
			break;
		default:
			throw new common.X2UsageError('The JWKS URI must be http or https.');
		}

		this._requestOptions = {
			_href: jwksUrl.href,
			method: 'GET',
			hostname: jwksUrl.hostname,
			port: jwksUrl.port,
			path: jwksUrl.pathname,
			headers: {
				'Accept': 'application/json'
			}
		};
		if (jwksUrl.username)
			this._requestOptions.auth =
				`${jwksUrl.username}:${jwksUrl.password}`;

		this._keysPromise = null;
		this._keysPending = false;
		this._keysExp = 0;
	}

	/**
	 * Get the keys using cached JWKS or load the JWKS.
	 *
	 * @returns {Promise} Promise of an object with keys being the key ids and
	 * values being the certificates used to verify signatures.
	 */
	getKeys() {

		if (!this._keysPending && (Date.now() >= this._keysExp)) {
			this._keysPending = true;
			this._keysPromise = new Promise((resolve, reject) => {
				log(`loading keys from ${this._requestOptions._href}`);
				const request = this._client.request(
					this._requestOptions, response => {
						const chunks = [];
						response.on('data', chunk => {
							chunks.push(chunk);
						}).on('end', () => {
							let jwks;
							const contentType = response.headers['content-type'];
							if (/^application\/json/.test(contentType)) {
								try {
									jwks = JSON.parse(
										Buffer.concat(chunks).toString('utf8'));
								} catch (e) {
									return reject(new common.X2DataError(
										'Could not parse JWKS response: ' +
											e.message));
								}
							}
							const statusCode = response.statusCode;
							if ((statusCode < 200) || (statusCode >= 300))
								return reject(new common.X2DataError(
									`Error ${statusCode} response from JWKS.`));
							if (!jwks || !Array.isArray(jwks.keys))
								return reject(new common.X2DataError(
									'Invalid JWKS response.'));
							const expiresHeader = response.headers['expires'];
							jwks.expiresAt = (
								expiresHeader ?
									(new Date(expiresHeader)).getTime() :
									Date.now() + 24*3600*1000
							);
							resolve(jwks);
						});
					});
				request.on('error', err => {
					reject(err);
				});
				request.end();
			}).then(
				jwks => {
					this._keysPending = false;
					this._keysExp = jwks.expiresAt;
					return jwks.keys.reduce((res, jwk) => {
						if ((jwk.use === 'sig') &&
							Array.isArray(jwk.x5c) && (jwk.x5c.length > 0)) {
							res[`${jwk.kid}:${jwk.alg}`] = (
								'-----BEGIN CERTIFICATE-----\n' +
								jwk.x5c[0].match(/.{1,64}/g).join('\n') +
								'\n-----END CERTIFICATE-----\n'
							);
						}
						return res;
					}, new Object());
				},
				err => {
					this._keysPending = false;
					this._keysExp = 0;
					return Promise.reject(err);
				}
			);
		}

		return this._keysPromise;
	}

	/**
	 * Get the key for the specified token.
	 *
	 * @param {Object} jwt Decoded JWT.
	 * @returns {Promise.<string>} Promise of the key.
	 */
	getKey(jwt) {

		if (!jwt.header || !jwt.header.kid || !jwt.header.alg) {
			log('no kid or alg in the token header');
			return null;
		}

		return this.getKeys().then(
			keys => keys[`${jwt.header.kid}:${jwt.header.alg}`]);
	}
}


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
	 * (string, number, etc.) to perform simple equivalency test. If the claim
	 * "aud" and the claim value in the JWT is an array, the claim test will
	 * succeed if <em>any</em> value in the array passes the specified claim
	 * test. Note, that token "nbf" and "exp" are always automatically tested.
	 * @param {string} [actorHandleClaim] Claim to use as the actor handle in the
	 * actor registry lookup. By default, "sub" claim is used.
	 */
	constructor(actorsRegistry, secretOrKey, claimsTest, actorHandleClaim) {

		this._actorsRegistry = actorsRegistry;
		this._secretOrKey = secretOrKey;
		this._claimsTest = claimsTest;
		this._actorHandleClaim = (actorHandleClaim || 'sub');
	}

	// authenticate the call
	authenticate(call) {

		// mark the call
		call[AUTHED] = true;

		// get the token from the Authorization header
		const match = /^Bearer\s+(.+)/i.exec(
			call.httpRequest.headers['authorization']);
		if (match === null) {
			log('no valid Bearer Authorization header');
			return Promise.resolve(null);
		}
		const token = match[1];

		// decode the token
		const decodedToken = jws.decode(token);
		if (!decodedToken) {
			log('failed to decode the token');
			return Promise.resolve(null);
		}
		if ((typeof decodedToken.payload) === 'string') {
			try {
				decodedToken.payload = JSON.parse(decodedToken.payload);
			} catch (e) {
				log('failed to parse token payload:', e);
				return Promise.resolve(null);
			}
		}

		// get the token payload object
		const payload = decodedToken.payload;
		if ((typeof payload) !== 'object') {
			log('token payload is not an object');
			return Promise.resolve(null);
		}

		// get actor handle
		const actorHandle = payload[this._actorHandleClaim];
		if ((actorHandle === undefined) || (actorHandle === null)) {
			log(`no "${this._actorHandleClaim}" claim in the token`);
			return Promise.resolve(null);
		}

		// validate the signature algorithm
		if (!decodedToken.header || !VALID_ALGS.has(decodedToken.header.alg)) {
			log('unsupported token signature algorithm');
			return Promise.resolve(null);
		}

		// make sure the token has signature
		if ((typeof decodedToken.signature) !== 'string') {
			log('token signature is not a string');
			return Promise.resolve(null);
		}

		// get current time
		const now = Math.floor(Date.now() / 1000);

		// build token verification promise
		/*let tokenVerificationPromise;
		if ((typeof this._secretOrKey) === 'function') {
			const secretOrKeyResult = this._secretOrKey(
		}*/
		const tokenVerificationPromise = Promise.resolve(
			(typeof this._secretOrKey) === 'function' ?
				/*this._secretOrKey.call(undefined, decodedToken)*/this._secretOrKey(decodedToken) :
				this._secretOrKey
		).then(
			secretOrKey => {
				try {

					// did we get the key?
					if (!secretOrKey) {
						log('no key for the signature');
						return null;
					}

					// verify the token signature
					if (!jws.verify(
						token, decodedToken.header.alg, secretOrKey)) {
						log('invalid token signature');
						return null;
					}

					// validate token "not before"
					if (payload.nbf !== undefined) {
						if ((typeof payload.nbf) !== 'number') {
							log('token "nbf" is not a number');
							return null;
						}
						if (payload.nbf > now + CLOCK_TOLERANCE) {
							log('token is not yet active');
							return null;
						}
					}

					// validate token expiration
					if (payload.exp !== undefined) {
						if ((typeof payload.exp) !== 'number') {
							log('token "exp" is not a number');
							return null;
						}
						if (payload.exp < now - CLOCK_TOLERANCE) {
							log('token has expired');
							return null;
						}
					}

					// validate the claims
					if (this._claimsTest)
						for (let claimName in this._claimsTest) {
							const claimTest = this._claimsTest[claimName];
							const claimValue = payload[claimName];
							let claimValid;
							if ((claimName === 'aud') &&
								Array.isArray(claimValue)) {
								claimValid = false;
								for (let v of claimValue) {
									if (this.isClaimValid(
										claimTest, v, payload)) {
										claimValid = true;
										break;
									}
								}
							} else {
								claimValid = this.isClaimValid(
									claimTest, claimValue, payload);
							}
							if (!claimValid) {
								log(`claim "${claimName}" test failed`);
								return null;
							}
						}

					// token verified
					return true;

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
			this._actorsRegistry.lookupActor(actorHandle)

		]).then(
			(results) => (results[0] && results[1]),
			err => Promise.reject(err)
		);
	}

	// test claim value
	isClaimValid(claimTest, claimValue, payload) {

		if ((typeof claimTest) === 'function')
			return claimTest.call(undefined, claimValue, payload);

		if (claimTest instanceof RegExp)
			return claimTest.test(claimValue);

		return (claimValue === claimTest);
	}

	// add response headers
	addResponseHeaders(call, response) {

		if (call[AUTHED] && (response.statusCode === 401))
			response.setHeader('WWW-Authenticate', 'Bearer');
	}

	/**
	 * Create key provider function for the authenticator that reads the keys
	 * from a JWK Set
	 * (see [RFC 7517]{@link https://tools.ietf.org/html/rfc7517}).
	 *
	 * @param {string} jwksUri The JWK Set URI. Usually available as "jkws_uri"
	 * property in the OpenID Connect discovery document.
	 * @returns {function} Keys provider function that can be used as the
	 * <code>secretOrKey</code> argument to the authenticator constructor.
	 */
	static jwksKey(jwksUri) {

		const provider = new JWKSKeyProvider(jwksUri);

		return provider.getKey.bind(provider);
	}
}

// export the class
module.exports = JWTAuthenticator;
