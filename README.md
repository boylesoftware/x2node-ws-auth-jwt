# X2 Framework for Node.js | Web Services JWT Authenticator

JSON Web Token (JWT) authenticator implementation for X2 Framework's [x2node-ws](https://www.npmjs.com/package/x2node-ws) module. For the JWT specification, see [RFC 7519](https://tools.ietf.org/html/rfc7519).

See module's [API Reference Documentation](https://boylesoftware.github.io/x2node-api-reference/module-x2node-ws-auth-jwt.html).

## Table of Contents

* [Usage](#usage)
* [Provider Examples](#provider-examples)
  * [Auth0](#auth0)
  * [Google Sign-In](#google-sign-in)

## Usage

To create an authenticator the application needs to provide:

* An actors registry (implementation of `ActorsRegistry` interface defined in `x2node-ws` module). Normally, the JWT's _subject_ (the "sub" claim) is used as the actor handle to lookup actors in the registry. A different claim can be used too (see authenticator constructor arguments).

* A secret or public key (depending on the algorithm), used to verify the token JWS signature.

Then, an authenticator can be added to a web service like the following:

```javascript
const ws = require('x2node-ws');
const JWTAuthenticator = require('x2node-ws-auth-jwt');

const MY_CLIENT_ID = '...';
const MY_SECRET_KEY = '...';

ws.createApplication()
    .addAuthenticator('/.*', new JWTAuthenticator(
        new MyActorsRegistry(), // custom application component
        new Buffer(MY_SECRET_KEY, 'base64'), {
            aud: MY_CLIENT_ID
        }
    ))
    ...
    .run(port);
```

The above installs the authenticator on all the web service endpoints.

The authenticator constructor takes the following arguments:

* `actorsRegistry` - Implementation of the `ActorsRegistry` interface (see [x2node-ws](https://www.npmjs.com/package/x2node-ws) module). The authenticator extracts an actor handle (whatever the application uses to identify sign users in, which may be the user id, login name, email, etc.) and uses it to lookup  the actor record in the actors registry.

* `secretOrKey` - Depending on the digital signature algorithm used by the provider that issues the JWTs, this is the public or the private key used to verify the signature. The key can be provided in one of the following forms:

  * A _Node.js_ `Buffer` with the key data. Normally, it's a secret key used with HMAC algorithms.
  * A string with the public key or certificate. Normally used with RSA and ECDSA algorithms.
  * A function, which takes the decoded JWT object, normally includes `header`, `payload` and `signature` elements, and returns the key string, `Buffer` or a `Promise` of either. Rejection of the promise leads to an application error, resolving it with a "falsy" value (`false`, `null`, `undefined`, etc.) leaves the call unauthenticated.

* `claimsTest` - An optional object with additional tests for the claims in the decoded token payload. The authenticator always automatically verifies "nbf" and "exp" claims, but the application can register additional tests. For example, it is almost always a good idea to include an "iss" and an "aud" claim test.

  The object provided as `claimsTest` has properties for each additional claim test. The name of the property is the claim name ("iss", "aud", etc.). The value can be one of the following:

  * A function, in which case it is passed the claim value as the first argument and the whole token payload object (aka claims set) as the second argument and returns either `true` if the claim is valid or `false` to deny authentication.
  * A `RegExp`, in which case the claim value is tested against it.
  * Anything else, in which case a simple equivalency test is used.

* `actorHandleClaim` - Optional name of the claim to use as the actor handle for the actors registry. If not specified, "sub" claim is used.

The authenticator uses `X2_APP_AUTH` section for debug logging. Add it to `NODE_DEBUG` environment variable to see the authenticator's debug messages (see [Node.js API docs](https://nodejs.org/docs/latest-v4.x/api/util.html#util_util_debuglog_section) for details).

## Provider Examples

The authenticator is written in a generic way to support JWT verification on the server side. Diffrerent authentication providers, however, use JWT in slightly different ways. Below are usage examples for some such providers.

### Auth0

When an [Auth0](https://auth0.com/) account is created for an application, it is issued a _Client ID_, which is used as the "aud" claim, and a _Client Secret_, which is the secret key for verification of JWT HMAC signatures. The "sub" claim can be normally used as the actor handle (note, that if Auth0's user database is used, the user id in the "sub" claim is prefixed with "auth0|"). Therefore, the JWT authenticator can be used as the following:

```javascript
const MY_CLIENT_ID = '...';
const MY_CLIENT_SECRET = '...';

ws.createApplication()
    .addAuthenticator('/.*', new JWTAuthenticator(
        new MyActorsRegistry(),
        new Buffer(MY_CLIENT_SECRET, 'base64'),
        {
            iss: 'https://myproject.auth0.com/',
            aud: MY_CLIENT_ID
        }
    ))
    ...
```

The example above verifies "iss" and "aud" claims as well.

### Google Sign-In

To use [Google Sign-In](https://developers.google.com/identity/sign-in/web/), a project is created in Google API Console and then assigned a _Client ID_, which is used as the "aud" claim. Instead of a secret key, however, Google Sign-In uses Google public keys to verify JWT RSA signatures. The current public keys are available at https://www.googleapis.com/oauth2/v1/certs and the specific key id used for the JWT signature is identified by "kid" field in the decoded JTW `header` section.

Here is an example of how it can be used:

```javascript
const request = require('request');

const MY_CLIENT_ID = 'XXX.apps.googleusercontent.com';

let keysExpireAt = 0;
let keys;

function getGooglePublicKeys(token) {

    // check if the keys are still fresh
    const now = Date.now();
    if (now < keysExpireAt)
        return keys;

    // give the get keys call 30 seconds to complete
    keysExpireAt = now + 30000;

    // do the call
    return keys = new Promise((resolve, reject) => {
        request.get(
            {
                url: 'https://www.googleapis.com/oauth2/v1/certs',
                json: true
            },
            (err, res, data) => {

                // reset expiration
                keysExpireAt = 0;

                // check if errors
                if (err)
                    return reject(err);
                if (res.statusCode !== 200)
                    return reject(`got ${res.statusCode} response`);

                // update expiration from the response
                keysExpireAt = (new Date(res.headers['expires'])).getTime();

                // fulfill promise with the keys
                resolve(data);
        });
    });
}

ws.createApplication()
    .addAuthenticator('/.*', new JWTAuthenticator(
        new MyActorsRegistry(),
        token => getGooglePublicKeys().then(
            keys => keys[token.header && token.header.kid],
            err => Promise.reject(err)
        ),
        {
            iss: 'https://accounts.google.com',
            aud: MY_CLIENT_ID,
            hd: 'mydomain.com' // can be used to restrict G Suite logins
        },
        'email' // use "email" claim as the user handle
    ))
    ...
```

The example above uses [request](https://www.npmjs.com/package/request) module to fetch the public certificates from Google. It also shows _very crude_ response caching logic.

Also, "email" claim is used as the user handle instead of the standard "sub".
