# X2 Framework for Node.js | Web Services JWT Authenticator

JSON Web Token (JWT) authenticator implementation for X2 Framework's webservices module.

## Usage

To create an authenticator the application needs to provide:

* An actors registry (implementation of `ActorRegistry` interface defined in `x2node-common` module). The handle used to lookup actors in the registry is the JWT's _subject_ (the `sub` field).

* A client id, which is the JWT's _audience_ (the `aud` field). Providers like [Auth0](https://auth0.com/) call it _Client ID_.

* A client secret, which is the JWT's secret (or public, depending on the algorithm used) key. Providers like [Auth0](https://auth0.com/) call it _Client Secret_.

Then, an authenticator can be added to a webservice like the following:

```javascript
const webservices = require('x2node-webservices');
const JWTAuthenticator = require('x2node-webservices-auth-jwt');

const MY_CLIENT_ID = '...';
const MY_CLIENT_SECRET = '...';

webservices.createApplication()
	.addAuthenticator('/.*', new JWTAuthenticator(
		new MyActorsRegistry(), // custom application component
		MY_CLIENT_ID,
		new Buffer(MY_CLIENT_SECRET, 'base64')
	))
	...
	.run(port);
```

The above installs the authenticator on all the webservice endpoints.

The authenticator uses `X2_APP_AUTH` section for debug logging. Add it to `NODE_DEBUG` environment variable to see the authenticator's debug messages.
