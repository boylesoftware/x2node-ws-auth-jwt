# X2 Framework for Node.js | Web Services JWT Authenticator

JSON Web Token (JWT) authenticator implementation for X2 Framework's [x2node-ws](https://www.npmjs.com/package/x2node-ws) module.

See module's [API Reference Documentation](https://boylesoftware.github.io/x2node-api-reference/module-x2node-ws-auth-jwt.html).

## Usage

To create an authenticator the application needs to provide:

* An actors registry (implementation of `ActorRegistry` interface defined in `x2node-common` module). The JWT's _subject_ (the `sub` field) is the handle used to lookup actors in the registry.

* A client id, which is the JWT's _audience_ (the `aud` field). Providers like [Auth0](https://auth0.com/) call it _Client ID_.

* A client secret, which is the JWT's secret (or public, depending on the algorithm used) key. Providers like [Auth0](https://auth0.com/) call it _Client Secret_.

Then, an authenticator can be added to a web service like the following:

```javascript
const ws = require('x2node-ws');
const JWTAuthenticator = require('x2node-ws-auth-jwt');

const MY_CLIENT_ID = '...';
const MY_CLIENT_SECRET = '...';

ws.createApplication()
    .addAuthenticator('/.*', new JWTAuthenticator(
        new MyActorsRegistry(), // custom application component
        MY_CLIENT_ID,
        new Buffer(MY_CLIENT_SECRET, 'base64')
    ))
    ...
    .run(port);
```

The above installs the authenticator on all the web service endpoints.

The authenticator uses `X2_APP_AUTH` section for debug logging. Add it to `NODE_DEBUG` environment variable to see the authenticator's debug messages (see [Node.js API docs](https://nodejs.org/docs/latest-v4.x/api/util.html#util_util_debuglog_section) for details).
