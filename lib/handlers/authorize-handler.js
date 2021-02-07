
/**
 * Module dependencies.
 */

var _ = require('lodash');
var AccessDeniedError = require('../errors/access-denied-error');
var AuthenticateHandler = require('../handlers/authenticate-handler');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidClientError = require('../errors/invalid-client-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var InvalidScopeError = require('../errors/invalid-scope-error');
var OAuthError = require('../errors/oauth-error');
var Promise = require('bluebird');
var Request = require('../request');
var Response = require('../response');
var ServerError = require('../errors/server-error');
var UnauthorizedClientError = require('../errors/unauthorized-client-error');
var is = require('../validator/is');
var qs = require('querystring');
var tokenUtil = require('../utils/token-util');
var url = require('url');

/**
 * Response types.
 */

var responseTypes = {
  code: require('../response-types/code-response-type'),
  token: require('../response-types/token-response-type')
};

/**
 * Constructor.
 */

function AuthorizeHandler(options) {
  options = options || {};

  if (!options.authorizationCodeLifetime) {
    throw new InvalidArgumentError('Missing parameter: `authorizationCodeLifetime`');
  }

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getClient) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getClient()`');
  }

  if (!options.model.saveAuthorizationCode) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveAuthorizationCode()`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  if (!options.model.validateScope) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `validateScope()`');
  }

  if (!options.model.authorizationAllowed) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `authorizationAllowed()`');
  }

  this.authorizationCodeLifetime = options.authorizationCodeLifetime;
  this.accessTokenLifetime = options.accessTokenLifetime;
  this.authenticateHandler = new AuthenticateHandler(options);
  this.model = options.model;
}

/**
 * Authorize Handler.
 */

AuthorizeHandler.prototype.handle = function(request, response) {
  if (!(request instanceof Request)) {
    throw new InvalidArgumentError('Invalid argument: `request` must be an instance of Request');
  }

  if (!(response instanceof Response)) {
    throw new InvalidArgumentError('Invalid argument: `response` must be an instance of Response');
  }

  var fns = [
    this.getClient(request),
    this.model.getUser ? this.model.getUser(request, response) : this.getUser(request, response)
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(function(client, user) {
      var responseType;
      var scope;
      var state;

      return Promise.bind(this)
        .then(function() {
          return this.authorizationAllowed(request);
        })
        .then(function() {
          scope = this.getScope(request);

          return this.validateScope(user, client, scope);
        })
        .then(function(scope) {
          state = this.getState(request);
          responseType = this.getResponseType(request);

          return this.buildSuccessRedirectUri(responseType, client, user, scope);
        })
        .then(function(redirect) {
          this.updateResponse(responseType, response, redirect.url, state);

          return redirect.code;
        })
        .catch(function(e) {
          if (!(e instanceof OAuthError)) {
            e = new ServerError(e);
          }

          var redirectUri = this.buildErrorRedirectUri(responseType, client, e);

          this.updateResponse(responseType, response, redirectUri, state);

          throw e;
        });
    });
};

/**
 * Get the client from the model.
 */

AuthorizeHandler.prototype.getClient = function(request) {
  var clientId = request.body.client_id || request.query.client_id;

  if (!clientId) {
    throw new InvalidRequestError('Missing parameter: `client_id`');
  }

  if (!is.vschar(clientId)) {
    throw new InvalidRequestError('Invalid parameter: `client_id`');
  }

  var redirectUri = request.body.redirect_uri || request.query.redirect_uri;

  if (redirectUri && !is.uri(redirectUri)) {
    throw new InvalidRequestError('Invalid request: `redirect_uri` is not a valid URI');
  }

  return Promise.try(() => this.model.getClient(clientId))
    .then(function(client) {
      if (!client) {
        throw new InvalidClientError('Invalid client: client credentials are invalid');
      }

      if (!client.grants) {
        throw new InvalidClientError('Invalid client: missing client `grants`');
      }

      if (!_.includes(client.grants, 'authorization_code')) {
        throw new UnauthorizedClientError('Unauthorized client: `grant_type` is invalid');
      }

      if (!client.redirectUri) {
        throw new InvalidClientError('Invalid client: missing client `redirectUri`');
      }

      if (
        redirectUri && 
        (
          (Array.isArray(client.redirectUri) && client.redirectUri.indexOf(redirectUri) === -1) || 
          (typeof client.redirectUri === 'string' && client.redirectUri !== redirectUri)
        )
      ) {
        throw new InvalidClientError('Invalid client: `redirect_uri` does not match client value');
      }

      if(redirectUri) client.redirectUri = redirectUri;

      return client;
    });
};

/**
 * Validate scope.
 */

AuthorizeHandler.prototype.validateScope = function(user, client, scope) {
  return Promise.try(() => this.model.validateScope(user, client, scope)).then(function(validationResult) {
    if (typeof validationResult === 'string') {
      return validationResult;
    }

    if (!validationResult) {
      throw new InvalidScopeError('Invalid scope: scope is invalid');
    }

    return scope;
  });
};

/**
 * Check that user allowed authorization
 */

AuthorizeHandler.prototype.authorizationAllowed = function(request) {
  return Promise.try(() => this.model.authorizationAllowed(request)).then(function(allowed) {
    if (!allowed) {
      throw new AccessDeniedError('Access denied: user denied access to application');
    }

    return allowed;
  });
};

/**
 * Get scope from the request.
 */

AuthorizeHandler.prototype.getScope = function(request) {
  var scope = request.body.scope || request.query.scope;

  if (scope && !is.nqschar(scope)) {
    throw new InvalidScopeError('Invalid parameter: `scope`');
  }

  return scope;
};

/**
 * Get state from the request.
 */

AuthorizeHandler.prototype.getState = function(request) {
  var state = request.body.state || request.query.state;

  if (state && !is.vschar(state)) {
    throw new InvalidRequestError('Invalid parameter: `state`');
  }

  return state;
};

/**
 * Get user by calling the authenticate middleware.
 */

AuthorizeHandler.prototype.getUser = function(request, response) {
  return this.authenticateHandler.handle(request, response).then(function(token) {
    return token.user;
  });
};

/**
 * Get response type.
 */

AuthorizeHandler.prototype.getResponseType = function(request) {
  var responseType = request.body.response_type || request.query.response_type;

  if (!responseType) {
    throw new InvalidRequestError('Missing parameter: `response_type`');
  }

  if (Object.keys(responseTypes).indexOf(responseType) === -1) {
    throw new InvalidRequestError('Invalid parameter: `response_type`');
  }

  var Type = responseTypes[responseType];

  return new Type(this);
};

/**
 * Build a successful response that redirects the user-agent to the client-provided url.
 */

AuthorizeHandler.prototype.buildSuccessRedirectUri = function(responseType, client, user, scope) {
  return Promise.try(() => responseType.buildRedirectUri.call(responseType, client, user, scope));
};

/**
 * Build an error response that redirects the user-agent to the client-provided url.
 */

AuthorizeHandler.prototype.buildErrorRedirectUri = function(responseType, client, error) {
  responseType = responseType || {};
  var uri = url.parse(client.redirectUri, true);

  uri.query = uri.query || {};
  uri.search = null;

  if(responseType.hash) {
    uri.hash = uri.hash || '#';
  }

  if (responseType.hash) {
    var query = qs.parse(uri.hash.substr(1));

    query.error = error.name;

    if (error.message) {
      query.error_description = error.message;
    }

    uri.hash = '#' + qs.stringify(query);
  } else {
    uri.query.error = error.name;

    if (error.message) {
      uri.query.error_description = error.message;
    }
  }

  return uri;
};

/**
 * Update response with the redirect uri and the state parameter, if available.
 */

AuthorizeHandler.prototype.updateResponse = function(responseType, response, redirectUri, state) {
  responseType = responseType || {};
  redirectUri.query = redirectUri.query || {};

  if(responseType.hash) {
    redirectUri.hash = redirectUri.hash || '#';
  }

  if (state) {
    if (responseType.hash) {
      var query = qs.parse(redirectUri.hash.substr(1));

      query.state = state;

      redirectUri.hash = '#' + qs.stringify(query);
    } else {
      redirectUri.query.state = state;
    }
  }

  response.redirect(url.format(redirectUri));
};

/**
 * Export constructor.
 */

module.exports = AuthorizeHandler;
