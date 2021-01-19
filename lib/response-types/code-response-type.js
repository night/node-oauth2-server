
/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var Promise = require('bluebird');
var tokenUtil = require('../utils/token-util');
var url = require('url');

/**
 * Constructor.
 */

function CodeResponseType(options) {
  options = options || {};

  if (!options.authorizationCodeLifetime) {
    throw new InvalidArgumentError('Missing parameter: `authorizationCodeLifetime`');
  }

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.saveAuthorizationCode) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveAuthorizationCode()`');
  }

  this.model = options.model;
  this.authorizationCodeLifetime = options.authorizationCodeLifetime;
}

/**
 * Generate authorization code.
 */

CodeResponseType.prototype.generateAuthorizationCode = function() {
  if (this.model.generateAuthorizationCode) {
    return Promise.try(() => this.model.generateAuthorizationCode());
  }

  return tokenUtil.generateRandomToken();
};

/**
 * Get authorization code lifetime.
 */

CodeResponseType.prototype.getAuthorizationCodeLifetime = function() {
  return new Date(Date.now() + this.authorizationCodeLifetime * 1000);
};

/**
 * Save authorization code.
 */

CodeResponseType.prototype.saveAuthorizationCode = function(authorizationCode, expiresAt, scope, client, user) {
  var code = {
    authorizationCode: authorizationCode,
    expiresAt: expiresAt,
    scope: scope
  };

  return Promise.try(() => this.model.saveAuthorizationCode(code, client, user));
};

/**
 * Build redirect uri.
 */

CodeResponseType.prototype.buildRedirectUri = function(client, user, scope) {
  if (!client) {
    throw new InvalidArgumentError('Missing parameter: `client`');
  }

  if (!user) {
    throw new InvalidArgumentError('Missing parameter: `user`');
  }

  var fns = [
    this.generateAuthorizationCode(),
    this.getAuthorizationCodeLifetime()
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(function(authorizationCode, expiresAt) {
      return Promise.bind(this)
        .then(function() {
          return this.saveAuthorizationCode(authorizationCode, expiresAt, scope, client, user);
        })
        .then(function(code) {
          var uri = url.parse(client.redirectUri, true);

          uri.query = uri.query || {};

          uri.query.code = code.authorizationCode;
          uri.search = null;

          return { code: code, url: uri };
        });
    });
};

/**
 * Export constructor.
 */

module.exports = CodeResponseType;
