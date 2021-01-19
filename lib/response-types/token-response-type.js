
/**
 * Module dependencies.
 */

var _ = require('lodash');
var BearerTokenType = require('../token-types/bearer-token-type');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var Promise = require('bluebird');
var TokenModel = require('../models/token-model');
var qs = require('querystring');
var tokenUtil = require('../utils/token-util');
var url = require('url');

/**
 * Constructor.
 */

function TokenResponseType(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  this.hash = true;
  this.model = options.model;
  this.accessTokenLifetime = options.accessTokenLifetime || 0;
}

/**
 * Generate access token.
 */

TokenResponseType.prototype.generateAccessToken = function() {
  if (this.model.generateAccessToken) {
    return Promise.try(() => this.model.generateAccessToken());
  }

  return tokenUtil.generateRandomToken();
};

/**
 * Get access token expiration date.
 */

TokenResponseType.prototype.getAccessTokenExpiresAt = function() {
  return new Date(this.accessTokenLifetime === 0 ? 0 : Date.now() + this.accessTokenLifetime * 1000);
};

/**
 * Save token.
 */

TokenResponseType.prototype.saveToken = function(user, client, scope) {
  var fns = [
    this.generateAccessToken(),
    this.getAccessTokenExpiresAt(),
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(function(accessToken, accessTokenExpiresAt) {
      var token = {
        accessToken: accessToken,
        accessTokenExpiresAt: accessTokenExpiresAt,
        scope: scope
      };

      return this.model.saveToken(token, client, user);
    });
};

/**
 * Get token type.
 */

TokenResponseType.prototype.getTokenType = function(model) {
  return new BearerTokenType(model.accessToken, this.accessTokenLifetime, model.refreshToken, model.scope);
};

/**
 * Build redirect uri.
 */

TokenResponseType.prototype.buildRedirectUri = function(client, user, scope) {
  if (!client) {
    throw new InvalidArgumentError('Missing parameter: `client`');
  }

  if (!user) {
    throw new InvalidArgumentError('Missing parameter: `user`');
  }

  var fns = [
    this.generateAccessToken(),
    this.getAccessTokenExpiresAt(),
  ];

  return Promise.all(fns)
    .bind(this)
    .spread(function(accessToken, expiresAt) {
      var token = {
        accessToken: accessToken,
        accessTokenExpiresAt: expiresAt,
        scope: scope
      };

      return Promise.bind(this)
        .then(function() {
          return this.saveToken(user, client, scope);
        })
        .then(function(token) {
          var model = new TokenModel(token);
          var tokenType = this.getTokenType(model);
          token = tokenType.valueOf();

          var uri = url.parse(client.redirectUri, true);

          uri.hash = uri.hash || '#';

          var query = qs.parse(uri.hash.substr(1));

          query = _.extend(query, token);

          uri.hash = '#' + qs.stringify(query);

          uri.search = null;

          return { token: token, url: uri };
        });
    });
};

/**
 * Export constructor.
 */

module.exports = TokenResponseType;
