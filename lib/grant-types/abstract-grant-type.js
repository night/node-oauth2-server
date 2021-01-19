
/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var Promise = require('bluebird');
var is = require('../validator/is');
var tokenUtil = require('../utils/token-util');

/**
 * Constructor.
 */

function AbstractGrantType(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  this.accessTokenLifetime = options.accessTokenLifetime || 0;
  this.refreshTokenLifetime = options.refreshTokenLifetime || 0;
  this.model = options.model;
}

/**
 * Generate access token.
 */

AbstractGrantType.prototype.generateAccessToken = function() {
  if (this.model.generateAccessToken) {
    return Promise.try(() => this.model.generateAccessToken());
  }

  return tokenUtil.generateRandomToken();
};

/**
 * Generate refresh token.
 */

AbstractGrantType.prototype.generateRefreshToken = function() {
  if (this.model.generateRefreshToken) {
    return Promise.try(() => this.model.generateRefreshToken());
  }

  return tokenUtil.generateRandomToken();
};

/**
 * Get access token expiration date.
 */

AbstractGrantType.prototype.getAccessTokenExpiresAt = function() {
  return new Date(this.accessTokenLifetime === 0 ? 0 : Date.now() + this.accessTokenLifetime * 1000);
};

/**
 * Get refresh token expiration date.
 */

AbstractGrantType.prototype.getRefreshTokenExpiresAt = function() {
  return new Date(this.refreshTokenLifetime === 0 ? 0 : Date.now() + this.refreshTokenLifetime * 1000);
};

/**
 * Get scope from the request body.
 */

AbstractGrantType.prototype.getScope = function(request) {
  if (!is.nqschar(request.body.scope)) {
    throw new InvalidArgumentError('Invalid parameter: `scope`');
  }

  return request.body.scope;
};

/**
 * Export constructor.
 */

module.exports = AbstractGrantType;
