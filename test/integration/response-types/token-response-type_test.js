
/**
 * Module dependencies.
 */

var TokenResponseType = require('../../../lib/response-types/token-response-type');
var InvalidArgumentError = require('../../../lib/errors/invalid-argument-error');
var Promise = require('bluebird');
var should = require('should');
var url = require('url');

/**
 * Test `TokenResponseType` integration.
 */

describe('TokenResponseType integration', function() {
  describe('constructor()', function() {
    it('should throw an error if `model` is missing', function() {
      try {
        new TokenResponseType({});

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `model`');
      }
    });

    it('should throw an error if the model does not implement `saveToken()`', function() {
      try {
        new TokenResponseType({ model: { } });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: model does not implement `saveToken()`');
      }
    });
  });

  describe('generateAccessToken()', function() {
    it('should return an access token', function() {
      var model = {
        saveToken: function() {}
      };
      var handler = new TokenResponseType({ accessTokenLifetime: 123, model: model, refreshTokenLifetime: 456 });

      return handler.generateAccessToken()
        .then(function(data) {
          data.should.be.a.sha1;
        })
        .catch(should.fail);
    });

    it('should support promises', function() {
      var model = {
        generateAccessToken: function() {
          return Promise.resolve({});
        },
        saveToken: function() {}
      };
      var handler = new TokenResponseType({ accessTokenLifetime: 123, model: model, refreshTokenLifetime: 456 });

      handler.generateAccessToken().should.be.an.instanceOf(Promise);
    });

    it('should support non-promises', function() {
      var model = {
        generateAccessToken: function() {
          return {};
        },
        saveToken: function() {}
      };
      var handler = new TokenResponseType({ accessTokenLifetime: 123, model: model, refreshTokenLifetime: 456 });

      handler.generateAccessToken().should.be.an.instanceOf(Promise);
    });
  });

  describe('saveToken()', function() {
    it('should return a token', function() {
      var token = {};
      var model = {
        saveToken: function() { return token; }
      };
      var handler = new TokenResponseType({ model: model });

      return handler.saveToken()
        .then(function(data) {
          data.should.equal(token);
        })
        .catch(should.fail);
    });

    it('should support promises', function() {
      var token = {};
      var model = {
        saveToken: function() { return Promise.resolve(token); }
      };
      var handler = new TokenResponseType({ model: model });

      handler.saveToken().should.be.an.instanceOf(Promise);
    });

    it('should support non-promises', function() {
      var token = {};
      var model = {
        saveToken: function() { return token; }
      };
      var handler = new TokenResponseType({ model: model });

      handler.saveToken().should.be.an.instanceOf(Promise);
    });
  });

  describe('getAccessTokenExpiresAt()', function() {
    it('should return a date', function() {
      var model = {
        saveToken: function() {}
      };
      var handler = new TokenResponseType({ model: model });

      handler.getAccessTokenExpiresAt().should.be.an.instanceOf(Date);
    });
  });

  describe('saveToken()', function() {
    it('should return a token', function() {
      var token = { accessToken: 12345 };
      var model = {
        saveToken: function() {
          return token;
        }
      };
      var handler = new TokenResponseType({ model: model });

      return handler.saveToken()
        .then(function(data) {
          data.should.equal(token);
        })
        .catch(should.fail);
    });

    it('should support promises when calling `model.saveToken()`', function() {
      var model = {
        saveToken: function() {
          return {};
        }
      };
      var handler = new TokenResponseType({ model: model });

      handler.saveToken().should.be.an.instanceOf(Promise);
    });

    it('should support non-promises when calling `model.saveToken()`', function() {
      var model = {
        saveToken: function() {
          return { accessToken: 12345 };
        }
      };
      var handler = new TokenResponseType({ model: model });

      handler.saveToken().should.be.an.instanceOf(Promise);
    });
  });

  describe('buildRedirectUri()', function() {
    it('should throw an error if the `client` is missing', function() {
      var model = {
        saveToken: function() {}
      };
      var responseType = new TokenResponseType({ model: model });

      try {
        responseType.buildRedirectUri(null);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `client`');
      }
    });

    it('should throw an error if the `user` is missing', function() {
      var model = {
        saveToken: function() {}
      };
      var responseType = new TokenResponseType({ model: model });

      try {
        responseType.buildRedirectUri({ id: 1, redirectUri: 'http://example.com/cb?foo=bar' });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `user`');
      }
    });

    it('should return the new redirect uri and set the `code` and `state` in the query', function() {
      var model = {
        saveToken: function() { return { accessToken: 'foo', client: {}, user: {} }; }
      };
      var responseType = new TokenResponseType({ accessTokenLifetime: 0, model: model });

      return responseType.buildRedirectUri({ id: 1, redirectUri: 'http://example.com/cb?foo=bar' }, { id: 2 })
        .then(function(redirect) {
          url.format(redirect.url).should.equal('http://example.com/cb?foo=bar#access_token=foo&token_type=bearer');
        });
    });
  });
});
