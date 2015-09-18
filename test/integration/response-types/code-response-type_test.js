
/**
 * Module dependencies.
 */

var CodeResponseType = require('../../../lib/response-types/code-response-type');
var InvalidArgumentError = require('../../../lib/errors/invalid-argument-error');
var Promise = require('bluebird');
var should = require('should');
var url = require('url');

/**
 * Test `CodeResponseType` integration.
 */

describe('CodeResponseType integration', function() {
  describe('constructor()', function() {
    it('should throw an error if `options.authorizationCodeLifetime` is missing', function() {
      try {
        new CodeResponseType();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `authorizationCodeLifetime`');
      }
    });

    it('should throw an error if `model` is missing', function() {
      try {
        new CodeResponseType({ authorizationCodeLifetime: 120 });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Missing parameter: `model`');
      }
    });

    it('should throw an error if the model does not implement `saveAuthorizationCode()`', function() {
      try {
        new CodeResponseType({ authorizationCodeLifetime: 120, model: { } });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: model does not implement `saveAuthorizationCode()`');
      }
    });
  });

  describe('generateAuthorizationCode()', function() {
    it('should return an auth code', function() {
      var model = {
        saveAuthorizationCode: function() { return { authorizationCode: 12345 }; }
      };
      var handler = new CodeResponseType({ authorizationCodeLifetime: 120, model: model });

      return handler.generateAuthorizationCode()
        .then(function(data) {
          data.should.be.a.sha1;
        })
        .catch(should.fail);
    });

    it('should support promises', function() {
      var model = {
        saveAuthorizationCode: function() {},
        generateAuthorizationCode: function() { return Promise.resolve('foo'); }
      };
      var handler = new CodeResponseType({ authorizationCodeLifetime: 120, model: model });

      handler.generateAuthorizationCode().should.be.an.instanceOf(Promise);
    });

    it('should support non-promises', function() {
      var model = {
        saveAuthorizationCode: function() {},
        generateAuthorizationCode: function() { return 'foo'; }
      };
      var handler = new CodeResponseType({ authorizationCodeLifetime: 120, model: model });

      handler.generateAuthorizationCode().should.be.an.instanceOf(Promise);
    });
  });

  describe('getAuthorizationCodeLifetime()', function() {
    it('should return a date', function() {
      var model = {
        saveAuthorizationCode: function() {}
      };
      var handler = new CodeResponseType({ authorizationCodeLifetime: 120, model: model });

      handler.getAuthorizationCodeLifetime().should.be.an.instanceOf(Date);
    });
  });

  describe('saveAuthorizationCode()', function() {
    it('should return an auth code', function() {
      var authorizationCode = { authorizationCode: 12345 };
      var model = {
        saveAuthorizationCode: function() {
          return authorizationCode;
        }
      };
      var handler = new CodeResponseType({ authorizationCodeLifetime: 120, model: model });

      return handler.saveAuthorizationCode('foo', 'bar', 'biz', 'baz')
        .then(function(data) {
          data.should.equal(authorizationCode);
        })
        .catch(should.fail);
    });

    it('should support promises when calling `model.saveAuthorizationCode()`', function() {
      var model = {
        saveAuthorizationCode: function() {
          return {};
        }
      };
      var handler = new CodeResponseType({ authorizationCodeLifetime: 120, model: model });

      handler.saveAuthorizationCode('foo', 'bar', 'biz', 'baz').should.be.an.instanceOf(Promise);
    });

    it('should support non-promises when calling `model.saveAuthorizationCode()`', function() {
      var model = {
        saveAuthorizationCode: function() {
          return { authorizationCode: 12345 };
        }
      };
      var handler = new CodeResponseType({ authorizationCodeLifetime: 120, model: model });

      handler.saveAuthorizationCode('foo', 'bar', 'biz', 'baz').should.be.an.instanceOf(Promise);
    });
  });

  describe('buildRedirectUri()', function() {
    it('should throw an error if the `client` is missing', function() {
      var model = {
        saveAuthorizationCode: function() {}
      };
      var responseType = new CodeResponseType({ authorizationCodeLifetime: 120, model: model });

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
        saveAuthorizationCode: function() {}
      };
      var responseType = new CodeResponseType({ authorizationCodeLifetime: 120, model: model });

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
        saveAuthorizationCode: function(data) { return data; },
        generateAuthorizationCode: function() { return 'foo'; }
      };
      var responseType = new CodeResponseType({ authorizationCodeLifetime: 120, model: model });

      return responseType.buildRedirectUri({ id: 1, redirectUri: 'http://example.com/cb?foo=bar' },{ id: 2 })
        .then(function(redirect) {
          url.format(redirect.url).should.equal('http://example.com/cb?foo=bar&code=foo');
        });
    });
  });
});
