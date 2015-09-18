
/**
 * Module dependencies.
 */

var AuthorizeHandler = require('../../../lib/handlers/authorize-handler');
var Request = require('../../../lib/request');
var sinon = require('sinon');
var should = require('should');

/**
 * Test `AuthorizeHandler`.
 */

describe('AuthorizeHandler', function() {
  describe('getClient()', function() {
    it('should call `model.getClient()`', function() {
      var model = {
        getAccessToken: function() {},
        getClient: sinon.stub().returns({ grants: ['authorization_code'], redirectUri: 'http://example.com/cb' }),
        saveAuthorizationCode: function() {},
        saveToken: function() {},
        validateScope: function() { return true; },
        authorizationAllowed: function() { return true; }
      };
      var handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model: model });
      var request = new Request({ body: { client_id: 12345, client_secret: 'secret' }, headers: {}, method: {}, query: {} });

      return handler.getClient(request)
        .then(function() {
          model.getClient.callCount.should.equal(1);
          model.getClient.firstCall.args.should.have.length(1);
          model.getClient.firstCall.args[0].should.equal(12345);
        })
        .catch(should.fail);
    });
  });
});
