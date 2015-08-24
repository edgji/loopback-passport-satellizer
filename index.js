var jwt = require('jsonwebtoken');
var extend = require('util')._extend;

module.exports = {

  // replace the default login callback with a simple pass-through function
  loginCallback: function(req, done) {

    return function(err, user, identity, payload) {
      done(err, user, payload);
    };
  },

  createTokenPayload: function(name, options) {

    return function(user, ttl, cb) {
      if (arguments.length === 2 && typeof ttl === 'function') {
        cb = ttl;
        ttl = 0;
      }
      var payload = {
        sub: user.id,
        iat: Date.now(), // issued at time
        exp: Date.now() + 10000 // expiration time
      };
      cb(null, payload);
    }
  },

  customCallback: function(name, options) {

    return function(req, res, next) {

      // need to pass along posted parameters from satellizer
      if (typeof req.body !== 'undefined') {
        req.query = extend(req.query, req.body);
      }

      // The satellizer callback
      passport.authenticate(name, extend({
          session: false,
          callbackURL: req.body.redirectUri || options.callbackURL
        }, options.authOptions),
        function (err, user, payload) {
          if (err) {
            return next(err);
          }
          if (!user) {
            return res.status(401).json('authentication error');
          }
          if (payload) {
            var token = jwt.sign(payload, options.secretOrPrivateKey || '');
            return res.json({ token: token });
          }
        })(req, res, next);
    };
  }
}
