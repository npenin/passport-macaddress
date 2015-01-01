/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , arp = require('node-arp')

/**
 * `Strategy` constructor.
 * Examples:
 *
 *     passport.use(new MacStrategy(
 *       function(hash, done) {
 *         User.findOne({ hash: hash }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('mac authentication strategy requires a verify function');
  
  passport.Strategy.call(this);
  this.name = 'mac';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a hash link.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
    var self=this;
    arp.getMAC(req.socket.remoteAddress, function(err, mac){
		var verified=function(err, user, info) {
			if (err) { return self.error(err); }
			if (!user) { return self.fail(info); }
			self.success(user, info);
		};
		  
        if(err)
        {
			//probably the local computer itself.
            self.success('computer');
			
            // self.fail({name:'unknown mac', message:mac});
        }
        else
        {
            if (self._passReqToCallback) {
                this._verify(req, mac, verified);
            } else {
                this._verify(mac, verified);
            }
        }
    });
};


/**
 * Expose `Strategy`.
 */ 
exports.Strategy = Strategy; 