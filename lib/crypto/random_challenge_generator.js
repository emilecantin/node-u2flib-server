var crypto = require('crypto');

exports.generateChallenge = function(cb) {
  return crypto.randomBytes(32).toString('base64');
};
