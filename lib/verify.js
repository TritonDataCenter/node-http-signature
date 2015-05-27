// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var crypto = require('crypto');



///--- Exported API

module.exports = {
  /**
   * Simply wraps up the node crypto operations for you, and returns
   * true or false.  You are expected to pass in an object that was
   * returned from `parse()`.
   *
   * @param {Object} parsedSignature the object you got from `parse`.
   * @param {String} key either an RSA private key PEM or HMAC secret.
   * @return {Boolean} true if valid, false otherwise.
   * @throws {TypeError} if you pass in bad arguments.
   */
  verifySignature: function verifySignature(parsedSignature, key) {
    assert.object(parsedSignature, 'parsedSignature');
    assert.string(key, 'key');

    var alg = parsedSignature.algorithm.match(/(HMAC|RSA|DSA)-(\w+)/);
    if (!alg || alg.length !== 3)
      throw new TypeError('parsedSignature: unsupported algorithm ' +
                          parsedSignature.algorithm);

    if (alg[1] === 'HMAC') {
      var hmac = crypto.createHmac(alg[2].toUpperCase(), key);
      hmac.update(parsedSignature.signingString);
      return (hmac.digest('base64') === parsedSignature.params.signature);
    } else {
      var verify = crypto.createVerify(alg[0]);
      verify.update(parsedSignature.signingString);
      return verify.verify(key, parsedSignature.params.signature, 'base64');
    }
  },
  
  /**
   * Verify HMAC against shared secret.  You are expected to pass in an object
   * that was returned from `parse()`.
   *
   * Note: this is simply a wrapper for backwards compatibility as both
   * RSA/DSA and HMAC signatures are now handled by verifySignature to
   * avoid other parts of the code having to care about the difference.
   * This should be removed if it isn't needed.
   *
   * @param {Object} parsedSignature the object you got from `parse`.
   * @param {String} secret HMAC shared secret.
   * @return {Boolean} true if valid, false otherwise.
   * @throws {TypeError} if you pass in bad arguments.
   */
  verifyHMAC: function verifyHMAC(parsedSignature, secret) {
    return this.verifySignature(parsedSignature, secret);
  }
};
