// Copyright 2011 Joyent, Inc.  All rights reserved.

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
      var alg2 = alg[2].toUpperCase();
      var hmac = crypto.createHmac(alg2, key);
      hmac.update(parsedSignature.signingString);

      // Compare hmac.digest('base64') with parsedSignature.params.signature in
      // constant time. Double hmac verification is the preferred way to do this
      // since we can't predict optimizations performed by the runtime.
      // https://www.isecpartners.com/blog/2011/february/double-hmac-verification.aspx
      var h1 = crypto.createHmac(alg2, key);
      h1.update(hmac.digest('base64'));
      var h2 = crypto.createHmac(alg2, key);
      h2.update(parsedSignature.params.signature);
      return h1.digest('base64') === h2.digest('base64');
    } else {
      var verify = crypto.createVerify(alg[0]);
      verify.update(parsedSignature.signingString);
      return verify.verify(key, parsedSignature.params.signature, 'base64');
    }
  }

};
