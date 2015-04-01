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
   * @param {String} keyType the type of key `rsa`, `dsa` or `hmac`, optional
   * @return {Boolean} true if valid, false otherwise.
   * @throws {TypeError} if you pass in bad arguments or sig algo doesn't match
   */
  verifySignature: function verifySignature(parsedSignature, key, keyType) {
    assert.object(parsedSignature, 'parsedSignature');
    assert.string(key, 'key');
    if (!keyType) {
      var m = key.match(/^-*BEGIN (RSA |DSA )?PUBLIC KEY-*/);
      if (m && m.length == 2 && m[1])
        keyType = m[1];
      else if (m && m.length == 2)
        keyType = 'rsa';
      else
        keyType = 'hmac';
    }

    var alg = parsedSignature.algorithm.match(/(HMAC|RSA|DSA)-(\w+)/);
    if (!alg || alg.length !== 3)
      throw new TypeError('parsedSignature: unsupported algorithm ' +
                          parsedSignature.algorithm);

    if (alg[1] !== keyType.toUpperCase())
      throw new TypeError('key type does not match signature algorithm ' +
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
  }

};
