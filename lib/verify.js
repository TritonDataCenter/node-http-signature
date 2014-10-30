// Copyright 2011 Joyent, Inc.  All rights reserved.

var assert = require('assert-plus');
var crypto = require('crypto');
var nacl = require('tweetnacl');


///--- Exported API

module.exports = {

  /**
   * Simply wraps up the node crypto operations for you, and returns
   * true or false.  You are expected to pass in an object that was
   * returned from `parse()`.
   *
   * @param {Object} parsedSignature the object you got from `parse`.
   * @param {String} key either an RSA private key PEM, HMAC secret, or base64-encoded Ed25519 key.
   * @return {Boolean} true if valid, false otherwise.
   * @throws {TypeError} if you pass in bad arguments.
   */
  verifySignature: function verifySignature(parsedSignature, key) {
    assert.object(parsedSignature, 'parsedSignature');
    assert.string(key, 'key');

    var alg = parsedSignature.algorithm.match(/(HMAC|RSA|DSA|ED25519)-(\w+)/);
    if (!alg || alg.length !== 3)
      throw new TypeError('parsedSignature: unsupported algorithm ' +
                          parsedSignature.algorithm);

    if (alg[1] === 'HMAC') {
      var hmac = crypto.createHmac(alg[2].toUpperCase(), key);
      hmac.update(parsedSignature.signingString);
      return (hmac.digest('base64') === parsedSignature.params.signature);
    } else if (alg[1] === 'RSA' || alg[1] === 'DSA') {
      var verify = crypto.createVerify(alg[0]);
      verify.update(parsedSignature.signingString);
      return verify.verify(key, parsedSignature.params.signature, 'base64');
    } else if (alg[1] === 'ED25519') {
      var message = nacl.util.decodeUTF8(parsedSignature.signingString);
      var keyDecoded = nacl.util.decodeBase64(key);
      var signatureDecoded = nacl.util.decodeBase64(parsedSignature.params.signature);
      return nacl.sign.detached.verify(message, signatureDecoded, keyDecoded);
    }
  }

};
