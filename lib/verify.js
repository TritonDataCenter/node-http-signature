// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var crypto = require('crypto');



///--- Exported API

module.exports = {
  /**
   * Verify RSA/DSA signature against public key.  You are expected to pass in
   * an object that was returned from `parse()`.
   *
   * @param {Object} parsedSignature the object you got from `parse`.
   * @param {String} pubkey RSA/DSA private key PEM.
   * @return {Boolean} true if valid, false otherwise.
   * @throws {TypeError} if you pass in bad arguments.
   */
  verifySignature: function verifySignature(parsedSignature, pubkey) {
    assert.object(parsedSignature, 'parsedSignature');
    assert.string(pubkey, 'pubkey');

    var alg = parsedSignature.algorithm.match(/^(RSA|DSA)-(\w+)/);
    if (!alg || alg.length !== 3)
      throw new TypeError('parsedSignature: unsupported algorithm ' +
                          parsedSignature.algorithm);

    var verify = crypto.createVerify(alg[0]);
    verify.update(parsedSignature.signingString);
    return verify.verify(pubkey, parsedSignature.params.signature, 'base64');
  },

  /**
   * Verify HMAC against shared secret.  You are expected to pass in an object
   * that was returned from `parse()`.
   *
   * @param {Object} parsedSignature the object you got from `parse`.
   * @param {String} secret HMAC shared secret.
   * @return {Boolean} true if valid, false otherwise.
   * @throws {TypeError} if you pass in bad arguments.
   */
  verifyHMAC: function verifyHMAC(parsedSignature, secret) {
    assert.object(parsedSignature, 'parsedHMAC');
    assert.string(secret, 'secret');

    var alg = parsedSignature.algorithm.match(/^HMAC-(\w+)/);
    if (!alg || alg.length !== 2)
      throw new TypeError('parsedSignature: unsupported algorithm ' +
                          parsedSignature.algorithm);
    var hashAlg = alg[1].toUpperCase();

    var hmac = crypto.createHmac(hashAlg, secret);
    hmac.update(parsedSignature.signingString);

    /*
     * Now double-hash to avoid leaking timing information - there's
     * no easy constant-time compare in JS, so we use this approach
     * instead. See for more info:
     * https://www.isecpartners.com/blog/2011/february/double-hmac-
     * verification.aspx
     */
    var h1 = crypto.createHmac(hashAlg, secret);
    h1.update(hmac.digest());
    var h2 = crypto.createHmac(hashAlg, secret);
    h2.update(new Buffer(parsedSignature.params.signature, 'base64'));

    return (h1.digest().equals(h2.digest()));
  }
};
