// Copyright 2011 Joyent, Inc.  All rights reserved.

var crypto = require('crypto');

var asn1 = require('asn1');
var ctype = require('ctype');



///--- Globals


var RSA_ENC_HDR = [0x30, 0x0d,
                   0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
                   0x01, 0x01, 0x05, 0x00];



///--- Helpers

function readNext(buffer, offset) {
  var len = ctype.ruint32(buffer, 'big', offset);
  offset += 4;

  var newOffset = offset + len;

  return {
    data: buffer.slice(offset, newOffset),
    offset: newOffset
  };
}


function writeInt(writer, buffer) {
  writer.writeByte(0x02); // ASN1.Integer
  writer.writeLength(buffer.length);

  for (var i = 0; i < buffer.length; i++)
    writer.writeByte(buffer[i]);

  return writer;
}




///--- API

module.exports = {

  /**
   * Converts an OpenSSH public key (rsa only) to a PKCS#8 PEM file.
   *
   * The intent of this module is to interoperate with OpenSSL only,
   * specifically the node crypto module's `verify` method.
   *
   * @param {String} key an OpenSSH public key.
   * @return {String} PEM encoded form of the RSA public key.
   * @throws {TypeError} on bad input.
   * @throws {Error} on invalid ssh key formatted data.
   */
  sshKeyToPEM: function(key) {
    if (!key || typeof(key) !== 'string')
      throw new TypeError('ssh_key (string) required');

    var buffer;
    var der;
    var exponent;
    var i;
    var modulus;
    var newKey = '';
    var offset = 0;
    var type;
    var tmp;

    try {
      buffer = new Buffer(key.split(' ')[1], 'base64');

      tmp = readNext(buffer, offset);
      type = tmp.data.toString();
      offset = tmp.offset;

      if (type !== 'ssh-rsa')
        throw new Error('Invalid ssh key type: ' + type);

      tmp = readNext(buffer, offset);
      exponent = tmp.data;
      offset = tmp.offset;

      tmp = readNext(buffer, offset);
      modulus = tmp.data;
    } catch (e) {
      throw new Error('Invalid ssh key: ' + key);
    }

    // DER is a subset of BER
    der = new asn1.BerWriter();

    der.startSequence(0x30);

    RSA_ENC_HDR.forEach(function(b) {
      der.writeByte(b);
    });

    der.startSequence(0x03); // bit string
    der.writeByte(0x00);

    // Now the actual key
    der.startSequence(0x30);
    writeInt(der, modulus);
    writeInt(der, exponent);
    der.endSequence();

    der.endSequence();
    der.endSequence();

    tmp = der.buffer.toString('base64');
    for (i = 0; i < tmp.length; i++) {
      if ((i % 64) === 0)
        newKey += '\n';
      newKey += tmp.charAt(i);
    }

    if (!/\\n$/.test(newKey))
      newKey += '\n';

    return '-----BEGIN PUBLIC KEY-----' + newKey + '-----END PUBLIC KEY-----\n';
  },


  /**
   * Generates an OpenSSH fingerprint from an ssh public key.
   *
   * @param {String} key an OpenSSH public key.
   * @return {String} key fingerprint.
   * @throws {TypeError} on bad input.
   * @throws {Error} if what you passed doesn't look like an ssh public key.
   */
  fingerprint: function(key) {
    if (!key || typeof(key) !== 'string')
      throw new TypeError('ssh_key (string) required');

    var pieces = key.split(' ');
    if (!pieces || !pieces.length || pieces.length < 2)
      throw new Error('invalid ssh key');

    var data = new Buffer(pieces[1], 'base64');

    var hash = crypto.createHash('md5');
    hash.update(data);
    var digest = hash.digest('hex');

    var fp = '';
    for (var i = 0; i < digest.length; i++) {
      if (i && i % 2 === 0)
        fp += ':';

      fp += digest[i];
    }

    return fp;
  }


};
