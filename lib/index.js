// Copyright 2011 Joyent, Inc.  All rights reserved.

var parser = require('./parser');
var signer = require('./signer');
var verify = require('./verify');



///--- Exported API

module.exports = {

  parse: parser.parseRequest,
  parseRequest: parser.parseRequest,

  sign: signer.signRequest,
  signRequest: signer.signRequest,

  verify: verify.verifySignature,
  verifySignature: verify.verifySignature

};
