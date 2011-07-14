// Copyright 2011 Joyent, Inc.  All rights reserved.

var crypto = require('crypto');
var fs = require('fs');
var http = require('http');

var httpu = require('httpu');
var uuid = require('node-uuid');

var httpSignature = require('../lib/index');



///--- Globals

var hmacKey = null;
var httpOptions = null;
var rsaPrivate = null;
var signOptions = null;



///--- Tests

exports.setUp = function(test, assert) {
  rsaPrivate = fs.readFileSync(__dirname + '/rsa_private.pem', 'ascii');
  assert.ok(rsaPrivate);

  hmacKey = uuid();
  httpOptions = {
    socketPath: uuid(),
    path: '/',
    method: 'GET',
    headers: {}
  };

  signOptions = {
    key: rsaPrivate,
    keyId: 'unitTest'
  };

  test.finish();
};


exports.test_defaults = function(test, assert) {
  var req = httpu.request(httpOptions, function(res) {});
  assert.ok(httpSignature.sign(req, signOptions));
  assert.ok(req.getHeader('Authorization'));
  console.log('> ' + req.getHeader('Authorization'));
  test.finish();
};


exports.test_request_line = function(test, assert) {
  var req = httpu.request(httpOptions, function(res) {});
  var opts = {
    keyId: 'unit',
    key: rsaPrivate,
    headers: ['date', 'request-line']
  };

  assert.ok(httpSignature.sign(req, opts));
  assert.ok(req.getHeader('Authorization'));
  console.log('> ' + req.getHeader('Authorization'));
  test.finish();
};


exports.test_hmac = function(test, assert) {
  var req = httpu.request(httpOptions, function(res) {});
  var opts = {
    keyId: 'unit',
    key: uuid(),
    algorithm: 'hmac-sha1'
  };

  assert.ok(httpSignature.sign(req, opts));
  assert.ok(req.getHeader('Authorization'));
  console.log('> ' + req.getHeader('Authorization'));
  test.finish();
};


exports.tearDown = function(test, assert) {
  test.finish();
};
