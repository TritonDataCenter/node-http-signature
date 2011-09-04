// Copyright 2011 Joyent, Inc.  All rights reserved.

var crypto = require('crypto');
var fs = require('fs');
var http = require('http');

var httpu = require('httpu');
var test = require('tap').test;
var uuid = require('node-uuid');

var httpSignature = require('../lib/index');



///--- Globals

var hmacKey = null;
var options = null;
var rsaPrivate = null;
var rsaPublic = null;
var server = null;
var socket = null;



// --- Helpers

function _pad(val) {
  if (parseInt(val, 10) < 10) {
    val = '0' + val;
  }
  return val;
}


function _rfc1123(date) {
  if (!date) date = new Date();

  var months = ['Jan',
                'Feb',
                'Mar',
                'Apr',
                'May',
                'Jun',
                'Jul',
                'Aug',
                'Sep',
                'Oct',
                'Nov',
                'Dec'];
  var days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  return days[date.getUTCDay()] + ', ' +
    _pad(date.getUTCDate()) + ' ' +
    months[date.getUTCMonth()] + ' ' +
    date.getUTCFullYear() + ' ' +
    _pad(date.getUTCHours()) + ':' +
    _pad(date.getUTCMinutes()) + ':' +
    _pad(date.getUTCSeconds()) +
    ' GMT';
}



///--- Tests

test('setup', function(t) {
  rsaPrivate = fs.readFileSync(__dirname + '/rsa_private.pem', 'ascii');
  rsaPublic = fs.readFileSync(__dirname + '/rsa_public.pem', 'ascii');
  t.ok(rsaPrivate);
  t.ok(rsaPublic);

  hmacKey = uuid();
  socket = '/tmp/.' + uuid();
  options = {
    socketPath: socket,
    path: '/',
    headers: {}
  };

  server = http.createServer(function(req, res) {
    server.tester(req, res);
  });

  server.listen(socket, function() {
    t.end();
  });
});


test('invalid hmac', function(t) {
  server.tester = function(req, res) {
    var parsed = httpSignature.parseRequest(req);
    t.ok(!httpSignature.verify(parsed, hmacKey));

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.headers.Date = _rfc1123();
  options.headers.Authorization =
    'Signature keyId="foo",algorithm="hmac-sha1" ' +
    uuid();

  httpu.get(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
});


test('valid hmac', function(t) {
  server.tester = function(req, res) {
    var parsed = httpSignature.parseRequest(req);
    t.ok(httpSignature.verify(parsed, hmacKey));

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.headers.Date = _rfc1123();
  var hmac = crypto.createHmac('sha1', hmacKey);
  hmac.update(options.headers.Date);
  options.headers.Authorization =
    'Signature keyId="foo",algorithm="hmac-sha1" ' +
    hmac.digest('base64');

  httpu.get(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
});


test('invalid rsa', function(t) {
  server.tester = function(req, res) {
    var parsed = httpSignature.parseRequest(req);
    t.ok(!httpSignature.verify(parsed, rsaPublic));

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.headers.Date = _rfc1123();
  options.headers.Authorization =
    'Signature keyId="foo",algorithm="rsa-sha1" ' +
    uuid();

  httpu.get(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
});


test('valid rsa', function(t) {
  server.tester = function(req, res) {
    var parsed = httpSignature.parseRequest(req);
    t.ok(httpSignature.verify(parsed, rsaPublic));

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.headers.Date = _rfc1123();
  var signer = crypto.createSign('RSA-SHA256');
  signer.update(options.headers.Date);
  options.headers.Authorization =
    'Signature keyId="foo",algorithm="rsa-sha256" ' +
    signer.sign(rsaPrivate, 'base64');

  httpu.get(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
});


test('tear down', function(t) {
  server.on('close', function() {
    t.end();
  });
  server.close();
});
