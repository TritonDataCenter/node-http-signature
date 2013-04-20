// Copyright 2011 Joyent, Inc.  All rights reserved.

var crypto = require('crypto');
var fs = require('fs');
var http = require('http');

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

  http.get(options, function(res) {
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
  hmac.update('date: ' + options.headers.Date);
  options.headers.Authorization =
    'Signature keyId="foo",algorithm="hmac-sha1" ' +
    hmac.digest('base64');

  http.get(options, function(res) {
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

  http.get(options, function(res) {
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
  signer.update('date: ' + options.headers.Date);
  options.headers.Authorization =
    'Signature keyId="foo",algorithm="rsa-sha256" ' +
    signer.sign(rsaPrivate, 'base64');

  http.get(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
});


// test values from spec for defaults
test('valid rsa from spec default', function(t) {
  server.tester = function(req, res) {
    console.log('> [DEFAULT]', req.headers.authorization);
    var parsed = httpSignature.parseRequest(req);
    t.ok(httpSignature.verify(parsed, rsaPublic));

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.method = 'POST';
  options.path = '/foo?param=value&pet=dog';
  options.headers.host = 'example.com';
  options.headers.Date = _rfc1123();
  options.headers['content-type'] = 'application/json';
  options.headers['content-md5'] = 'Sd/dVLAcvNLSq16eXua5uQ==';
  options.headers['content-length'] = '18';
  var signer = crypto.createSign('RSA-SHA256');
  signer.update('date: ' + options.headers.Date);
  options.headers.Authorization =
    'Signature keyId="Test",algorithm="rsa-sha256"' +
    ' ' + signer.sign(rsaPrivate, 'base64');

  var req = http.request(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
  req.write('{"hello": "world"}');
  req.end();
});

// test values from spec for all headers
test('valid rsa from spec all headers', function(t) {
  server.tester = function(req, res) {
    console.log('> [ALL]', req.headers.authorization);
    var parsed = httpSignature.parseRequest(req);
    t.ok(httpSignature.verify(parsed, rsaPublic));

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.method = 'POST';
  options.path = '/foo?param=value&pet=dog';
  options.headers.host = 'example.com';
  options.headers.Date = _rfc1123();
  options.headers['content-type'] = 'application/json';
  options.headers['content-md5'] = 'Sd/dVLAcvNLSq16eXua5uQ==';
  options.headers['content-length'] = '18';
  var signer = crypto.createSign('RSA-SHA256');
  signer.update(options.method + ' ' + options.path + ' HTTP/1.1\n');
  signer.update('host: ' + options.headers.host + '\n');
  signer.update('date: ' + options.headers.Date + '\n');
  signer.update('content-type: ' + options.headers['content-type'] + '\n');
  signer.update('content-md5: ' + options.headers['content-md5'] + '\n');
  signer.update('content-length: ' + options.headers['content-length']);
  options.headers.Authorization =
    'Signature keyId="Test",algorithm="rsa-sha256",headers=' +
    '"request-line host date content-type content-md5 content-length"' +
    ' ' + signer.sign(rsaPrivate, 'base64');

  var req = http.request(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
  req.write('{"hello": "world"}');
  req.end();
});


test('tear down', function(t) {
  server.on('close', function() {
    t.end();
  });
  server.close();
});
