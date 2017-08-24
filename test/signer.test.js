// Copyright 2011 Joyent, Inc.  All rights reserved.

var crypto = require('crypto');
var fs = require('fs');
var http = require('http');
var sshpk = require('sshpk');

var test = require('tap').test;
var uuid = require('uuid');

var httpSignature = require('../lib/index');



///--- Globals

var hmacKey = null;
var httpOptions = null;
var rsaPrivate = null;
var dsaPrivate = null;
var ecdsaPrivate = null;
var signOptions = null;
var server = null;
var socket = null;



///--- Tests


test('setup', function(t) {
  rsaPrivate = fs.readFileSync(__dirname + '/rsa_private.pem', 'ascii');
  dsaPrivate = fs.readFileSync(__dirname + '/dsa_private.pem', 'ascii');
  ecdsaPrivate = fs.readFileSync(__dirname + '/ecdsa_private.pem', 'ascii');
  t.ok(rsaPrivate);
  t.ok(dsaPrivate);
  t.ok(ecdsaPrivate);

  socket = '/tmp/.' + uuid();

  server = http.createServer(function(req, res) {
    res.writeHead(200);
    res.end();
  });

  server.listen(socket, function() {
    hmacKey = uuid();
    httpOptions = {
      socketPath: socket,
      path: '/',
      method: 'GET',
      headers: {}
    };

    signOptions = {
      key: rsaPrivate,
      keyId: 'unitTest'
    };

    t.end();
  });
});


test('defaults', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  req._stringToSign = null;
  t.ok(httpSignature.sign(req, signOptions));
  var authz = req.getHeader('Authorization');
  t.ok(authz);

  t.strictEqual(typeof (req._stringToSign), 'string');
  t.ok(req._stringToSign.match(/^date: [^\n]*$/));

  var key = sshpk.parsePrivateKey(rsaPrivate);
  var sig = key.createSign().update(req._stringToSign).sign();
  t.ok(authz.indexOf(sig.toString()) !== -1);

  console.log('> ' + authz);
  req.end();
});

test('with custom authorizationHeaderName', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  req._stringToSign = null;
  var opts = Object.create(signOptions);
  opts.authorizationHeaderName = 'x-auths';
  t.ok(httpSignature.sign(req, opts));
  var authz = req.getHeader('x-auths');
  t.ok(authz);

  t.strictEqual(typeof (req._stringToSign), 'string');
  t.ok(req._stringToSign.match(/^date: [^\n]*$/));

  var key = sshpk.parsePrivateKey(rsaPrivate);
  var sig = key.createSign().update(req._stringToSign).sign();
  t.ok(authz.indexOf(sig.toString()) !== -1);

  console.log('> ' + authz);
  req.end();
});


test('request line strict unspecified', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
    keyId: 'unit',
    key: rsaPrivate,
    headers: ['date', 'request-line']
  };

  req._stringToSign = null;
  t.ok(httpSignature.sign(req, opts));
  t.ok(req.getHeader('Authorization'));
  t.strictEqual(typeof (req._stringToSign), 'string');
  t.ok(req._stringToSign.match(/^date: [^\n]*\nGET \/ HTTP\/1.1$/));

  console.log('> ' + req.getHeader('Authorization'));
  req.end();
});

test('request line strict false', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
    keyId: 'unit',
    key: rsaPrivate,
    headers: ['date', 'request-line'],
    strict: false
  };

  t.ok(httpSignature.sign(req, opts));
  t.ok(req.getHeader('Authorization'));
  t.ok(!req.hasOwnProperty('_stringToSign'));
  t.ok(req._stringToSign === undefined);
  console.log('> ' + req.getHeader('Authorization'));
  req.end();
});

test('request line strict true', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
    keyId: 'unit',
    key: rsaPrivate,
    headers: ['date', 'request-line'],
    strict: true
  };

  t.throws(function() {
     httpSignature.sign(req, opts)
   });
  req.end();
});

test('request target', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
    keyId: 'unit',
    key: rsaPrivate,
    headers: ['date', '(request-target)']
  };

  req._stringToSign = null;
  t.ok(httpSignature.sign(req, opts));
  t.ok(req.getHeader('Authorization'));
  t.strictEqual(typeof (req._stringToSign), 'string');
  t.ok(req._stringToSign.match(/^date: [^\n]*\n\(request-target\): get \/$/));
  console.log('> ' + req.getHeader('Authorization'));
  req.end();
});

test('request-target with dsa key', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
    keyId: 'unit',
    key: dsaPrivate,
    headers: ['date', '(request-target)']
  };

  t.ok(httpSignature.sign(req, opts));
  t.ok(req.getHeader('Authorization'));
  console.log('> ' + req.getHeader('Authorization'));
  req.end();
});

test('request-target with ecdsa key', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
    keyId: 'unit',
    key: ecdsaPrivate,
    headers: ['date', '(request-target)']
  };

  t.ok(httpSignature.sign(req, opts));
  t.ok(req.getHeader('Authorization'));
  console.log('> ' + req.getHeader('Authorization'));
  req.end();
});

test('hmac', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
    keyId: 'unit',
    key: uuid(),
    algorithm: 'hmac-sha1'
  };

  t.ok(httpSignature.sign(req, opts));
  t.ok(req.getHeader('Authorization'));
  console.log('> ' + req.getHeader('Authorization'));
  req.end();
});

test('createSigner with RSA key', function(t) {
  var s = httpSignature.createSigner({
    keyId: 'foo',
    key: rsaPrivate,
    algorithm: 'rsa-sha1'
  });
  s.writeTarget('get', '/');
  var date = s.writeDateHeader();
  s.sign(function (err, authz) {
    t.error(err);
    console.log('> ' + authz);
    var req = http.request(httpOptions, function(res) {
      t.end();
    });
    req.setHeader('date', date);
    req.setHeader('authorization', authz);
    req.end();
  });
});

test('createSigner with RSA key, auto algo', function(t) {
  var s = httpSignature.createSigner({
    keyId: 'foo',
    key: rsaPrivate
  });
  s.writeTarget('get', '/');
  var date = s.writeDateHeader();
  s.sign(function (err, authz) {
    t.error(err);
    var req = http.request(httpOptions, function(res) {
      t.end();
    });
    req.setHeader('date', date);
    req.setHeader('authorization', authz);
    req.end();
  });
});

test('createSigner with HMAC key', function(t) {
  var s = httpSignature.createSigner({
    keyId: 'foo',
    key: hmacKey,
    algorithm: 'hmac-sha256'
  });
  var date = s.writeDateHeader();
  s.writeTarget('get', '/');
  s.writeHeader('x-some-header', 'bar');
  s.sign(function (err, authz) {
    t.error(err);
    var req = http.request(httpOptions, function(res) {
      t.end();
    });
    req.setHeader('date', date);
    req.setHeader('authorization', authz);
    req.setHeader('x-some-header', 'bar');
    req.end();
  });
});

test('createSigner with sign function', function(t) {
  var date;
  var s = httpSignature.createSigner({
    sign: function (data, cb) {
      t.ok(typeof (data) === 'string');
      var m = data.match(/^date: (.+)$/);
      t.ok(m);
      t.strictEqual(m[1], date);
      cb(null, {
        keyId: 'foo',
        algorithm: 'hmac-sha256',
        signature: 'fakesig'
      });
    }
  });
  date = s.writeDateHeader();
  s.sign(function (err, authz) {
    t.error(err);
    t.ok(authz.match(/fakesig/));
    var req = http.request(httpOptions, function(res) {
      t.end();
    });
    req.setHeader('date', date);
    req.setHeader('authorization', authz);
    req.end();
  });
});

test('tear down', function(t) {
  server.on('close', function() {
    t.end();
  });
  server.close();
});
