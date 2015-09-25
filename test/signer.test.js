// Copyright 2011 Joyent, Inc.  All rights reserved.

var crypto = require('crypto');
var fs = require('fs');
var http = require('http');

var test = require('tap').test;
var uuid = require('node-uuid');

var httpSignature = require('../lib/index');



///--- Globals

var hmacKey = null;
var httpOptions = null;
var rsaPrivate = null;
var signOptions = null;
var server = null;
var socket = null;



///--- Tests


test('setup', function(t) {
  rsaPrivate = fs.readFileSync(__dirname + '/rsa_private.pem', 'ascii');
  t.ok(rsaPrivate, 'rsaPrivate');

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
  t.ok(httpSignature.sign(req, signOptions), 'defaults httpSig');
  t.ok(req.getHeader('Authorization'), 'defaults Authorization');
  console.log('> ' + req.getHeader('Authorization'));
  req.end();
});


test('request line', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
    keyId: 'unit',
    key: rsaPrivate,
    headers: ['date', 'request-line']
  };

  t.ok(httpSignature.sign(req, opts), 'request line httpSig');
  t.ok(req.getHeader('Authorization'), 'request line Authorization');
  console.log('> ' + req.getHeader('Authorization'));
  req.end();
});


test('(target-request)', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
    keyId: 'unit',
    key: rsaPrivate,
    headers: ['date', '(target-request)'],
    draft: '03'
  };

  t.ok(httpSignature.sign(req, opts),'(target-request) httpSignature');
  t.ok(req.getHeader('Authorization'),'(target-request) Authorization');
  console.log('> ' + req.getHeader('Authorization'));
  req.end();
});



test('(target-request) draft 01', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
    keyId: 'unit',
    key: rsaPrivate,
    headers: ['date', '(target-request)'],
    draft: '01'
  };

  // tap.throws is broken
  var thrown;
  try {
    httpSignature.sign(req, opts);
    thrown = false;
  } catch (e) {
    thrown = e.message;
  }
  t.same(thrown, '(target-request) was not in the request', 'thrown');
  req.end();
});


test('request-line draft 03', function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
    keyId: 'unit',
    key: rsaPrivate,
    headers: ['date', 'request-line'],
    draft: '03'
  };

  // tap.throws is broken
  var thrown;
  try {
    httpSignature.sign(req, opts);
    thrown = false;
  } catch (e) {
    thrown = e.message;
  }
  t.same(thrown, 'request-line was not in the request', 'thrown');
  req.end();
});


test('bad draft',function(t) {
  var req = http.request(httpOptions, function(res) {
    t.end();
  });
  var opts = {
        keyId: 'unit',
        key: rsaPrivate,
        headers: ['date'],
        draft: '99'
      };
  // tap.throws is broken
  var thrown;
  try {
    httpSignature.sign(req, opts);
    thrown = false;
  } catch (e) {
    thrown = e.message;
  }
  t.same(thrown, 'draft 99 is not supported', 'thrown');
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

  t.ok(httpSignature.sign(req, opts), 'hmac httpSig');
  t.ok(req.getHeader('Authorization'), 'hmac Authorization');
  console.log('> ' + req.getHeader('Authorization'));
  req.end();
});


test('tear down', function(t) {
  server.on('close', function() {
    t.end();
  });
  server.close();
});
