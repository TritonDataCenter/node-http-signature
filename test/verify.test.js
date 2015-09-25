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
    t.ok(!httpSignature.verifyHMAC(parsed, hmacKey));

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.headers.Date = _rfc1123();
  options.headers.Authorization =
    'Signature keyId="foo",algorithm="hmac-sha1",signature="' +
     uuid() + '"';

  http.get(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
});


test('valid hmac', function(t) {
  server.tester = function(req, res) {
    var parsed = httpSignature.parseRequest(req);
    t.ok(httpSignature.verifyHMAC(parsed, hmacKey));

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.headers.Date = _rfc1123();
  var hmac = crypto.createHmac('sha1', hmacKey);
  hmac.update('date: ' + options.headers.Date);
  options.headers.Authorization =
    'Signature keyId="foo",algorithm="hmac-sha1",signature="' +
    hmac.digest('base64') + '"';

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
    'Signature keyId="foo",algorithm="rsa-sha1",signature="' +
    uuid() + '"';

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
    'Signature keyId="foo",algorithm="rsa-sha256",signature="' +
    signer.sign(rsaPrivate, 'base64') + '"';

  http.get(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
});


test('invalid date', function(t) {
  server.tester = function(req, res) {
    t.throws(function() {
      httpSignature.parseRequest(req);
    });

    res.writeHead(400);
    res.end();
  };

  options.method = 'POST';
  options.path = '/';
  options.headers.host = 'example.com';
  // very old, out of valid date range
  options.headers.Date = 'Sat, 01 Jan 2000 00:00:00 GMT';
  var signer = crypto.createSign('RSA-SHA256');
  signer.update('date: ' + options.headers.Date);
  options.headers.Authorization =
    'Signature keyId="Test",algorithm="rsa-sha256",signature="' +
    signer.sign(rsaPrivate, 'base64') + '"';

  var req = http.request(options, function(res) {
    t.equal(res.statusCode, 400);
    t.end();
  });
  req.end();
});


// test values from spec for simple test
test('valid rsa from spec default', function(t) {
  server.tester = function(req, res) {
    console.log('> [SIMPLE]', req.headers.authorization);
    var parsed = httpSignature.parseRequest(req, {
      // this test uses a fixed old date so ignore clock skew
      clockSkew: Number.MAX_VALUE
    });
    t.ok(httpSignature.verify(parsed, rsaPublic));
    // check known signature
    t.ok(req.headers.authorization === 'Signature keyId="Test",algorithm="rsa-sha256",signature="ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA="');

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.method = 'POST';
  options.path = '/';
  options.headers.host = 'example.com';
  // date from spec examples
  options.headers.Date = 'Thu, 05 Jan 2012 21:31:40 GMT';
  var signer = crypto.createSign('RSA-SHA256');
  signer.update('date: ' + options.headers.Date);
  options.headers.Authorization =
    'Signature keyId="Test",algorithm="rsa-sha256",signature="' +
    signer.sign(rsaPrivate, 'base64') + '"';

  var req = http.request(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
  req.end();
});


// test values from spec for defaults
test('valid rsa from spec default #2', function(t) {
  server.tester = function(req, res) {
    console.log('> [DEFAULT]', req.headers.authorization);
    var parsed = httpSignature.parseRequest(req, {
      // this test uses a fixed old date so ignore clock skew
      clockSkew: Number.MAX_VALUE
    });
    t.ok(httpSignature.verify(parsed, rsaPublic));
    // check known signature
    t.ok(req.headers.authorization === 'Signature keyId="Test",algorithm="rsa-sha256",signature="ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA="');

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.method = 'POST';
  options.path = '/foo?param=value&pet=dog';
  options.headers.host = 'example.com';
  options.headers.Date = 'Thu, 05 Jan 2012 21:31:40 GMT';
  options.headers['content-type'] = 'application/json';
  options.headers['content-md5'] = 'Sd/dVLAcvNLSq16eXua5uQ==';
  options.headers['content-length'] = '18';
  var signer = crypto.createSign('RSA-SHA256');
  signer.update('date: ' + options.headers.Date);
  options.headers.Authorization =
    'Signature keyId="Test",algorithm="rsa-sha256",signature="' +
    signer.sign(rsaPrivate, 'base64') + '"';

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
    var parsed = httpSignature.parseRequest(req, {
      // this test uses a fixed old date so ignore clock skew
      clockSkew: Number.MAX_VALUE
    });
    t.ok(httpSignature.verify(parsed, rsaPublic));
    // check known signature
    t.ok(req.headers.authorization === 'Signature keyId="Test",algorithm="rsa-sha256",headers="request-line host date content-type content-md5 content-length",signature="H/AaTDkJvLELy4i1RujnKlS6dm8QWiJvEpn9cKRMi49kKF+mohZ15z1r+mF+XiKS5kOOscyS83olfBtsVhYjPg2Ei3/D9D4Mvb7bFm9IaLJgYTFFuQCghrKQQFPiqJN320emjHxFowpIm1BkstnEU7lktH/XdXVBo8a6Uteiztw="');

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.method = 'POST';
  options.path = '/foo?param=value&pet=dog';
  options.headers.host = 'example.com';
  options.headers.Date = 'Thu, 05 Jan 2012 21:31:40 GMT';
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
    ',signature="' + signer.sign(rsaPrivate, 'base64') + '"';

  var req = http.request(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
  req.write('{"hello": "world"}');
  req.end();
});



// draft 3 function
test('valid rsa from spec draft 03', function(t) {
  server.tester = function(req, res) {
    console.log('> [ALL]', req.headers.authorization);
    var parsed = httpSignature.parseRequest(req, {
      // this test uses a fixed old date so ignore clock skew
      clockSkew: Number.MAX_VALUE,
      draft: '03'
    });
    t.ok(httpSignature.verify(parsed, rsaPublic));
    // check expected signature
    t.equal(req.headers.authorization, 'Signature keyId="Test",algorithm="rsa-sha256",headers="(request-target) date x-nonce",signature="gTfYLWS703Y/5301ij3Xf+gtxV1fdF3mrdXOCxz3QtGylT/CP7xOpuEMvK/TSHYQauAk99P7QQ2HBoOtuIz0IU6OGfXOYTrbqyC/+9Ip9NqBh+ks9svfxOZZC/TW8n+NoQXYpiK6JTAc0erMXp0CawjVaHLQRbW6EDq7Kqhk4SI="');

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.method = 'GET';
  options.path = '/happy?when=now';
  options.headers['x-nonce'] = '1234';
  options.headers.Date = 'Thu, 05 Jan 2012 21:31:40 GMT';

  var signer = crypto.createSign('RSA-SHA256');
  signer.update('(request-target): ' + options.method + ' ' + options.path + '\n');
  signer.update('date: ' + options.headers.Date + '\n');
  signer.update('x-nonce: ' + options.headers['x-nonce']);
  options.headers.Authorization =
    'Signature keyId="Test",algorithm="rsa-sha256",headers=' +
    '"(request-target) date x-nonce"' +
    ',signature="' + signer.sign(rsaPrivate, 'base64') + '"';

  var req = http.request(options, function(res) {
    t.equal(res.statusCode, 200);
    t.end();
  });
  req.end();
});


// test values from spec for all headers - draft 03
test('valid rsa from spec draft 03, all headers', function(t) {
  server.tester = function(req, res) {
    console.log('> [ALL]', req.headers.authorization);
    var parsed = httpSignature.parseRequest(req, {
      // this test uses a fixed old date so ignore clock skew
      clockSkew: Number.MAX_VALUE,
      draft: '03'
    });
    t.ok(httpSignature.verify(parsed, rsaPublic));
    // check expected signature
    t.equal(req.headers.authorization, 'Signature keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date content-type content-md5 content-length",signature="VNG/wZs2H/T9lyTeRyDFtLKwhrtTWSdng1L6AD7th1oK//yBKu97Lh3hH+R/9g9VfpaYscw1DKzK9CaDV8AnECg5v7UTBL9bQaCB4le7k/jHQk5kcxt5E3XKDNdYOl90PT0SG43vnbXvFvJ3zKdNqNeZeqLoC0zL/OMEWV9GfCI="');

    res.writeHead(200);
    res.write(JSON.stringify(parsed, null, 2));
    res.end();
  };

  options.method = 'POST';
  options.path = '/foo?param=value&pet=dog';
  options.headers.host = 'example.com';
  options.headers.Date = 'Thu, 05 Jan 2012 21:31:40 GMT';
  options.headers['content-type'] = 'application/json';
  options.headers['content-md5'] = 'Sd/dVLAcvNLSq16eXua5uQ==';
  options.headers['content-length'] = '18';
  var signer = crypto.createSign('RSA-SHA256');
  signer.update('(request-target): ' + options.method + ' ' + options.path + '\n');
  signer.update('host: ' + options.headers.host + '\n');
  signer.update('date: ' + options.headers.Date + '\n');
  signer.update('content-type: ' + options.headers['content-type'] + '\n');
  signer.update('content-md5: ' + options.headers['content-md5'] + '\n');
  signer.update('content-length: ' + options.headers['content-length']);
  options.headers.Authorization =
    'Signature keyId="Test",algorithm="rsa-sha256",headers=' +
    '"(request-target) host date content-type content-md5 content-length"' +
    ',signature="' + signer.sign(rsaPrivate, 'base64') + '"';

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
