// Copyright 2011 Joyent, Inc.  All rights reserved.

var http = require('http');

var httpu = require('httpu');
var uuid = require('node-uuid');

var httpSignature = require('../lib/index');



///--- Globals

var options = null;
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

exports.setUp = function(test, assert) {
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
    test.finish();
  });
};


exports.test_no_authorization = function(test, assert) {
  server.tester = function(req, res) {
    assert.throws(
      function() {
        httpSignature.parseRequest(req);
      },
      TypeError);

    res.writeHead(200);
    res.end();
  };

  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_bad_scheme = function(test, assert) {
  server.tester = function(req, res) {
    assert.throws(
      function() {
        httpSignature.parseRequest(req);
      },
        /InvalidHeaderError: scheme was not "Signature"/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization = 'Basic blahBlahBlah';
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_no_key_id = function(test, assert) {
  server.tester = function(req, res) {
    assert.throws(
      function() {
        httpSignature.parseRequest(req);
      },
        /InvalidHeaderError: keyId was not specified/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization = 'Signature foo';
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_key_id_no_value = function(test, assert) {
  server.tester = function(req, res) {
    assert.throws(
      function() {
        httpSignature.parseRequest(req);
      },
        /InvalidHeaderError: keyId was not specified/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization = 'Signature keyId=';
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_key_id_no_quotes = function(test, assert) {
  server.tester = function(req, res) {
    assert.throws(
      function() {
        httpSignature.parseRequest(req);
      },
        /InvalidHeaderError: keyId was not specified/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization =
    'Signature keyId=foo,algorithm=hmac-sha1 aabbcc';
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_no_algorithm = function(test, assert) {
  server.tester = function(req, res) {
    assert.throws(
      function() {
        httpSignature.parseRequest(req);
      },
        /InvalidHeaderError: algorithm was not specified/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization = 'Signature keyId="foo"';
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_algorithm_no_value = function(test, assert) {
  server.tester = function(req, res) {
    assert.throws(
      function() {
        httpSignature.parseRequest(req);
      },
        /InvalidHeaderError: algorithm was not specified/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization = 'Signature keyId="foo",algorithm=';
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_no_signature = function(test, assert) {
  server.tester = function(req, res) {
    assert.throws(
      function() {
        httpSignature.parseRequest(req);
      },
        /InvalidHeaderError: signature was empty/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization = 'Signature keyId="foo",algorithm="foo"';
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_invalid_algorithm = function(test, assert) {
  server.tester = function(req, res) {
    assert.throws(
      function() {
        httpSignature.parseRequest(req);
      },
        /InvalidParamsError: foo is not supported/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization =
    'Signature keyId="foo",algorithm="foo" aaabbbbcccc';
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_no_date_header = function(test, assert) {
  server.tester = function(req, res) {
    assert.throws(
      function() {
        httpSignature.parseRequest(req);
      },
        /MissingHeaderError: date was not in the request/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization =
    'Signature keyId="foo",algorithm="rsa-sha256" aaabbbbcccc';
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_valid_default_headers = function(test, assert) {
  server.tester = function(req, res) {
    assert.doesNotThrow(function() {
      httpSignature.parseRequest(req);
    });

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization =
    'Signature keyId="foo",algorithm="rsa-sha256" aaabbbbcccc';
  options.headers.Date = _rfc1123();
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_explicit_headers_missing = function(test, assert) {
  server.tester = function(req, res) {
    assert.throws(
      function() {
        httpSignature.parseRequest(req);
      },
        /MissingHeaderError: content-md5 was not in the request/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization =
    'Signature keyId="foo",algorithm="rsa-sha256",' +
    'headers="date content-md5" aaabbbbcccc';
  options.headers.Date = _rfc1123();
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_valid_explicit_headers = function(test, assert) {
  server.tester = function(req, res) {
    assert.doesNotThrow(function() {
      var parsed = httpSignature.parseRequest(req);
      res.writeHead(200);
      res.write(JSON.stringify(parsed, null, 2));
      res.end();
    });
  };


  options.headers.Authorization =
    'Signature keyId="fo,o",algorithm="RSA-sha256",' +
    'headers="dAtE cOntEnt-MD5 request-line",' +
    'extensions="blah blah" digitalSignature';
  options.headers.Date = _rfc1123();
  options.headers['content-md5'] = uuid();
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);

    var body = '';
    res.setEncoding('utf8');
    res.on('data', function(chunk) {
      body += chunk;
    });

    res.on('end', function() {
      console.log(body);
      var parsed = JSON.parse(body);
      assert.ok(parsed);
      assert.equal(parsed.scheme, 'Signature');
      assert.ok(parsed.params);
      assert.equal(parsed.params.keyId, 'fo,o');
      assert.equal(parsed.params.algorithm, 'rsa-sha256');
      assert.equal(parsed.params.extensions, 'blah blah');
      assert.ok(parsed.params.headers);
      assert.equal(parsed.params.headers.length, 3);
      assert.equal(parsed.params.headers[0], 'date');
      assert.equal(parsed.params.headers[1], 'content-md5');
      assert.equal(parsed.params.headers[2], 'request-line');
      assert.equal(parsed.signature, 'digitalSignature');
      assert.ok(parsed.signingString);
      assert.equal(parsed.signingString,
                   (options.headers.Date + '\n' +
                    options.headers['content-md5'] + '\n' +
                    'GET / HTTP/1.1'));
      assert.equal(parsed.params.keyId, parsed.keyId);
      assert.equal(parsed.params.algorithm.toUpperCase(),
                   parsed.algorithm);
      test.finish();
    });
  });
};


exports.test_expired = function(test, assert) {
  server.tester = function(req, res) {
    var options = {
      clockSkew: 1,
      headers: ['date']
    };

    setTimeout(function() {
      assert.throws(
        function() {
          httpSignature.parseRequest(req, options);
        },
          /ExpiredRequestError: clock skew of \d\.\d+s was greater than 1s/
      );

      res.writeHead(200);
      res.end();
    }, 1200);
  };

  options.headers.Authorization =
    'Signature keyId="f,oo",algorithm="RSA-sha256",' +
    'headers="dAtE cOntEnt-MD5" digitalSignature';
  options.headers.Date = _rfc1123();
  options.headers['content-md5'] = uuid();
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_missing_required_header = function(test, assert) {
  server.tester = function(req, res) {
    var options = {
      clockSkew: 1,
      headers: ['date', 'x-unit-test']
    };

    assert.throws(
      function() {
        httpSignature.parseRequest(req, options);
      },
        /MissingHeaderError: x-unit-test was not a signed header/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization =
    'Signature keyId="f,oo",algorithm="RSA-sha256",' +
    'headers="dAtE cOntEnt-MD5" digitalSignature';
  options.headers.Date = _rfc1123();
  options.headers['content-md5'] = uuid();
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.test_not_whitelist_algorithm = function(test, assert) {
  server.tester = function(req, res) {
    var options = {
      clockSkew: 1,
      algorithms: ['rsa-sha1']
    };

    assert.throws(
      function() {
        httpSignature.parseRequest(req, options);
      },
        /InvalidParamsError: rsa-sha256 is not a supported algorithm/
    );

    res.writeHead(200);
    res.end();
  };

  options.headers.Authorization =
    'Signature keyId="f,oo",algorithm="RSA-sha256",' +
    'headers="dAtE cOntEnt-MD5" digitalSignature';
  options.headers.Date = _rfc1123();
  options.headers['content-md5'] = uuid();
  httpu.get(options, function(res) {
    assert.equal(res.statusCode, 200);
    test.finish();
  });
};


exports.tearDown = function(test, assert) {
  server.on('close', function() {
    test.finish();
  });
  server.close();
};
