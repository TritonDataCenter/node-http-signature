// Copyright 2015 Joyent, Inc.  All rights reserved.

var fs = require('fs');
var path = require('path');
var http = require('http');
var sshpk = require('sshpk');
var assert = require('assert-plus');

var test = require('tap').test;
var uuid = require('node-uuid');

var httpSignature = require('../lib/index');

var doc;
var privKey, pubKey;
var httpReqData;
var signs = [];
var httpReq;

test('read in doc', function (t) {
	doc = fs.readFileSync(path.join(__dirname, '..', 'http_signing.md'));
	if (Buffer.isBuffer(doc))
		doc = doc.toString('utf-8');
	doc = doc.split('\n');
	t.end();
});

test('find keys and examples', function (t) {
	var i = 0;
	for (; i < doc.length; ++i)
		if (/^# Appendix A/.test(doc[i]))
			break;
	if (i >= doc.length)
		t.fail('could not find appendix A')

	var pubKeyLines = [];
	for (; i < doc.length; ++i)
		if (/-BEGIN PUBLIC KEY-/.test(doc[i]))
			break;
	for (; i < doc.length; ++i) {
		pubKeyLines.push(doc[i]);
		if (/-END PUBLIC KEY-/.test(doc[i]))
			break;
	}
	pubKey = sshpk.parseKey(pubKeyLines.
	    map(function (l) { return (l.replace(/^    /g, '')); }).
	    join('\n'));

	var privKeyLines = [];
	for (; i < doc.length; ++i)
		if (/-BEGIN RSA PRIVATE KEY-/.test(doc[i]))
			break;
	for (; i < doc.length; ++i) {
		privKeyLines.push(doc[i]);
		if (/-END RSA PRIVATE KEY-/.test(doc[i]))
			break;
	}
	privKey = sshpk.parsePrivateKey(privKeyLines.
	    map(function (l) { return (l.replace(/^    /g, '')); }).
	    join('\n'));

	var reqLines = [];
	for (; i < doc.length; ++i)
		if (doc[i] === '<!-- httpreq -->')
			break;
	for (++i; i < doc.length; ++i) {
		if (doc[i] === '<!-- /httpreq -->')
			break;
		reqLines.push(doc[i]);
	}
	httpReqData = reqLines.
	    map(function (l) { return (l.replace(/^    /g, '')); }).
	    join('\r\n');

	var thisConfig;
	var lines;
	do {
		thisConfig = {};
		for (; i < doc.length; ++i) {
			var m = doc[i].match(/^<!-- sign (.+) -->$/);
			if (m && m[1]) {
				thisConfig = JSON.parse(m[1]);
				break;
			}
		}

		for (; i < doc.length; ++i)
			if (doc[i] === '<!-- signstring -->')
				break;
		lines = [];
		for (++i; i < doc.length; ++i) {
			if (doc[i] === '<!-- /signstring -->')
				break;
			if (doc[i].length > 0)
				lines.push(doc[i]);
		}
		thisConfig.signString = lines.
		    map(function (l) { return (l.replace(/^    /g, '')); }).
		    join('\n');

		for (; i < doc.length; ++i)
			if (doc[i] === '<!-- authz -->')
				break;
		lines = [];
		for (++i; i < doc.length; ++i) {
			if (doc[i] === '<!-- /authz -->')
				break;
			if (doc[i].length > 0)
				lines.push(doc[i]);
		}
		thisConfig.authz = lines.
		    map(function (l) { return (l.replace(/^    /g, '')); }).
		    join('\n');

		if (thisConfig.name)
			signs.push(thisConfig);

	} while (i < doc.length);

	t.end();
});

/*
 * This is horrible, and depends on a totally private node.js interface. But
 * it's better than trying to write our own HTTP parser... I hope. This
 * interface has been pretty stable in practice, with minimal change from
 * 0.8 through to 4.2.
 */
var binding, HTTPParser, kOnHeadersComplete;

if (process.binding)
	binding = process.binding('http_parser');
if (binding)
	HTTPParser = binding.HTTPParser;
if (HTTPParser)
	kOnHeadersComplete = HTTPParser.kOnHeadersComplete;

function DummyRequest() {
}
DummyRequest.prototype.getHeader = function (h) {
	return (this.headers[h.toLowerCase()]);
};
DummyRequest.prototype.setHeader = function (h, v) {
	this.headers[h.toLowerCase()] = v;
};
function parseHttpRequest(data, cb) {
	var p = new HTTPParser();
	var obj = new DummyRequest();
	p[kOnHeadersComplete] = onHeadersComplete;
	function onHeadersComplete(opts) {
		obj.httpVersionMajor = opts.versionMajor;
		obj.httpVersionMinor = opts.versionMinor;
		obj.httpVersion = opts.versionMajor + '.' + opts.versionMinor;

		obj.rawHeaders = opts.headers;
		obj.headers = {};
		for (var i = 0; i < opts.headers.length; i += 2) {
			var k = opts.headers[i].toLowerCase();
			var v = opts.headers[i+1];
			obj.headers[k] = v;
		}

		obj.url = opts.url;
		obj.path = opts.url;
		obj.method = HTTPParser.methods[opts.method];
		obj.upgrade = opts.upgrade;

		assert.ok(obj.httpVersion);
		cb(obj);
	}
	p.execute(new Buffer(data));
}

if (binding && HTTPParser && kOnHeadersComplete) {

	test('parse http request', function (t) {
		parseHttpRequest(httpReqData, function (req) {
			httpReq = req;
			t.end();
		});
	});

	test('setup configs', function (t) {
		signs.forEach(function (sign) {
			test('example in "' + sign.name + '"',
			    testSignConfig.bind(this, sign));
		});
		t.end();
	});

	function testSignConfig(config, t) {
		var opts = config.options;
		opts.key = privKey;

		delete (httpReq.headers['authorization']);
		t.ok(httpSignature.signRequest(httpReq, opts));

		var authz = 'Authorization: ' +
		    httpReq.headers['authorization'];
		t.strictEqual(config.authz, authz);

		t.end();
	}

}
