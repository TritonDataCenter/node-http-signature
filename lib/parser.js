// Copyright 2011 Joyent, Inc.  All rights reserved.

var assert = require('assert');
var util = require('util');



///--- Globals

var Algorithms = {
  'rsa-sha1': true,
  'rsa-sha256': true,
  'rsa-sha512': true,
  'dsa-sha1': true,
  'hmac-sha1': true,
  'hmac-sha256': true,
  'hmac-sha512': true
};

var State = {
  New: 0,
  Params: 1,
  Signature: 2
};

var ParamsState = {
  Name: 0,
  Value: 1
};



///--- Specific Errors

function HttpSignatureError(message, caller) {
  if (Error.captureStackTrace)
    Error.captureStackTrace(this, caller || HttpSignatureError);

  this.message = message;
  this.__defineGetter__('name', function() {
    return caller.name;
  });
}
util.inherits(HttpSignatureError, Error);

function ExpiredRequestError(message) {
  HttpSignatureError.call(this, message, ExpiredRequestError);
}
util.inherits(ExpiredRequestError, HttpSignatureError);


function InvalidHeaderError(message) {
  HttpSignatureError.call(this, message, InvalidHeaderError);
}
util.inherits(InvalidHeaderError, HttpSignatureError);


function InvalidParamsError(message) {
  HttpSignatureError.call(this, message, InvalidParamsError);
}
util.inherits(InvalidParamsError, HttpSignatureError);


function MissingHeaderError(message) {
  HttpSignatureError.call(this, message, MissingHeaderError);
}
util.inherits(MissingHeaderError, HttpSignatureError);



///--- Exported API

module.exports = {

  /**
   * Parses the 'Authorization' header out of an http.ServerRequest object.
   *
   * Note that this API will fully validate the Authorization header, and throw
   * on any error.  It will not however check the signature, or the keyId format
   * as those are specific to your environment.  You can use the options object
   * to pass in extra constraints.
   *
   * As a response object you can expect this:
   *
   *     {
   *       "scheme": "Signature",
   *       "params": {
   *         "keyId": "foo",
   *         "algorithm": "rsa-sha256",
   *         "headers": [
   *           "date",
   *           "content-md5"
   *         ]
   *       },
   *       "signature": "base64",
   *       "signingString": "ready to be passed to crypto.verify()"
   *     }
   *
   * @param {Object} request an http.ServerRequest.
   * @param {Object} options an optional options object with:
   *                   - clockSkew: allowed clock skew in seconds (default 300).
   *                   - headers: header names to require (default: date).
   *                   - algorithms: algorithms to support (default: all).
   * @return {Object} parsed out object (see above).
   * @throws {TypeError} on invalid input.
   * @throws {InvalidHeaderError} on an invalid Authorization header error.
   * @throws {InvalidParamsError} if the params in the scheme are invalid.
   * @throws {MissingHeaderError} if the params indicate a header not present,
   *                              either in the request headers from the params,
   *                              or not in the params from a required header
   *                              in options.
   * @throws {ExpiredRequestError} if the value of date exceeds clock skew.
   */
  parseRequest: function(request, options) {
    if (!request || !request.headers)
      throw new TypeError('request must be a node http.ServerRequest');

    if (!request.headers.authorization)
      throw new MissingHeaderError('no authorization header present in ' +
                                   'the requset');

    if (options && typeof(options) !== 'object')
      throw new TypeError('options was not an object');

    if (!options) {
      options = {
        clockSkew: 300,
        headers: ['date']
      };
    } else {
      if (options.clockSkew === undefined) {
        options.clockSkew = 300;
      } else if (typeof(options.clockSkew) !== 'number') {
        throw new TypeError('options.clockSkew must be in seconds (number)');
      }

      if (options.headers === undefined) {
        options.headers = ['date'];
      } else if (!(options.headers instanceof Array)) {
        throw new TypeError('options.headers must be an array of strings');
      } else {
        options.headers.forEach(function(h) {
          if (typeof(h) !== 'string')
            throw new TypeError('options.headers must be an array of strings');
        });
      }
    }

    var i = 0;
    var state = State.New;
    var substate = ParamsState.Name;
    var tmpName = '';
    var tmpValue = '';

    var parsed = {
      scheme: '',
      params: {},
      signature: '',
      signingString: '',

      get algorithm() {
        return this.params.algorithm.toUpperCase();
      },

      get keyId() {
        return this.params.keyId;
      }

    };

    var authz = request.headers.authorization;
    for (i = 0; i < authz.length; i++) {
      var c = authz.charAt(i);

      switch (Number(state)) {

      case State.New:
        if (c !== ' ') parsed.scheme += c;
        else state = State.Params;
        break;

      case State.Params:

        switch (Number(substate)) {

        case ParamsState.Name:
          if (c === '=') {
            // NoOp
          } else if (c === '"') {
            parsed.params[tmpName] = '';
            tmpValue = '';
            substate = ParamsState.Value;
          } else if (c === ',') {
            // NoOp
          } else if (c === ' ') {
            state = State.Signature;
          } else {
            tmpName += c;
          }
          break;

        case ParamsState.Value:
          if (c === '"') {
            parsed.params[tmpName] = tmpValue;
            tmpName = '';
            substate = ParamsState.Name;
          } else {
            tmpValue += c;
          }
          break;
        }
        break;

      case State.Signature:
        parsed.signature += c;
        break;
      }
    }

    if (!parsed.params.headers || parsed.params.headers === '') {
      parsed.params.headers = ['date'];
    } else {
      parsed.params.headers = parsed.params.headers.split(' ');
    }

    // Minimally validate the parsed object
    if (!parsed.scheme || parsed.scheme !== 'Signature')
      throw new InvalidHeaderError('scheme was not "Signature"');

    if (!parsed.params.keyId)
      throw new InvalidHeaderError('keyId was not specified');

    if (!parsed.params.algorithm)
      throw new InvalidHeaderError('algorithm was not specified');

    if (!parsed.signature)
      throw new InvalidHeaderError('signature was empty');

    // Check the algorithm against the official list
    parsed.params.algorithm = parsed.params.algorithm.toLowerCase();
    if (!Algorithms[parsed.params.algorithm])
      throw new InvalidParamsError(parsed.params.algorithm +
                                   ' is not supported');

    // Build the signingString
    for (i = 0; i < parsed.params.headers.length; i++) {
      var h = parsed.params.headers[i].toLowerCase();
      parsed.params.headers[i] = h;

      var value;
      if (h !== 'request-line') {
        value = request.headers[h];
        if (!value)
          throw new MissingHeaderError(h + ' was not in the request');
      } else {
        value =
          request.method + ' ' + request.url + ' HTTP/' + request.httpVersion;
      }

      parsed.signingString += value;
      if ((i + 1) < parsed.params.headers.length)
        parsed.signingString += '\n';
    }

    // Check against the constraints
    if (request.headers.date) {
      var date = new Date(request.headers.date);
      var now = new Date();
      var skew = Math.abs(now.getTime() - date.getTime());

      if ((now.getTime() - date.getTime()) > options.clockSkew * 1000) {
        throw new ExpiredRequestError('clock skew of ' +
                                      (skew / 1000) +
                                      's was greater than ' +
                                      options.clockSkew + 's');
      }
    }

    options.headers.forEach(function(h) {
      // Remember that we already checked any headers in the params
      // were in the request, so if this passes we're good.
      if (parsed.params.headers.indexOf(h) < 0)
        throw new MissingHeaderError(h + ' was not a signed header');
    });

    if (options.algorithms) {
      if (options.algorithms.indexOf(parsed.params.algorithm) === -1)
        throw new InvalidParamsError(parsed.params.algorithm +
                                     ' is not a supported algorithm');
    }

    return parsed;
  }

};
