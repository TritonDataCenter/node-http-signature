// Copyright 2011 Joyent, Inc.  All rights reserved.

var test = require('tap').test;

var sshKeyFingerprint = require('../lib/index').sshKeyFingerprint;
var sshKeyToPEM = require('../lib/index').sshKeyToPEM;
var pemToRsaSSHKey = require('../lib/index').pemToRsaSSHKey;



///--- Globals
var SSH_1024 = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEAvad19ePSDckmgmo6Unqmd8' +
  'n2G7o1794VN3FazVhV09yooXIuUhA+7OmT7ChiHueayxSubgL2MrO/HvvF/GGVUs/t3e0u4' +
  '5YwRC51EVhyDuqthVJWjKrYxgDMbHru8fc1oV51l0bKdmvmJWbA/VyeJvstoX+eiSGT3Jge' +
  'egSMVtc= mark@foo.local';
var PEM_1024 = '-----BEGIN PUBLIC KEY-----\n' +
  'MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQC9p3X149INySaCajpSeqZ3yfYb\n' +
  'ujXv3hU3cVrNWFXT3Kihci5SED7s6ZPsKGIe55rLFK5uAvYys78e+8X8YZVSz+3d\n' +
  '7S7jljBELnURWHIO6q2FUlaMqtjGAMxseu7x9zWhXnWXRsp2a+YlZsD9XJ4m+y2h\n' +
  'f56JIZPcmB56BIxW1wIBIw==\n' +
  '-----END PUBLIC KEY-----\n';

var SSH_2048 = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAr+isTwMYqwCAcY0Yb2F0pF' +
  '+/F4/wxGzcrLR2PrgoBXwjj/TnEA3tJ7v08Rru3lAd/O59B6TbXOsYbQ+2Syd82Dm8L3SJR' +
  'NlZJ6DZUOAwnTOoNgkfH2CsbGS84aTPTeXjmMsw52GvQ9yWFDUglHzMIzK2iSHWNl1dAaBE' +
  'iddifGmrpUTPJ5Tt7l8YS4jdaBf6klS+3CvL6xET/RjZhKGtrrgsRRYUB2XVtgQhKDu7PtD' +
  'dlpy4+VISdVhZSlXFnBhya/1KxLS5UFHSAdOjdxzW1bh3cPzNtuPXZaiWUHvyIWpGVCzj5N' +
  'yeDXcc7n0E20yx9ZDkAITuI8X49rnQzuCN5Q== mark@bluesnoop.local';
var PEM_2048 = '-----BEGIN PUBLIC KEY-----\n' +
  'MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAr+isTwMYqwCAcY0Yb2F0\n' +
  'pF+/F4/wxGzcrLR2PrgoBXwjj/TnEA3tJ7v08Rru3lAd/O59B6TbXOsYbQ+2Syd8\n' +
  '2Dm8L3SJRNlZJ6DZUOAwnTOoNgkfH2CsbGS84aTPTeXjmMsw52GvQ9yWFDUglHzM\n' +
  'IzK2iSHWNl1dAaBEiddifGmrpUTPJ5Tt7l8YS4jdaBf6klS+3CvL6xET/RjZhKGt\n' +
  'rrgsRRYUB2XVtgQhKDu7PtDdlpy4+VISdVhZSlXFnBhya/1KxLS5UFHSAdOjdxzW\n' +
  '1bh3cPzNtuPXZaiWUHvyIWpGVCzj5NyeDXcc7n0E20yx9ZDkAITuI8X49rnQzuCN\n' +
  '5QIBIw==\n' +
  '-----END PUBLIC KEY-----\n';

var SSH_4096 = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAgEAsWUdvcKBBjW4GJ8Uyo0S8U' +
  'FFZbg5bqeRWPHcR2eIbo/k7M54PmWFqNL3YCIR8cRsvsFuYObnVaY01p1p/9+tpN4ezaHS5' +
  '9glhADTSva3uLrYuWA1FCKFi6/rXn9WkM5diSVrrTXzaQE8ZsVRA5QG6AeWhC3x/HNbiJOG' +
  'd9u0xrzYnyjrhO6x7eCnSz/AtNURLyWHbZ9Q0VEY5UVQsfAmmAAownMTth1m7KRG/KgM1Oz' +
  '9Dc+IUHYf0pjxFLQVQgqPnOLsj8OIJEt9SbZR33n66UJezbsbm0uJ+ophA3W/OacvHzCmoL' +
  'm9PaCwYEZ2pIlYlhkGGu6CFpfXhYUne61WAV8xR8pDXaIL7BqLRJZKlxPzrg9Iu278V9XeL' +
  'CnandXIGpaKwC5p7N/K6JoLB+nI1xd4X1NIftaBouxmYTXJy1VK2DKkD+KyvUPtN7EXnC4G' +
  'E4eDn9nibIj35GjfiDXrxcPPaJhSVzqvIIt55XcAnUEEVtiKtxICKwTSbvsojML5hL/gdeu' +
  'MWnMxj1nsZzTgSurD2OFaQ22k5HGu9aC+duNvvgjXWou7BsS/vH1QbP8GbIvYKlO5xNIj9z' +
  'kjINP3nCX4K1+IpW3PDkgS/DleUhUlvhxb10kc4af+9xViAGkV71WqNcoY+PAETvEbDbYpg' +
  'VEBd4mwFJLl/DT2Nlbj9q0= mark@bluesnoop.local';
var PEM_4096 = '-----BEGIN PUBLIC KEY-----\n' +
  'MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAsWUdvcKBBjW4GJ8Uyo0S\n' +
  '8UFFZbg5bqeRWPHcR2eIbo/k7M54PmWFqNL3YCIR8cRsvsFuYObnVaY01p1p/9+t\n' +
  'pN4ezaHS59glhADTSva3uLrYuWA1FCKFi6/rXn9WkM5diSVrrTXzaQE8ZsVRA5QG\n' +
  '6AeWhC3x/HNbiJOGd9u0xrzYnyjrhO6x7eCnSz/AtNURLyWHbZ9Q0VEY5UVQsfAm\n' +
  'mAAownMTth1m7KRG/KgM1Oz9Dc+IUHYf0pjxFLQVQgqPnOLsj8OIJEt9SbZR33n6\n' +
  '6UJezbsbm0uJ+ophA3W/OacvHzCmoLm9PaCwYEZ2pIlYlhkGGu6CFpfXhYUne61W\n' +
  'AV8xR8pDXaIL7BqLRJZKlxPzrg9Iu278V9XeLCnandXIGpaKwC5p7N/K6JoLB+nI\n' +
  '1xd4X1NIftaBouxmYTXJy1VK2DKkD+KyvUPtN7EXnC4GE4eDn9nibIj35GjfiDXr\n' +
  'xcPPaJhSVzqvIIt55XcAnUEEVtiKtxICKwTSbvsojML5hL/gdeuMWnMxj1nsZzTg\n' +
  'SurD2OFaQ22k5HGu9aC+duNvvgjXWou7BsS/vH1QbP8GbIvYKlO5xNIj9zkjINP3\n' +
  'nCX4K1+IpW3PDkgS/DleUhUlvhxb10kc4af+9xViAGkV71WqNcoY+PAETvEbDbYp\n' +
  'gVEBd4mwFJLl/DT2Nlbj9q0CASM=\n' +
  '-----END PUBLIC KEY-----\n';

var DSA_1024 = 'ssh-dss AAAAB3NzaC1kc3MAAACBAKK5sckoM05sOPajUcTWG0zPTvyRmj6' +
  'YQ1g2IgezUUrXgY+2PPy07+JrQi8SN9qr/CBP+0q0Ec48qVFf9LlkUBwu9Jf5HTUVNiKNj3c' +
  'SRPFH8HqZn+nxhVsOLhnHWxgDQ8OOm48Ma61NcYVo2B0Ne8cUs8xSqLqba2EG9ze87FQZAAA' +
  'AFQCVP/xpiAofZRD8L4QFwxOW9krikQAAAIACNv0EmKr+nIA13fjhpiqbYYyVXYOiWM4cmOD' +
  'G/d1J8/vR4YhWHWPbAEw7LD0DEwDIHLlRZr/1jsHbFcwt4tzRs95fyHzpucpGhocmjWx43qt' +
  'xEhDeJrxPlkIXHakciAEhoo+5YeRSSgRse5PrZDosdr5fA+DADs8tnto5Glf5owAAAIBHcEF' +
  '5ytvCRiKbsWKOgeMZ7JT/XGX+hMhS7aaJ2IspKj7YsWada1yBwoM6yYHtlpnGsq/PoPaZU8K' +
  '40f47psV6OhSh+/O/jgqLS/Ur2c0mQQqIb7vvkc7he/SPOQAqyDmyYFBuazuSf2s9Uy2hfvj' +
  'Wgb6X+vN9W8SOb2668IL7Vg== mark@bluesnoop.local';
var DSA_1024_PEM = '-----BEGIN PUBLIC KEY-----\n' +
  'MIIBtjCCASsGByqGSM44BAEwggEeAoGBAKK5sckoM05sOPajUcTWG0zPTvyRmj6Y\n' +
  'Q1g2IgezUUrXgY+2PPy07+JrQi8SN9qr/CBP+0q0Ec48qVFf9LlkUBwu9Jf5HTUV\n' +
  'NiKNj3cSRPFH8HqZn+nxhVsOLhnHWxgDQ8OOm48Ma61NcYVo2B0Ne8cUs8xSqLqb\n' +
  'a2EG9ze87FQZAhUAlT/8aYgKH2UQ/C+EBcMTlvZK4pECgYACNv0EmKr+nIA13fjh\n' +
  'piqbYYyVXYOiWM4cmODG/d1J8/vR4YhWHWPbAEw7LD0DEwDIHLlRZr/1jsHbFcwt\n' +
  '4tzRs95fyHzpucpGhocmjWx43qtxEhDeJrxPlkIXHakciAEhoo+5YeRSSgRse5Pr\n' +
  'ZDosdr5fA+DADs8tnto5Glf5owOBhAACgYBHcEF5ytvCRiKbsWKOgeMZ7JT/XGX+\n' +
  'hMhS7aaJ2IspKj7YsWada1yBwoM6yYHtlpnGsq/PoPaZU8K40f47psV6OhSh+/O/\n' +
  'jgqLS/Ur2c0mQQqIb7vvkc7he/SPOQAqyDmyYFBuazuSf2s9Uy2hfvjWgb6X+vN9\n' +
  'W8SOb2668IL7Vg==\n' +
  '-----END PUBLIC KEY-----\n';

///--- Tests

test('1024b pem to rsa ssh key', function(t) {
  t.equal(pemToRsaSSHKey(PEM_1024, 'mark@foo.local'), SSH_1024);
  t.end();
});

test('2048b pem to rsa ssh key', function(t) {
  t.equal(pemToRsaSSHKey(PEM_2048, 'mark@bluesnoop.local'), SSH_2048);
  t.end();
});

test('4096b pem to rsa ssh key', function(t) {
  t.equal(pemToRsaSSHKey(PEM_4096, 'mark@bluesnoop.local'), SSH_4096);
  t.end();
});

test('1024b rsa ssh key', function(t) {
  t.equal(sshKeyToPEM(SSH_1024), PEM_1024);
  t.end();
});

test('2048b rsa ssh key', function(t) {
  t.equal(sshKeyToPEM(SSH_2048), PEM_2048);
  t.end();
});


test('4096b rsa ssh key', function(t) {
  t.equal(sshKeyToPEM(SSH_4096), PEM_4096);
  t.end();
});


test('1024b dsa ssh key', function(t) {
  t.equal(sshKeyToPEM(DSA_1024), DSA_1024_PEM);
  t.end();
});

test('fingerprint', function(t) {
  var fp = sshKeyFingerprint(SSH_1024);
  t.equal(fp, '59:a4:61:0e:38:18:9f:0f:28:58:2a:27:f7:65:c5:87');
  t.end();
});


