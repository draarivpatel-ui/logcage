import test from 'node:test';
import assert from 'node:assert/strict';
import { esm, throwsCode, shapedJwt, syntheticVendorSecrets } from './helpers.mjs';

const { CODE, redactSecrets } = esm;
const R = '[REDACTED]';

function countOccurrences(text, needle) {
  return text.split(needle).length - 1;
}

test('redactSecrets leaves benign text unchanged', () => {
  assert.equal(redactSecrets('ordinary log message'), 'ordinary log message');
});

for (const [label, value] of [
  ['undefined', undefined], ['null', null], ['number', 1], ['boolean', false],
  ['object', {}], ['array', []], ['bigint', 1n], ['symbol', Symbol('x')]
]) {
  test('redactSecrets rejects ' + label + ' input', () => {
    throwsCode(() => redactSecrets(value), CODE.INVALID_INPUT);
  });
}

for (const [label, options] of [
  ['unknown key', { nope: true }],
  ['empty replacement', { replacement: '' }],
  ['long replacement', { replacement: 'x'.repeat(129) }],
  ['newline replacement', { replacement: 'x\n' }],
  ['escape replacement', { replacement: 'x\x1b' }],
  ['bidi replacement', { replacement: 'x\u202e' }],
  ['non-array extraSecrets', { extraSecrets: 'abc' }],
  ['too many extraSecrets', { extraSecrets: Array.from({ length: 65 }, (_, i) => 's' + i) }],
  ['empty extra secret', { extraSecrets: [''] }],
  ['long extra secret', { extraSecrets: ['x'.repeat(4097)] }],
  ['numeric extra secret', { extraSecrets: [1] }],
  ['non-object pii', { pii: true }],
  ['array pii', { pii: [] }],
  ['unknown pii key', { pii: { phone: true } }],
  ['non-boolean pii email', { pii: { email: 1 } }]
]) {
  test('redactSecrets rejects options with ' + label, () => {
    throwsCode(() => redactSecrets('x', options), label === 'non-array extraSecrets' || label === 'too many extraSecrets' || label === 'empty extra secret' || label === 'long extra secret' || label === 'numeric extra secret' ? CODE.INVALID_OPTIONS : CODE.INVALID_OPTIONS);
  });
}

for (const [name, input, expected] of [
  ['authorization bearer', 'Authorization: Bearer abcdefgh12345678', 'Authorization: Bearer ' + R],
  ['lowercase bearer', 'authorization: bearer abcdefgh12345678', 'authorization: bearer ' + R],
  ['standalone bearer', 'bearer abcdefgh12345678', 'bearer ' + R],
  ['authorization basic', 'Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==', 'Authorization: Basic ' + R],
  ['lowercase basic', 'authorization: basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==', 'authorization: basic ' + R],
  ['bearer JWT shaped', 'Bearer ' + shapedJwt(), 'Bearer ' + R],
  ['bearer punctuation token', 'Bearer abc-def_123', 'Bearer ' + R],
  ['multiple spaces', 'Bearer   abcdefgh12345678', 'Bearer   ' + R],
  ['tab after bearer', 'Bearer\tabcdefgh12345678', 'Bearer\t' + R],
  ['text after token', 'Bearer abcdefgh12345678 done', 'Bearer ' + R + ' done']
]) {
  test('auth token redaction: ' + name, () => {
    assert.equal(redactSecrets(input), expected);
  });
}

for (const [name, input] of [
  ['bearer prose of', 'bearer of good news'],
  ['basic prose authentication', 'basic authentication'],
  ['bearer short token', 'Bearer abc'],
  ['embedded bearer word', 'xBearer abcdefgh12345678'],
  ['basic short token', 'Basic abc']
]) {
  test('auth token high precision negative: ' + name, () => {
    assert.equal(redactSecrets(input), input);
  });
}

for (const [name, input, expected] of [
  ['https user pass', 'https://user:pass@example.com/path', 'https://' + R + '@example.com/path'],
  ['http user pass', 'http://user:pass@example.com/path', 'http://' + R + '@example.com/path'],
  ['uppercase scheme', 'HTTPS://user:pass@example.com/path', 'HTTPS://' + R + '@example.com/path'],
  ['user only', 'https://user@example.com/', 'https://' + R + '@example.com/'],
  ['multiple at signs', 'https://a@b@example.com/', 'https://' + R + '@example.com/'],
  ['query after host', 'https://user:pass@example.com/path?q=1', 'https://' + R + '@example.com/path?q=1'],
  ['fragment after host', 'https://user:pass@example.com/#x', 'https://' + R + '@example.com/#x'],
  ['two urls', 'https://u:p@a.test/ http://x:y@b.test/', 'https://' + R + '@a.test/ http://' + R + '@b.test/'],
  ['custom scheme', 'mongodb+srv://u:p@example.test/db', 'mongodb+srv://' + R + '@example.test/db'],
  ['empty host still masked', 'https://u:p@/path', 'https://' + R + '@/path']
]) {
  test('URL credential redaction: ' + name, () => {
    assert.equal(redactSecrets(input), expected);
  });
}

for (const [name, input] of [
  ['url without credentials', 'https://example.com/path'],
  ['at in path', 'https://example.com/user@example.com'],
  ['at before scheme', 'user@example.com https://example.com/'],
  ['incomplete scheme', 'https:/user:pass@example.com']
]) {
  test('URL credential high precision negative: ' + name, () => {
    assert.equal(redactSecrets(input), input);
  });
}

for (const [name, input, expected] of [
  ['cookie line end', 'Cookie: session=abcdef; theme=light', 'Cookie: ' + R],
  ['cookie newline', 'Cookie: session=abcdef\nnext', 'Cookie: ' + R + '\nnext'],
  ['lowercase cookie', 'cookie: session=abcdef', 'cookie: ' + R],
  ['set-cookie line end', 'Set-Cookie: session=abcdef; Path=/', 'Set-Cookie: ' + R],
  ['lowercase set-cookie', 'set-cookie: session=abcdef', 'set-cookie: ' + R],
  ['set-cookie crlf', 'Set-Cookie: session=abcdef\r\nnext', 'Set-Cookie: ' + R + '\r\nnext'],
  ['cookie no space', 'Cookie:session=abcdef', 'Cookie:' + R]
]) {
  test('cookie header redaction: ' + name, () => {
    assert.equal(redactSecrets(input), expected);
  });
}

for (const [name, input] of [
  ['cookie prose no colon', 'cookie jar is open'],
  ['cookied key', 'cookied: abcdef'],
  ['set-cookieless', 'set-cookieless: abcdef']
]) {
  test('cookie high precision negative: ' + name, () => {
    assert.equal(redactSecrets(input), input);
  });
}

for (const [name, input, expected] of [
  ['bare jwt', shapedJwt(), R],
  ['jwt in sentence', 'token ' + shapedJwt() + ' end', 'token ' + R + ' end'],
  ['jwt after equals', 'jwt=' + shapedJwt(), 'jwt=' + R],
  ['jwt twice', shapedJwt() + ' ' + shapedJwt(), R + ' ' + R]
]) {
  test('JWT redaction: ' + name, () => {
    assert.equal(redactSecrets(input), expected);
  });
}

for (const [name, input] of [
  ['two-part token', 'abc.def'],
  ['short jwt-shaped token', 'eyJabc.defghijklm.uvwxyz'],
  ['ordinary dotted text', 'aaaaaaaaa.bbbbbbbbb.ccccccccc'],
  ['jwt prefix embedded in word', 'x' + shapedJwt()]
]) {
  test('JWT high precision negative: ' + name, () => {
    assert.equal(redactSecrets(input), input);
  });
}

const pemBody = '-----BEGIN RSA PRIVATE KEY-----\nMIIBsynthetic\n-----END RSA PRIVATE KEY-----';
for (const [name, input, expected] of [
  ['RSA private key block', 'x ' + pemBody + ' y', 'x ' + R + ' y'],
  ['EC private key block', '-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----', R],
  ['OPENSSH private key block', '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----', R],
  ['unterminated private key', 'x -----BEGIN RSA PRIVATE KEY-----\nabc', 'x ' + R],
  ['private key with crlf', '-----BEGIN RSA PRIVATE KEY-----\r\nabc\r\n-----END RSA PRIVATE KEY-----\r\nnext', R + '\r\nnext']
]) {
  test('PEM redaction: ' + name, () => {
    assert.equal(redactSecrets(input), expected);
  });
}

for (const [name, input] of [
  ['public key block', '-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----'],
  ['certificate block', '-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----'],
  ['lowercase private key text', '-----begin rsa private key-----\nabc']
]) {
  test('PEM high precision negative: ' + name, () => {
    assert.equal(redactSecrets(input), input);
  });
}

const vendor = syntheticVendorSecrets();
for (const [name, secret] of Object.entries(vendor)) {
  test('vendor token redaction: ' + name, () => {
    assert.equal(redactSecrets('prefix ' + secret + ' suffix'), 'prefix ' + R + ' suffix');
  });
}

for (const [name, input] of [
  ['aws fragment', 'AKIAABC'],
  ['github fragment', 'ghp_abc'],
  ['stripe fragment', 'sk_live_abc'],
  ['slack fragment', 'xoxb-abc'],
  ['openai fragment', 'sk-abc'],
  ['anthropic fragment', 'sk-ant-abc'],
  ['npm fragment', 'npm_abc'],
  ['pypi fragment', 'pypi-abc'],
  ['google fragment', 'AIzaabc']
]) {
  test('vendor token high precision negative: ' + name, () => {
    assert.equal(redactSecrets(input), input);
  });
}

for (const [name, input, expected] of [
  ['password equals', 'password=abcdef', 'password=' + R],
  ['password colon', 'password: abcdef', 'password: ' + R],
  ['passwd equals', 'passwd=abcdef', 'passwd=' + R],
  ['api key underscore', 'api_key: abcdef', 'api_key: ' + R],
  ['api key hyphen', 'api-key=abcdef', 'api-key=' + R],
  ['api key camel', 'apiKey=abcdef', 'apiKey=' + R],
  ['access token camel', 'accessToken=abcdef', 'accessToken=' + R],
  ['refresh token underscore', 'refresh_token=abcdef', 'refresh_token=' + R],
  ['client secret json', '"client_secret":"abcdef"', '"client_secret":"' + R + '"'],
  ['private key json', '"private_key":"abcdef"', '"private_key":"' + R + '"'],
  ['session id json spaces', '"session_id": "abcdef"', '"session_id": "' + R + '"'],
  ['aws secret key', 'aws_secret_access_key=abcdef', 'aws_secret_access_key=' + R],
  ['single quoted value', "password='abcdef'", "password='" + R + "'"],
  ['value stops at comma', 'token=abcdef, next=1', 'token=' + R + ', next=1'],
  ['value stops at semicolon', 'token=abcdef; next=1', 'token=' + R + '; next=1'],
  ['value stops at ampersand', 'token=abcdef&next=1', 'token=' + R + '&next=1'],
  ['value stops at whitespace', 'token=abcdef next=1', 'token=' + R + ' next=1'],
  ['uppercase key', 'PASSWORD=abcdef', 'PASSWORD=' + R],
  ['mixed separator key', 'a-p-i_k-e-y=abcdef', 'a-p-i_k-e-y=' + R],
  ['x api key header', 'x-api-key: abcdef', 'x-api-key: ' + R]
]) {
  test('generic key-value redaction: ' + name, () => {
    assert.equal(redactSecrets(input), expected);
  });
}

for (const [name, input] of [
  ['passwordless', 'passwordless=abcdef'],
  ['tokenize', 'tokenize=abcdef'],
  ['secretary', 'secretary=abcdef'],
  ['password prose', 'the password is abcdef'],
  ['password short value', 'password=abc'],
  ['token empty value', 'token='],
  ['unrelated key', 'username=abcdef']
]) {
  test('generic key-value high precision negative: ' + name, () => {
    assert.equal(redactSecrets(input), input);
  });
}

for (const [name, input, secret, expected] of [
  ['exact', 'abc def', 'abc', R + ' def'],
  ['regex metacharacters', 'a.b*c', 'a.b*c', R],
  ['all occurrences', 'abc abc', 'abc', R + ' ' + R],
  ['case sensitive exact', 'ABC abc', 'abc', 'ABC ' + R],
  ['url encoded uppercase', 'a%2Fb', 'a/b', R],
  ['url encoded lowercase', 'a%2fb', 'a/b', R],
  ['space percent encoded', 'a%20b', 'a b', R],
  ['unicode uppercase percent', 'x%C3%A9y', 'xéy', R],
  ['unicode lowercase percent', 'x%c3%a9y', 'xéy', R],
  ['overlapping longest first', 'abcdef', 'abcdef', R],
  ['custom replacement exact', 'abc', 'abc', '<mask>']
]) {
  test('extra secret redaction: ' + name, () => {
    const replacement = name === 'custom replacement exact' ? '<mask>' : undefined;
    assert.equal(redactSecrets(input, { extraSecrets: [secret], replacement }), expected);
  });
}

test('extra secret base64 standard form is redacted', () => {
  const secret = 'a b';
  const encoded = Buffer.from(secret, 'utf8').toString('base64');
  assert.equal(encoded, 'YSBi');
  assert.equal(redactSecrets(encoded, { extraSecrets: [secret] }), R);
});

test('extra secret unpadded base64 form is redacted', () => {
  const secret = 'ab';
  const encoded = Buffer.from(secret, 'utf8').toString('base64').replace(/=+$/u, '');
  assert.equal(encoded, 'YWI');
  assert.equal(redactSecrets(encoded, { extraSecrets: [secret] }), R);
});

test('extra secret URL-safe base64 form is redacted', () => {
  const secret = '>>>???';
  const standard = Buffer.from(secret, 'utf8').toString('base64');
  const urlSafe = standard.replace(/\+/g, '-').replace(/\//g, '_');
  assert.notEqual(urlSafe, standard);
  assert.equal(redactSecrets(urlSafe, { extraSecrets: [secret] }), R);
});

test('extra secret unpadded URL-safe base64 form is redacted', () => {
  const secret = '>>>???';
  const standard = Buffer.from(secret, 'utf8').toString('base64');
  const urlSafe = standard.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
  assert.equal(redactSecrets(urlSafe, { extraSecrets: [secret] }), R);
});

test('overlapping extra secrets choose the longest form first', () => {
  const output = redactSecrets('abcdef', { extraSecrets: ['bcd', 'abcdef'] });
  assert.equal(output, R);
  assert.equal(countOccurrences(output, R), 1);
});

test('overlapping extra secrets remain longest first regardless of input order', () => {
  const output = redactSecrets('abcdef', { extraSecrets: ['abcdef', 'bcd'] });
  assert.equal(output, R);
  assert.equal(countOccurrences(output, R), 1);
});

test('non-overlapping extra secrets are all redacted', () => {
  assert.equal(redactSecrets('abc xyz', { extraSecrets: ['abc', 'xyz'] }), R + ' ' + R);
});

test('extra secret does not reprocess replacement text recursively', () => {
  assert.equal(redactSecrets('abc', { extraSecrets: ['abc'], replacement: 'abc' }), 'abc');
});

for (const [name, input, expected] of [
  ['email basic', 'mail a@example.com end', 'mail ' + R + ' end'],
  ['email plus', 'mail first.last+tag@example.co.uk end', 'mail ' + R + ' end'],
  ['ssn valid shape', 'ssn 123-45-6789 end', 'ssn ' + R + ' end'],
  ['ipv4 valid', 'ip 192.168.0.1 end', 'ip ' + R + ' end'],
  ['ipv4 zero', 'ip 0.0.0.0 end', 'ip ' + R + ' end'],
  ['luhn contiguous', 'card 4111111111111111 end', 'card ' + R + ' end'],
  ['luhn spaces', 'card 4111 1111 1111 1111 end', 'card ' + R + ' end'],
  ['luhn hyphens', 'card 4111-1111-1111-1111 end', 'card ' + R + ' end']
]) {
  test('optional PII positive: ' + name, () => {
    assert.equal(redactSecrets(input, { pii: { email: true, ssn: true, ipv4: true, luhnCard: true } }), expected);
  });
}

for (const [name, input] of [
  ['ssn area 000', '000-12-3456'],
  ['ssn area 666', '666-12-3456'],
  ['ssn area 900', '900-12-3456'],
  ['ssn group 00', '123-00-4567'],
  ['ssn serial 0000', '123-45-0000'],
  ['ssn undashed', '123456789'],
  ['ipv4 octet 256', '256.1.1.1'],
  ['ipv4 incomplete', '1.2.3'],
  ['ipv4 too many parts', '1.2.3.4.5'],
  ['luhn invalid checksum', '4111111111111112'],
  ['luhn too short', '411111111111'],
  ['email missing tld', 'a@example'],
  ['email missing host', 'a@.com']
]) {
  test('optional PII high precision negative: ' + name, () => {
    assert.equal(redactSecrets(input, { pii: { email: true, ssn: true, ipv4: true, luhnCard: true } }), input);
  });
}

for (const [name, input] of [
  ['email', 'a@example.com'],
  ['ssn', '123-45-6789'],
  ['ipv4', '192.168.0.1'],
  ['luhn card', '4111111111111111']
]) {
  test('PII remains enabled only by request: ' + name, () => {
    assert.equal(redactSecrets(input), input);
  });
}

test('redaction is deterministic for repeated calls', () => {
  const input = 'Authorization: Bearer abcdefgh12345678 https://u:p@example.test/ token=abcdef';
  assert.equal(redactSecrets(input), redactSecrets(input));
});

test('redaction is idempotent for a second pass', () => {
  const input = 'Authorization: Bearer abcdefgh12345678 token=abcdef';
  const once = redactSecrets(input);
  assert.equal(redactSecrets(once), once);
});

test('custom replacement is used across built-in detectors', () => {
  assert.equal(redactSecrets('token=abcdef', { replacement: '<hidden>' }), 'token=<hidden>');
});
