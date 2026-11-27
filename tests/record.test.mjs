import test from 'node:test';
import assert from 'node:assert/strict';
import { esm, throwsCode, assertNoTerminalControls } from './helpers.mjs';

const { CODE, sanitizeLogRecord } = esm;
const R = '[REDACTED]';

function json(value) {
  return JSON.stringify(value);
}

test('sanitizeLogRecord returns null for null', () => {
  assert.equal(sanitizeLogRecord(null), null);
});

test('sanitizeLogRecord returns null for undefined', () => {
  assert.equal(sanitizeLogRecord(undefined), null);
});

for (const [label, input, expected] of [
  ['string', 'hello', 'hello'],
  ['finite number', 1.5, 1.5],
  ['negative zero', -0, -0],
  ['boolean true', true, true],
  ['boolean false', false, false],
  ['NaN', NaN, 'NaN'],
  ['Infinity', Infinity, 'Infinity'],
  ['negative Infinity', -Infinity, '-Infinity'],
  ['bigint', 10n, '10n'],
  ['negative bigint', -10n, '-10n'],
  ['symbol', Symbol('x'), 'Symbol(x)'],
  ['anonymous symbol', Symbol(), 'Symbol()']
]) {
  test('primitive root conversion: ' + label, () => {
    assert.equal(sanitizeLogRecord(input), expected);
  });
}

test('function root conversion is deterministic', () => {
  function namedFunction() {}
  assert.equal(sanitizeLogRecord(namedFunction), '[Function namedFunction]');
  assert.equal(sanitizeLogRecord(() => {}).startsWith('[Function'), true);
});

test('function with throwing proxy name fails closed to anonymous function marker', () => {
  const input = new Proxy(function synthetic() {}, {
    get() { throw new Error('get trap ran'); }
  });
  assert.equal(sanitizeLogRecord(input), '[Function]');
});

test('revoked proxy function fails closed to anonymous function marker', () => {
  const revoked = Proxy.revocable(function synthetic() {}, {});
  revoked.revoke();
  assert.equal(sanitizeLogRecord(revoked.proxy), '[Function]');
});

for (const [label, options] of [
  ['unknown key', { nope: true }],
  ['bad maxDepth type', { maxDepth: '1' }],
  ['zero maxDepth', { maxDepth: 0 }],
  ['huge maxDepth', { maxDepth: 65 }],
  ['zero maxKeys', { maxKeys: 0 }],
  ['huge maxKeys', { maxKeys: 10001 }],
  ['zero maxArrayLength', { maxArrayLength: 0 }],
  ['huge maxArrayLength', { maxArrayLength: 10001 }],
  ['zero maxNodes', { maxNodes: 0 }],
  ['huge maxNodes', { maxNodes: 100001 }],
  ['non-array sensitiveKeys', { sensitiveKeys: 'x' }],
  ['empty sensitive key', { sensitiveKeys: [''] }],
  ['separator-only sensitive key', { sensitiveKeys: ['___'] }],
  ['non-array redactPaths', { redactPaths: 'user.password' }],
  ['empty redact path string', { redactPaths: [''] }],
  ['empty redact path segment', { redactPaths: [['user', '']] }],
  ['numeric redact path segment', { redactPaths: [['user', 0]] }]
]) {
  test('sanitizeLogRecord rejects options with ' + label, () => {
    throwsCode(() => sanitizeLogRecord({}, options), CODE.INVALID_OPTIONS);
  });
}

test('record output object has a null prototype', () => {
  const output = sanitizeLogRecord({ a: 1 });
  assert.equal(Object.getPrototypeOf(output), null);
  assert.equal(output.a, 1);
});

test('record sanitization does not mutate a frozen input object', () => {
  const input = Object.freeze({ a: Object.freeze({ b: 'x\n' }), c: Object.freeze([1, 2]) });
  const before = json(input);
  const output = sanitizeLogRecord(input);
  assert.equal(json(input), before);
  assert.notEqual(output, input);
  assert.notEqual(output.a, input.a);
});

test('record sanitization copies arrays instead of mutating them', () => {
  const input = [1, { x: 2 }];
  const output = sanitizeLogRecord(input);
  assert.notEqual(output, input);
  assert.notEqual(output[1], input[1]);
  assert.deepEqual(JSON.parse(json(output)), [1, { x: 2 }]);
});

for (const key of [
  'password', 'PASSWORD', 'pass-word', 'pass_word', 'passwd', 'pwd', 'secret', 'token',
  'apiKey', 'api_key', 'API-KEY', 'authorization', 'cookie', 'set-cookie', 'set_cookie',
  'privateKey', 'private_key', 'accessToken', 'access_token', 'refreshToken', 'refresh_token',
  'clientSecret', 'client_secret', 'sessionId', 'session_id', 'ssn', 'creditCard', 'credit_card',
  'csrfToken', 'xsrfToken', 'secretAccessKey', 'awsSecretAccessKey', 'accessKey', 'sessionKey', 'encryptionKey'
]) {
  test('sensitive built-in key is redacted: ' + key, () => {
    const output = sanitizeLogRecord({ [key]: 'do-not-read' });
    assert.equal(output[key] === R || output[Object.keys(output)[0]] === R, true);
  });
}

test('sensitive key is redacted before a throwing getter is read', () => {
  const input = {};
  Object.defineProperty(input, 'password', {
    enumerable: true,
    get() { throw new Error('getter was read'); }
  });
  const output = sanitizeLogRecord(input);
  assert.equal(output.password, R);
});

test('control-obfuscated sensitive key is still redacted', () => {
  const key = 'pass' + String.fromCharCode(0) + 'word';
  const output = sanitizeLogRecord({ [key]: 'secret-value' });
  assert.equal(Object.values(output)[0], R);
});

test('ANSI-obfuscated sensitive key is still redacted', () => {
  const key = 'pass\x1b[31mword';
  const output = sanitizeLogRecord({ [key]: 'secret-value' });
  assert.equal(output.password, R);
});


test('invisible astral format character does not evade sensitive key matching', () => {
  const key = 'pass' + String.fromCodePoint(0xe0020) + 'word';
  const output = sanitizeLogRecord({ [key]: 'secret-value' });
  assert.equal(Object.values(output)[0], R);
});

test('additional sensitiveKeys are honored', () => {
  const output = sanitizeLogRecord({ customField: 'x', nested: { custom_field: 'y' } }, { sensitiveKeys: ['customField'] });
  assert.equal(output.customField, R);
  assert.equal(output.nested.custom_field, R);
});

test('sensitiveKeys matching is case and separator normalized', () => {
  const output = sanitizeLogRecord({ 'Cus-tom_Field': 'x' }, { sensitiveKeys: ['custom field'] });
  assert.equal(output['Cus-tom_Field'], R);
});

for (const [label, redactPaths] of [
  ['dot path', ['user.password']],
  ['array path', [['user', 'password']]],
  ['separator-normalized path', ['user.pass-word']],
  ['array index path', ['users.0.password']]
]) {
  test('redactPaths are honored: ' + label, () => {
    const input = label === 'array index path'
      ? { users: [{ password: 'x', other: 'y' }] }
      : { user: { password: 'x', other: 'y' } };
    const output = sanitizeLogRecord(input, { redactPaths });
    if (label === 'array index path') assert.equal(output.users[0].password, R);
    else assert.equal(output.user.password, R);
  });
}

test('redactPaths do not redact a different path', () => {
  const output = sanitizeLogRecord({ user: { password: 'x' }, admin: { password: 'y' } }, { redactPaths: ['user.password'] });
  assert.equal(output.user.password, R);
  assert.equal(output.admin.password, R);
});

test('redactPaths are exact rather than suffix matched when the key is not sensitive', () => {
  const output = sanitizeLogRecord({ outer: { inner: { custom: 'x' } } }, { redactPaths: ['inner.custom'] });
  assert.equal(output.outer.inner.custom, 'x');
});

for (const key of ['__proto__', 'constructor', 'prototype', 'Constructor', 'Prototype']) {
  test('dangerous object key is omitted: ' + key, () => {
    const input = {};
    Object.defineProperty(input, key, { value: 'x', enumerable: true, configurable: true });
    const output = sanitizeLogRecord(input);
    assert.equal(Object.keys(output).length, 0, json(output));
  });
}

test('JSON.parse proto key does not pollute output or Object.prototype', () => {
  const input = JSON.parse('{"__proto__":{"polluted":true},"safe":1}');
  const output = sanitizeLogRecord(input);
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal(output.safe, 1);
  assert.equal(Object.keys(output).includes('__proto__'), false);
});

test('dangerous key hidden by ANSI sequence is omitted after canonicalization', () => {
  const input = { ['__pro' + '\x1b[31m' + 'to__']: 'x', safe: 1 };
  const output = sanitizeLogRecord(input);
  assert.equal(Object.keys(output).includes('__proto__'), false);
  assert.equal(output.safe, 1);
});

test('object keys are sanitized', () => {
  const output = sanitizeLogRecord({ ['a\nb']: 1 });
  assert.equal(output['a\\nb'], 1);
});

test('object keys are redacted when they contain key-value secrets', () => {
  const output = sanitizeLogRecord({ ['token=abcdef']: 1 });
  assert.equal(output['token=' + R], 1);
});

test('colliding sanitized keys are preserved with deterministic duplicate suffixes', () => {
  const output = sanitizeLogRecord({ ['a\n']: 1, ['a\\n']: 2 });
  assert.equal(output['a\\n'], 1);
  assert.equal(output['a\\n [duplicate 2]'], 2);
});

test('empty object key is preserved', () => {
  const output = sanitizeLogRecord({ '': 1 });
  assert.equal(output[''], 1);
});

test('symbol keys are converted to deterministic string keys', () => {
  const sym = Symbol('hello');
  const output = sanitizeLogRecord({ [sym]: 1 });
  assert.equal(output['Symbol(hello)'], 1);
});

test('string values are sanitized for CWE-117 controls', () => {
  const output = sanitizeLogRecord({ message: 'one\r\ntwo\u2028three' });
  assert.equal(output.message, 'one\\r\\ntwo\\u2028three');
});

test('string values have terminal sequences stripped', () => {
  const output = sanitizeLogRecord({ message: 'red\x1b[31mteam' });
  assert.equal(output.message, 'redteam');
});

test('string values are redacted after terminal canonicalization', () => {
  const output = sanitizeLogRecord({ message: 'Bearer abc\x1b[31mdef123' });
  assert.equal(output.message, 'Bearer ' + R);
});

test('direct secrets are redacted before truncation can expose a prefix boundary', () => {
  const secret = 'abcdefgh12345678';
  const output = sanitizeLogRecord({ message: 'token=' + secret }, { maxLength: 20 });
  assert.equal(output.message.includes(secret), false);
  assert.equal(output.message.includes('abcdefgh'), false);
});

for (const mode of ['escape', 'strip']) {
  test('ANSI-obfuscated extra secret is redacted before truncation in ' + mode + ' mode', () => {
    const secret = 'syntheticSecret1234567890AB';
    const input = 'syn' + '\x1b[31m' + 'theticSecret1234567890AB';
    const output = sanitizeLogRecord({ message: input }, { mode, maxLength: 16, extraSecrets: [secret] });
    assert.equal(output.message, R);
    assert.equal(output.message.includes('synth'), false);
  });
}

test('control-obfuscated extra secret is redacted before truncation in strip mode', () => {
  const secret = 'syntheticSecret1234567890AB';
  const input = 'syn' + String.fromCharCode(0) + 'theticSecret1234567890AB';
  const output = sanitizeLogRecord({ message: input }, { mode: 'strip', maxLength: 16, extraSecrets: [secret] });
  assert.equal(output.message, R);
  assert.equal(output.message.includes('synth'), false);
});

test('PII options apply inside record strings', () => {
  const output = sanitizeLogRecord({ email: 'a@example.com' }, { pii: { email: true }, sensitiveKeys: [] });
  assert.equal(output.email, R);
});

test('URL object userinfo is redacted', () => {
  const output = sanitizeLogRecord({ url: new URL('https://user:pass@example.com/path') });
  assert.equal(output.url, 'https://' + R + '@example.com/path');
});

test('valid Date becomes an ISO string', () => {
  const output = sanitizeLogRecord({ date: new Date('2026-01-02T03:04:05.000Z') });
  assert.equal(output.date, '2026-01-02T03:04:05.000Z');
});

test('invalid Date becomes a deterministic marker', () => {
  const output = sanitizeLogRecord({ date: new Date(NaN) });
  assert.equal(output.date, '[Invalid Date]');
});

test('Map becomes an array of key value pairs', () => {
  const output = sanitizeLogRecord(new Map([['a', 1], ['b', 'x\ny']]));
  assert.deepEqual(JSON.parse(json(output)), [['a', 1], ['b', 'x\\ny']]);
});

test('Map sensitive key redacts its value', () => {
  const output = sanitizeLogRecord(new Map([['password', 'secret-value']]));
  assert.deepEqual(JSON.parse(json(output)), [['password', R]]);
});

test('Map is bounded by maxArrayLength', () => {
  const output = sanitizeLogRecord(new Map([[1, 1], [2, 2], [3, 3]]), { maxArrayLength: 2 });
  assert.deepEqual(JSON.parse(json(output)), [[1, 1], [2, 2], '[Truncated]']);
});

test('Set becomes a bounded array', () => {
  const output = sanitizeLogRecord(new Set([1, 2, 3]), { maxArrayLength: 2 });
  assert.deepEqual(JSON.parse(json(output)), [1, 2, '[Truncated]']);
});

for (const [label, value, expected] of [
  ['Uint8Array', new Uint8Array([1, 2, 3]), [1, 2, 3]],
  ['Int16Array', new Int16Array([-1, 2]), [-1, 2]],
  ['Float64Array', new Float64Array([1.5, 2.5]), [1.5, 2.5]],
  ['BigInt64Array', new BigInt64Array([1n, 2n]), ['1n', '2n']]
]) {
  test('typed array conversion: ' + label, () => {
    assert.deepEqual(JSON.parse(json(sanitizeLogRecord(value))), expected);
  });
}

test('typed arrays are bounded by maxArrayLength', () => {
  const output = sanitizeLogRecord(new Uint8Array([1, 2, 3]), { maxArrayLength: 2 });
  assert.deepEqual(JSON.parse(json(output)), [1, 2, '[Truncated]']);
});

test('DataView becomes a deterministic marker', () => {
  assert.equal(sanitizeLogRecord(new DataView(new ArrayBuffer(4))), '[DataView]');
});

test('Error preserves name message code stack and cause', () => {
  const error = new Error('bad\nmessage');
  error.code = 'E_TEST';
  error.stack = 'Error: bad\nmessage\n    at synthetic';
  error.cause = { password: 'secret-value' };
  const output = sanitizeLogRecord(error);
  assert.equal(output.name, 'Error');
  assert.equal(output.message, 'bad\\nmessage');
  assert.equal(output.code, 'E_TEST');
  assert.equal(output.stack.includes('\n'), false);
  assert.equal(output.cause.password, R);
});

test('Error cause circular reference is bounded', () => {
  const error = new Error('bad');
  error.cause = error;
  const output = sanitizeLogRecord(error);
  assert.equal(output.cause, '[Circular]');
});

test('AggregateError errors are preserved recursively and sanitized', () => {
  const inner = new Error('inner\nmessage');
  inner.stack = 'synthetic inner stack';
  const aggregate = new AggregateError([inner], 'outer\nmessage');
  const output = sanitizeLogRecord(aggregate);
  assert.equal(output.name, 'AggregateError');
  assert.equal(output.message, 'outer\\nmessage');
  assert.equal(Array.isArray(output.errors), true);
  assert.equal(output.errors.length, 1);
  assert.equal(output.errors[0].message, 'inner\\nmessage');
  assert.equal(output.errors[0].stack, 'synthetic inner stack');
});

test('Error custom enumerable properties are copied through the safe record pipeline', () => {
  const error = new Error('bad');
  error.details = { token: 'synthetic-token-value', safe: 'ok\nvalue' };
  error.requestId = 'req-1';
  const output = sanitizeLogRecord(error);
  assert.equal(output.requestId, 'req-1');
  assert.equal(output.details.token, R);
  assert.equal(output.details.safe, 'ok\\nvalue');
});

test('Error custom dangerous properties are omitted', () => {
  const error = new Error('bad');
  Object.defineProperty(error, '__proto__', { value: { polluted: true }, enumerable: true, configurable: true });
  const output = sanitizeLogRecord(error);
  assert.equal(Object.keys(output).includes('__proto__'), false);
  assert.equal(Object.prototype.polluted, undefined);
});

test('direct circular object reference is bounded', () => {
  const input = { a: 1 };
  input.self = input;
  const output = sanitizeLogRecord(input);
  assert.equal(output.self, '[Circular]');
});

test('indirect circular object reference is bounded', () => {
  const a = { name: 'a' };
  const b = { name: 'b', a };
  a.b = b;
  const output = sanitizeLogRecord(a);
  assert.equal(output.b.a, '[Circular]');
});

test('circular array reference is bounded', () => {
  const input = [1];
  input.push(input);
  const output = sanitizeLogRecord(input);
  assert.deepEqual(JSON.parse(json(output)), [1, '[Circular]']);
});

test('repeated non-circular object is copied twice', () => {
  const shared = { x: 1 };
  const output = sanitizeLogRecord({ a: shared, b: shared });
  assert.equal(output.a.x, 1);
  assert.equal(output.b.x, 1);
  assert.notEqual(output.a, output.b);
});

test('deep nesting is bounded by maxDepth', () => {
  const input = { l1: { l2: { l3: { value: 'x' } } } };
  const output = sanitizeLogRecord(input, { maxDepth: 2 });
  assert.equal(output.l1.l2.l3, '[MaxDepth]');
});

test('500-level hostile nesting does not overflow the call stack', () => {
  const root = {};
  let cursor = root;
  for (let i = 0; i < 500; i += 1) {
    cursor.next = {};
    cursor = cursor.next;
  }
  cursor.value = 'end';
  const output = sanitizeLogRecord(root, { maxDepth: 12 });
  let current = output;
  for (let i = 0; i < 12; i += 1) current = current.next;
  assert.equal(current.next, '[MaxDepth]');
});

test('objects at maxDepth can still expose primitive values', () => {
  const output = sanitizeLogRecord({ l1: { l2: { value: 'x' } } }, { maxDepth: 2 });
  assert.equal(output.l1.l2.value, 'x');
});

test('maxKeys bounds object expansion and adds a count marker', () => {
  const output = sanitizeLogRecord({ a: 1, b: 2, c: 3 }, { maxKeys: 2 });
  assert.equal(output.a, 1);
  assert.equal(output.b, 2);
  assert.equal(output.c, undefined);
  assert.equal(output['[truncated]'], '1 more');
});

test('maxKeys counts symbol keys too', () => {
  const output = sanitizeLogRecord({ a: 1, [Symbol('s')]: 2 }, { maxKeys: 1 });
  assert.equal(output.a, 1);
  assert.equal(output['[truncated]'], '1 more');
});

test('maxArrayLength bounds arrays and appends a marker', () => {
  const output = sanitizeLogRecord([1, 2, 3, 4], { maxArrayLength: 3 });
  assert.deepEqual(JSON.parse(json(output)), [1, 2, 3, '[Truncated]']);
});

test('maxNodes bounds total expansion', () => {
  const output = sanitizeLogRecord({ a: 1, b: 2 }, { maxNodes: 1 });
  assert.equal(output.a, '[Truncated]');
  assert.equal(output.b, '[Truncated]');
});

test('sparse array holes become null like JSON-compatible data', () => {
  const input = [];
  input.length = 2;
  const output = sanitizeLogRecord(input);
  assert.deepEqual(JSON.parse(json(output)), [null, null]);
});

test('throwing getter becomes an unreadable marker', () => {
  const input = {};
  Object.defineProperty(input, 'unsafe', {
    enumerable: true,
    get() { throw new Error('boom'); }
  });
  const output = sanitizeLogRecord(input);
  assert.equal(output.unsafe, '[Unreadable]');
});

test('fake Map tag object fails closed instead of throwing', () => {
  const input = {};
  Object.defineProperty(input, Symbol.toStringTag, { value: 'Map' });
  const output = sanitizeLogRecord(input);
  assert.equal(output, '[Unreadable]');
});

test('record output remains JSON serializable for mixed supported types', () => {
  const input = {
    date: new Date('2026-01-01T00:00:00Z'),
    map: new Map([['a', 1]]),
    set: new Set([1]),
    bytes: new Uint8Array([1]),
    bigint: 1n,
    error: Object.assign(new Error('x'), { stack: 'synthetic' })
  };
  const output = sanitizeLogRecord(input);
  assert.doesNotThrow(() => JSON.stringify(output));
});

test('record string output contains no terminal controls', () => {
  const output = sanitizeLogRecord({ x: 'a\x1b[31m\n\u2028b' });
  assertNoTerminalControls(output.x);
});
