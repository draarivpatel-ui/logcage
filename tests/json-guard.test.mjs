import test from 'node:test';
import assert from 'node:assert/strict';
import { esm, throwsCode, fixedNow, assertNoRawLineBreaks, assertNoTerminalControls } from './helpers.mjs';

const { CODE, formatSafeJsonLog, createLogCage, sanitizeLogLine } = esm;
const R = '[REDACTED]';

function parseLine(line) {
  assertNoRawLineBreaks(line);
  return JSON.parse(line);
}

test('formatSafeJsonLog emits deterministic key order', () => {
  const line = formatSafeJsonLog('info', 'hello', { a: 1 }, { timestamp: fixedNow() });
  assert.equal(line, '{"ts":"' + fixedNow() + '","level":"info","msg":"hello","meta":{"a":1}}');
});

test('formatSafeJsonLog omits meta when the argument is not supplied', () => {
  const parsed = parseLine(formatSafeJsonLog('info', 'hello'));
  assert.equal('meta' in parsed, false);
  assert.equal(parsed.level, 'info');
  assert.equal(parsed.msg, 'hello');
  assert.equal(typeof parsed.ts, 'string');
});

test('formatSafeJsonLog represents explicit undefined meta as null', () => {
  const parsed = parseLine(formatSafeJsonLog('info', 'hello', undefined, { timestamp: fixedNow() }));
  assert.equal('meta' in parsed, true);
  assert.equal(parsed.meta, null);
});

for (const [label, level, message] of [
  ['undefined level', undefined, 'x'], ['null level', null, 'x'], ['number level', 1, 'x'],
  ['undefined message', 'info', undefined], ['null message', 'info', null], ['number message', 'info', 1]
]) {
  test('formatSafeJsonLog rejects ' + label, () => {
    throwsCode(() => formatSafeJsonLog(level, message), CODE.INVALID_INPUT);
  });
}

test('formatSafeJsonLog rejects a level that sanitizes to empty', () => {
  throwsCode(() => formatSafeJsonLog('\x1b[31m', 'x', undefined, { mode: 'strip' }), CODE.INVALID_INPUT);
});

test('formatSafeJsonLog allows an empty message', () => {
  assert.equal(parseLine(formatSafeJsonLog('info', '', undefined, { timestamp: fixedNow() })).msg, '');
});

for (const [label, options] of [
  ['bad timestamp type', { timestamp: true }],
  ['invalid Date timestamp', { timestamp: new Date(NaN) }],
  ['infinite numeric timestamp', { timestamp: Infinity }],
  ['empty timestamp', { timestamp: '' }],
  ['long timestamp', { timestamp: 'x'.repeat(129) }],
  ['small maxOutputBytes', { maxOutputBytes: 1000 }],
  ['huge maxOutputBytes', { maxOutputBytes: 4194305 }],
  ['fractional maxOutputBytes', { maxOutputBytes: 1024.5 }]
]) {
  test('formatSafeJsonLog rejects options with ' + label, () => {
    throwsCode(() => formatSafeJsonLog('info', 'x', undefined, options), CODE.INVALID_OPTIONS);
  });
}

test('timestamp string is exact when supplied', () => {
  assert.equal(parseLine(formatSafeJsonLog('info', 'x', undefined, { timestamp: fixedNow() })).ts, fixedNow());
});

test('numeric timestamp is converted to ISO', () => {
  assert.equal(parseLine(formatSafeJsonLog('info', 'x', undefined, { timestamp: 0 })).ts, '1970-01-01T00:00:00.000Z');
});

test('Date timestamp is converted to ISO', () => {
  assert.equal(parseLine(formatSafeJsonLog('info', 'x', undefined, { timestamp: new Date(0) })).ts, '1970-01-01T00:00:00.000Z');
});

test('valid timestamp is not truncated by a small message maxLength', () => {
  const line = formatSafeJsonLog('info', 'x', undefined, { timestamp: fixedNow(), maxLength: 16 });
  assert.equal(parseLine(line).ts, fixedNow());
});

for (const [label, input] of [
  ['CR', '\r'], ['LF', '\n'], ['NEL', '\x85'], ['LS', '\u2028'], ['PS', '\u2029']
]) {
  test('NDJSON neutralizes line break in level: ' + label, () => {
    const line = formatSafeJsonLog('a' + input + 'b', 'x', undefined, { timestamp: fixedNow() });
    assertNoRawLineBreaks(line);
    assert.equal(parseLine(line).level.includes(input), false);
  });
  test('NDJSON neutralizes line break in message: ' + label, () => {
    const line = formatSafeJsonLog('info', 'a' + input + 'b', undefined, { timestamp: fixedNow() });
    assertNoRawLineBreaks(line);
    assert.equal(parseLine(line).msg.includes(input), false);
  });
  test('NDJSON neutralizes line break in meta string: ' + label, () => {
    const line = formatSafeJsonLog('info', 'x', { value: 'a' + input + 'b' }, { timestamp: fixedNow() });
    assertNoRawLineBreaks(line);
    assert.equal(parseLine(line).meta.value.includes(input), false);
  });
}

test('NDJSON neutralizes terminal controls', () => {
  const line = formatSafeJsonLog('info', 'a\x1b[31mb', { x: 'c\x9b32md' }, { timestamp: fixedNow() });
  assertNoTerminalControls(line);
  assert.equal(parseLine(line).msg, 'ab');
  assert.equal(parseLine(line).meta.x, 'cd');
});

test('NDJSON does not allow quote injection to create fields', () => {
  const line = formatSafeJsonLog('info', '","level":"evil', undefined, { timestamp: fixedNow() });
  const parsed = parseLine(line);
  assert.equal(parsed.level, 'info');
  assert.equal(parsed.msg, '","level":"evil');
});

test('NDJSON redacts bearer secrets in message', () => {
  const parsed = parseLine(formatSafeJsonLog('info', 'Bearer abcdefgh12345678', undefined, { timestamp: fixedNow() }));
  assert.equal(parsed.msg, 'Bearer ' + R);
});

test('NDJSON redacts sensitive meta keys', () => {
  const parsed = parseLine(formatSafeJsonLog('info', 'x', { password: 'abc' }, { timestamp: fixedNow() }));
  assert.equal(parsed.meta.password, R);
});

test('NDJSON handles circular meta', () => {
  const meta = {};
  meta.self = meta;
  const parsed = parseLine(formatSafeJsonLog('info', 'x', meta, { timestamp: fixedNow() }));
  assert.equal(parsed.meta.self, '[Circular]');
});

test('NDJSON handles Error meta', () => {
  const error = new Error('bad\ninput');
  error.stack = 'synthetic stack';
  const parsed = parseLine(formatSafeJsonLog('error', 'failed', { error }, { timestamp: fixedNow() }));
  assert.equal(parsed.meta.error.name, 'Error');
  assert.equal(parsed.meta.error.message, 'bad\\ninput');
});

test('oversized NDJSON output fails closed', () => {
  const error = throwsCode(() => formatSafeJsonLog('info', 'x'.repeat(2000), undefined, {
    timestamp: fixedNow(),
    maxOutputBytes: 1024
  }), CODE.LIMIT_EXCEEDED);
  assert.equal(error.limit, 1024);
  assert.equal(error.actual > 1024, true);
});

test('maxOutputBytes is enforced in UTF-8 bytes rather than UTF-16 code units', () => {
  const error = throwsCode(() => formatSafeJsonLog('info', 'é'.repeat(500), undefined, {
    timestamp: fixedNow(),
    maxOutputBytes: 1024
  }), CODE.LIMIT_EXCEEDED);
  assert.equal(error.actual > 1024, true);
});

test('NDJSON redacts an ANSI-obfuscated extra secret before truncation', () => {
  const secret = 'syntheticSecret1234567890AB';
  const input = 'syn' + '\x1b[31m' + 'theticSecret1234567890AB';
  const parsed = parseLine(formatSafeJsonLog('info', input, undefined, {
    timestamp: fixedNow(),
    maxLength: 16,
    extraSecrets: [secret]
  }));
  assert.equal(parsed.msg, R);
});

test('formatSafeJsonLog rejects unknown options', () => {
  throwsCode(() => formatSafeJsonLog('info', 'x', undefined, { nope: true }), CODE.INVALID_OPTIONS);
});

test('createLogCage returns a frozen guard', () => {
  const cage = createLogCage();
  assert.equal(Object.isFrozen(cage), true);
  assert.throws(() => { cage.line = () => 'x'; }, TypeError);
});

test('createLogCage validates options at creation time', () => {
  throwsCode(() => createLogCage({ nope: true }), CODE.INVALID_OPTIONS);
  throwsCode(() => createLogCage({ maxLength: 4 }), CODE.INVALID_OPTIONS);
});

test('guard line uses base maxLength', () => {
  const cage = createLogCage({ maxLength: 16 });
  assert.equal(cage.line('x'.repeat(17)), 'xxxxx[truncated]');
});

test('guard line accepts valid per-call overrides', () => {
  const cage = createLogCage({ maxLength: 32 });
  assert.equal(cage.line('x'.repeat(17), { maxLength: 16 }), 'xxxxx[truncated]');
});

test('guard line rejects irrelevant per-call overrides', () => {
  const cage = createLogCage();
  throwsCode(() => cage.line('x', { maxDepth: 2 }), CODE.INVALID_OPTIONS);
});

test('guard redact uses base extraSecrets', () => {
  const cage = createLogCage({ extraSecrets: ['synthetic-secret'] });
  assert.equal(cage.redact('value synthetic-secret end'), 'value ' + R + ' end');
});

test('guard redact accepts replacement override', () => {
  const cage = createLogCage();
  assert.equal(cage.redact('token=abcdef', { replacement: '<hidden>' }), 'token=<hidden>');
});

test('guard redact rejects irrelevant per-call overrides', () => {
  const cage = createLogCage();
  throwsCode(() => cage.redact('x', { maxKeys: 2 }), CODE.INVALID_OPTIONS);
});

test('guard record uses base sensitiveKeys', () => {
  const cage = createLogCage({ sensitiveKeys: ['custom'] });
  assert.equal(cage.record({ custom: 'x' }).custom, R);
});

test('guard record accepts depth override', () => {
  const cage = createLogCage();
  const output = cage.record({ a: { b: { c: {} } } }, { maxDepth: 1 });
  assert.equal(output.a.b, '[MaxDepth]');
});

test('guard record rejects irrelevant per-call overrides', () => {
  const cage = createLogCage();
  throwsCode(() => cage.record({}, { timestamp: fixedNow() }), CODE.INVALID_OPTIONS);
});

test('guard json uses base timestamp', () => {
  const cage = createLogCage({ timestamp: fixedNow() });
  assert.equal(parseLine(cage.json('info', 'x')).ts, fixedNow());
});

test('guard json accepts maxOutputBytes override', () => {
  const cage = createLogCage({ timestamp: fixedNow() });
  throwsCode(() => cage.json('info', 'x'.repeat(2000), undefined, { maxOutputBytes: 1024 }), CODE.LIMIT_EXCEEDED);
});

test('guard json rejects line-only per-call override mistakes inside options object', () => {
  const cage = createLogCage();
  assert.doesNotThrow(() => cage.json('info', 'x', undefined, { maxLength: 32 }));
});

test('guard methods do not mutate base configuration across calls', () => {
  const cage = createLogCage({ maxLength: 32 });
  cage.line('abcdef', { maxLength: 16 });
  assert.equal(cage.line('abcdef'), 'abcdef');
});


test('guard configuration is isolated from later caller array and object mutation', () => {
  const extraSecrets = ['first-secret'];
  const sensitiveKeys = ['custom'];
  const redactPaths = [['outer', 'inner']];
  const pii = { email: false };
  const cage = createLogCage({ extraSecrets, sensitiveKeys, redactPaths, pii });
  extraSecrets[0] = 'changed-secret';
  sensitiveKeys[0] = 'changed';
  redactPaths[0][0] = 'changed';
  pii.email = true;
  assert.equal(cage.redact('first-secret'), R);
  assert.equal(cage.record({ custom: 'x' }).custom, R);
  assert.equal(cage.record({ outer: { inner: 'x' } }).outer.inner, R);
  assert.equal(cage.redact('a@example.com'), 'a@example.com');
});

test('guard override merging still uses the immutable creation-time configuration', () => {
  const extraSecrets = ['first-secret'];
  const cage = createLogCage({ extraSecrets });
  extraSecrets[0] = 'changed-secret';
  assert.equal(cage.redact('first-secret', { replacement: '<x>' }), '<x>');
});

test('wrapConsole forwards sanitized strings', () => {
  const calls = [];
  const cage = createLogCage();
  const wrapped = cage.wrapConsole({ log: (...args) => calls.push(args) });
  wrapped.log('a\nb\x1b[31m');
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'a\\nb');
});

test('wrapConsole redacts secrets in strings', () => {
  const calls = [];
  const cage = createLogCage();
  const wrapped = cage.wrapConsole({ log: (...args) => calls.push(args) });
  wrapped.log('Bearer abcdefgh12345678');
  assert.equal(calls[0][0], 'Bearer ' + R);
});

test('wrapConsole sanitizes object arguments', () => {
  const calls = [];
  const cage = createLogCage();
  const wrapped = cage.wrapConsole({ log: (...args) => calls.push(args) });
  wrapped.log({ password: 'x', safe: 'a\n' });
  assert.equal(calls[0][0].password, R);
  assert.equal(calls[0][0].safe, 'a\\n');
});

test('wrapConsole preserves primitive number boolean null and undefined arguments', () => {
  const calls = [];
  const cage = createLogCage();
  const wrapped = cage.wrapConsole({ log: (...args) => calls.push(args) });
  wrapped.log(1, true, null, undefined);
  assert.deepEqual(calls[0], [1, true, null, undefined]);
});

test('wrapConsole converts bigint and symbol arguments safely', () => {
  const calls = [];
  const cage = createLogCage();
  const wrapped = cage.wrapConsole({ log: (...args) => calls.push(args) });
  wrapped.log(1n, Symbol('x'));
  assert.equal(calls[0][0], '1n');
  assert.equal(calls[0][1], 'Symbol(x)');
});

test('wrapConsole missing methods fall back to log', () => {
  const calls = [];
  const cage = createLogCage();
  const wrapped = cage.wrapConsole({ log: (...args) => calls.push(['log', ...args]) });
  wrapped.error('x');
  wrapped.trace('y');
  assert.deepEqual(calls, [['log', 'x'], ['log', 'y']]);
});

test('wrapConsole uses method-specific target functions when present', () => {
  const calls = [];
  const target = {
    log: (...args) => calls.push(['log', ...args]),
    error: (...args) => calls.push(['error', ...args])
  };
  const wrapped = createLogCage().wrapConsole(target);
  wrapped.error('x');
  assert.deepEqual(calls, [['error', 'x']]);
});

test('wrapConsole does not mutate the target', () => {
  const target = { log() {} };
  const before = Object.keys(target).join(',');
  const wrapped = createLogCage().wrapConsole(target);
  assert.equal(Object.keys(target).join(','), before);
  assert.notEqual(wrapped, target);
});

test('wrapConsole returns a frozen object', () => {
  const wrapped = createLogCage().wrapConsole({ log() {} });
  assert.equal(Object.isFrozen(wrapped), true);
});

for (const [label, target] of [
  ['null target', null],
  ['number target', 1],
  ['object without log', {}]
]) {
  test('wrapConsole rejects ' + label, () => {
    throwsCode(() => createLogCage().wrapConsole(target), CODE.INVALID_INPUT);
  });
}

test('default console target can be wrapped without throwing', () => {
  const wrapped = createLogCage().wrapConsole();
  assert.equal(typeof wrapped.log, 'function');
});

test('guard and direct sanitizer agree for the same input and options', () => {
  const cage = createLogCage({ maxLength: 32, mode: 'strip' });
  assert.equal(cage.line('a\nb'), sanitizeLogLine('a\nb', { maxLength: 32, mode: 'strip' }));
});
