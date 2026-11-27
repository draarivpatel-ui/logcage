import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import { formatSafeJsonLog, redactSecrets, sanitizeLogLine } from '../src/index.mjs';

const ALPHA_NUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const SAFE_CHARS = (ALPHA_NUM + ' .,_-').split('');
const TOKEN_CHARS = (ALPHA_NUM + '-._~+/=').split('');

function stringFrom(chars, minLength, maxLength) {
  return fc.array(fc.constantFrom(...chars), { minLength, maxLength }).map((items) => items.join(''));
}

function mixedToken() {
  return fc.array(fc.integer({ min: 0, max: TOKEN_CHARS.length - 1 }), { minLength: 24, maxLength: 40 })
    .map((indexes) => indexes.map((value, index) => TOKEN_CHARS[(value + index * 17) % TOKEN_CHARS.length]).join(''));
}

function hasUnsafeOutputChar(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
    if (code >= 0xd800 && code <= 0xdfff) return true;
    if (code === 0x2028 || code === 0x2029) return true;
    if (code >= 0x202a && code <= 0x202e) return true;
    if (code >= 0x2066 && code <= 0x2069) return true;
  }
  return false;
}

test('positive: printable benign log text is preserved', () => {
  fc.assert(fc.property(stringFrom(SAFE_CHARS, 0, 180), (input) => {
    assert.equal(sanitizeLogLine(input), input);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: control and terminal mutations cannot split or control log lines', () => {
  const attack = fc.constantFrom(
    '\n', '\r', '\u2028', '\u2029', '\u0000', '\u007f',
    '\u001b[31m', '\u001b[2J', '\u001b]52;c;SGVsbG8=\u0007',
    '\u001b]8;;https://evil.example\u001b\\', '\u202e', '\u2066'
  );
  fc.assert(fc.property(
    fc.string({ maxLength: 90 }),
    attack,
    fc.string({ maxLength: 90 }),
    (before, hostile, after) => {
      const output = sanitizeLogLine(before + hostile + after);
      assert.equal(hasUnsafeOutputChar(output), false);
      assert.ok(output.length <= 4096);
    }
  ), { seed: 20261127, numRuns: 120 });
});

test('positive: ordinary prose is not over-redacted', () => {
  const word = fc.constantFrom('ordinary', 'log', 'message', 'user', 'completed', 'checkout', 'bearer', 'of', 'good', 'news');
  const prose = fc.array(word, { minLength: 2, maxLength: 8 }).map((words) => words.join(' '));
  fc.assert(fc.property(prose, (input) => {
    assert.equal(redactSecrets(input), input);
  }), { seed: 20261127, numRuns: 80 });
});

test('negative: bearer credentials are redacted without exposing the token', () => {
  fc.assert(fc.property(mixedToken(), (token) => {
    const input = 'Authorization: Bearer ' + token;
    const output = redactSecrets(input);
    assert.equal(output, 'Authorization: Bearer [REDACTED]');
    assert.equal(output.includes(token), false);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: NDJSON output stays one line and never carries credential material', () => {
  const hostileMessage = fc.constantFrom('first\nsecond', 'esc\u001b[31m', 'reverse\u202evalue', 'plain message');
  fc.assert(fc.property(hostileMessage, mixedToken(), (message, token) => {
    const line = formatSafeJsonLog('info', message, {
      authorization: 'Bearer ' + token
    }, {
      timestamp: '2026-01-01T00:00:00.000Z'
    });
    assert.equal(hasUnsafeOutputChar(line), false);
    assert.equal(line.includes(token), false);
    const parsed = JSON.parse(line);
    assert.equal(parsed.ts, '2026-01-01T00:00:00.000Z');
    assert.equal(parsed.level, 'info');
    assert.equal(typeof parsed.msg, 'string');
  }), { seed: 20261127, numRuns: 100 });
});
