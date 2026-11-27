import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import * as esm from '../src/index.mjs';

const require = createRequire(import.meta.url);
const cjs = require('../cjs/index.cjs');

export { esm, cjs };
export const MODULES = [
  ['ESM', esm],
  ['CJS', cjs]
];

export function throwsCode(fn, code, message) {
  let error;
  try {
    fn();
  } catch (caught) {
    error = caught;
  }
  assert.ok(error, message || 'expected function to throw');
  assert.equal(error.name, 'LogCageError', message);
  assert.equal(error.code, code, message || 'unexpected error code');
  return error;
}

export function ch(cp) {
  return String.fromCodePoint(cp);
}

export function escapeForm(cp) {
  if (cp === 10) return '\\n';
  if (cp === 13) return '\\r';
  if (cp === 9) return '\\t';
  if (cp <= 0xff) return '\\x' + cp.toString(16).padStart(2, '0');
  if (cp <= 0xffff) return '\\u' + cp.toString(16).padStart(4, '0');
  return '\\u{' + cp.toString(16) + '}';
}

export function assertNoRawLineBreaks(value) {
  for (const bad of ['\n', '\r', '\x85', '\u2028', '\u2029']) {
    assert.equal(value.includes(bad), false, 'output contains a raw line break');
  }
}

export function assertNoTerminalControls(value) {
  assert.equal(value.includes('\x1b'), false, 'output contains ESC');
  for (let cp = 0; cp <= 0x1f; cp += 1) {
    assert.equal(value.includes(String.fromCharCode(cp)), false, 'output contains C0 control ' + cp);
  }
  for (let cp = 0x7f; cp <= 0x9f; cp += 1) {
    assert.equal(value.includes(String.fromCharCode(cp)), false, 'output contains DEL or C1 control ' + cp);
  }
  assertNoRawLineBreaks(value);
}

export function shapedJwt() {
  return 'eyJ' + 'a'.repeat(20) + '.' + 'b'.repeat(24) + '.' + 'c'.repeat(24);
}

export function syntheticVendorSecrets() {
  return {
    aws: 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP',
    github: 'gh' + 'p_' + 'A1'.repeat(18),
    githubPat: 'github' + '_pat_' + 'A1_'.repeat(12),
    stripe: 'sk' + '_live_' + 'A1'.repeat(18),
    stripeWebhook: 'wh' + 'sec_' + 'A1'.repeat(18),
    slack: 'xox' + 'b-' + '1234567890-' + 'abcdefghij',
    openai: 'sk-' + 'A1'.repeat(24),
    openaiProject: 'sk-' + 'proj-' + 'A1'.repeat(24),
    anthropic: 'sk-' + 'ant-' + 'A1'.repeat(24),
    npm: 'npm' + '_' + 'A1'.repeat(18),
    pypi: 'pypi' + '-' + 'A1'.repeat(24),
    google: 'AI' + 'za' + 'A1'.repeat(17) + 'A'
  };
}

export function fixedNow() {
  return '2026-01-02T03:04:05.000Z';
}
