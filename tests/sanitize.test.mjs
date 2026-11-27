import test from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { esm, throwsCode, ch, escapeForm, assertNoTerminalControls } from './helpers.mjs';

const { CODE, sanitizeLogLine } = esm;

test('sanitizeLogLine leaves ordinary ASCII unchanged', () => {
  assert.equal(sanitizeLogLine('plain ascii 123 !@#$%^&*()'), 'plain ascii 123 !@#$%^&*()');
});

test('sanitizeLogLine leaves ordinary Unicode text unchanged', () => {
  assert.equal(sanitizeLogLine('hello café 東京 مرحبا'), 'hello café 東京 مرحبا');
});

test('sanitizeLogLine leaves a valid astral surrogate pair unchanged', () => {
  assert.equal(sanitizeLogLine('music \u{1f600} end'), 'music \u{1f600} end');
});

for (const [label, value] of [
  ['undefined', undefined], ['null', null], ['number', 1], ['boolean', true],
  ['object', {}], ['array', []], ['bigint', 1n], ['symbol', Symbol('x')]
]) {
  test('sanitizeLogLine rejects ' + label + ' input', () => {
    throwsCode(() => sanitizeLogLine(value), CODE.INVALID_INPUT);
  });
}

for (const [label, options] of [
  ['unknown key', { nope: true }],
  ['bad mode', { mode: 'remove' }],
  ['numeric mode', { mode: 1 }],
  ['fractional maxLength', { maxLength: 10.5 }],
  ['small maxLength', { maxLength: 4 }],
  ['huge maxLength', { maxLength: 1048577 }],
  ['empty marker', { truncationMarker: '' }],
  ['long marker', { truncationMarker: 'x'.repeat(65) }],
  ['newline marker', { truncationMarker: 'bad\n' }],
  ['escape marker', { truncationMarker: 'bad\x1b' }],
  ['bidi marker', { truncationMarker: 'bad\u202e' }],
  ['lone surrogate marker', { truncationMarker: 'bad\ud800' }],
  ['marker larger than max', { maxLength: 16, truncationMarker: 'x'.repeat(16) }]
]) {
  test('sanitizeLogLine rejects options with ' + label, () => {
    throwsCode(() => sanitizeLogLine('x', options), CODE.INVALID_OPTIONS);
  });
}

for (const [name, cp] of [
  ['LF', 10], ['CR', 13], ['NEL', 0x85], ['LINE SEPARATOR', 0x2028], ['PARAGRAPH SEPARATOR', 0x2029]
]) {
  test('escape mode neutralizes ' + name, () => {
    assert.equal(sanitizeLogLine('a' + ch(cp) + 'b'), 'a' + escapeForm(cp) + 'b');
  });
  test('strip mode removes ' + name, () => {
    assert.equal(sanitizeLogLine('a' + ch(cp) + 'b', { mode: 'strip' }), 'ab');
  });
}

test('escape mode neutralizes CRLF as two visible escapes', () => {
  assert.equal(sanitizeLogLine('one\r\ntwo'), 'one\\r\\ntwo');
});

for (let cp = 0; cp <= 0x1f; cp += 1) {
  test('escape mode neutralizes C0 control 0x' + cp.toString(16).padStart(2, '0'), () => {
    if (cp === 0x1b) {
      assert.equal(sanitizeLogLine('a' + ch(cp) + 'b'), 'a');
    } else {
      assert.equal(sanitizeLogLine('a' + ch(cp) + 'b'), 'a' + escapeForm(cp) + 'b');
    }
  });
  test('strip mode removes C0 control 0x' + cp.toString(16).padStart(2, '0'), () => {
    assert.equal(sanitizeLogLine('a' + ch(cp) + 'b', { mode: 'strip' }), cp === 0x1b ? 'a' : 'ab');
  });
}

for (let cp = 0x7f; cp <= 0x9f; cp += 1) {
  const sequenceStarter = cp === 0x90 || cp === 0x98 || cp === 0x9b || cp === 0x9d || cp === 0x9e || cp === 0x9f;
  test('escape mode neutralizes DEL or C1 control 0x' + cp.toString(16), () => {
    const expected = sequenceStarter ? 'a' : 'a' + escapeForm(cp) + 'b';
    assert.equal(sanitizeLogLine('a' + ch(cp) + 'b'), expected);
  });
  test('strip mode removes DEL or C1 control 0x' + cp.toString(16), () => {
    assert.equal(sanitizeLogLine('a' + ch(cp) + 'b', { mode: 'strip' }), sequenceStarter ? 'a' : 'ab');
  });
}

for (const [name, input, expected] of [
  ['CSI color', 'a\x1b[31mb', 'ab'],
  ['CSI cursor movement', 'a\x1b[2Jb', 'ab'],
  ['CSI private mode', 'a\x1b[?25lb', 'ab'],
  ['CSI unterminated', 'a\x1b[31;', 'a'],
  ['CSI empty final byte', 'a\x1b[b', 'a'],
  ['8-bit CSI color', 'a\x9b31mb', 'ab'],
  ['8-bit CSI unterminated', 'a\x9b31;', 'a'],
  ['OSC BEL', 'a\x1b]0;title\x07b', 'ab'],
  ['OSC ST', 'a\x1b]0;title\x1b\\b', 'ab'],
  ['OSC 8-bit ST', 'a\x1b]0;title\x9cb', 'ab'],
  ['OSC-8 hyperlink', 'a\x1b]8;;https://example.test\x1b\\label\x1b]8;;\x1b\\b', 'alabelb'],
  ['OSC-52 clipboard write', 'a\x1b]52;c;SGVsbG8=\x07b', 'ab'],
  ['OSC unterminated', 'a\x1b]52;c;SGVsbG8=', 'a'],
  ['8-bit OSC', 'a\x9d0;title\x07b', 'ab'],
  ['DCS', 'a\x1bPpayload\x1b\\b', 'ab'],
  ['8-bit DCS', 'a\x90payload\x9cb', 'ab'],
  ['SOS', 'a\x1bXpayload\x1b\\b', 'ab'],
  ['PM', 'a\x1b^payload\x1b\\b', 'ab'],
  ['APC', 'a\x1b_payload\x1b\\b', 'ab'],
  ['8-bit APC', 'a\x9fpayload\x9cb', 'ab'],
  ['lone ESC end', 'ab\x1b', 'ab'],
  ['ESC sequence final byte', 'a\x1bb', 'a'],
  ['ESC reset', 'a\x1bcb', 'ab'],
  ['ESC save cursor', 'a\x1b7b', 'ab'],
  ['ESC charset', 'a\x1b(0b', 'ab'],
  ['ESC hash sequence', 'a\x1b#8b', 'ab'],
  ['double ESC', 'a\x1b\x1b[31mb', 'ab']
]) {
  test('terminal sequence is stripped: ' + name, () => {
    assert.equal(sanitizeLogLine(input), expected);
  });
}

for (const cp of [
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
  0x2066, 0x2067, 0x2068, 0x2069,
  0x200e, 0x200f, 0x061c
]) {
  test('bidi control U+' + cp.toString(16).toUpperCase() + ' is neutralized', () => {
    assert.equal(sanitizeLogLine('a' + ch(cp) + 'b'), 'a' + escapeForm(cp) + 'b');
    assert.equal(sanitizeLogLine('a' + ch(cp) + 'b', { mode: 'strip' }), 'ab');
  });
}

for (const cp of [
  0x00ad, 0x0600, 0x0605, 0x06dd, 0x070f, 0x0890, 0x0891, 0x08e2,
  0x180e, 0x200b, 0x200c, 0x200d, 0x2060, 0x2064, 0x206a, 0x206f,
  0xfe00, 0xfe0f, 0xfeff, 0xfff9, 0xfffb, 0x110bd, 0x110cd,
  0x13430, 0x1343f, 0x1bca0, 0x1bca3, 0x1d173, 0x1d17a,
  0xe0001, 0xe0020, 0xe007f, 0xe0100, 0xe01ef
]) {
  test('format control U+' + cp.toString(16).toUpperCase() + ' is neutralized', () => {
    assert.equal(sanitizeLogLine('a' + ch(cp) + 'b'), 'a' + escapeForm(cp) + 'b');
  });
}

for (const cp of [0xfdd0, 0xfdef, 0xfffe, 0xffff, 0x1fffe, 0x1ffff, 0x10fffe, 0x10ffff]) {
  test('noncharacter U+' + cp.toString(16).toUpperCase() + ' is neutralized', () => {
    assert.equal(sanitizeLogLine('a' + ch(cp) + 'b'), 'a' + escapeForm(cp) + 'b');
  });
}

for (const [label, value] of [
  ['lone high surrogate', '\ud800'],
  ['lone low surrogate', '\udc00'],
  ['high surrogate before ASCII', '\ud800x'],
  ['low surrogate after ASCII', 'x\udfff'],
  ['two high surrogates', '\ud800\ud800']
]) {
  test('lone surrogate case is escaped: ' + label, () => {
    const output = sanitizeLogLine('a' + value + 'b');
    assert.equal(output.includes(value[0] === 'x' ? '\udfff' : '\ud800'), false);
    assertNoTerminalControls(output);
  });
}

test('strip mode joins text separated only by terminal sequences', () => {
  assert.equal(sanitizeLogLine('sec\x1b[31mret', { mode: 'strip' }), 'secret');
});

test('escape mode also strips terminal sequence bytes atomically', () => {
  assert.equal(sanitizeLogLine('sec\x1b[31mret'), 'secret');
});

test('truncation marker is included in maxLength', () => {
  const output = sanitizeLogLine('x'.repeat(17), { maxLength: 16 });
  assert.equal(output, 'xxxxx[truncated]');
  assert.equal(output.length, 16);
});

test('input exactly at maxLength is not marked truncated', () => {
  assert.equal(sanitizeLogLine('x'.repeat(16), { maxLength: 16 }), 'x'.repeat(16));
});

test('input one over maxLength is marked truncated', () => {
  assert.equal(sanitizeLogLine('x'.repeat(17), { maxLength: 16 }), 'xxxxx[truncated]');
});

test('escape token truncation does not emit a partial escape', () => {
  const output = sanitizeLogLine('x'.repeat(16) + '\n', { maxLength: 16 });
  assert.equal(output, 'xxxxx[truncated]');
  assert.equal(output.endsWith('\\x[truncated]'), false);
  assert.ok(output.length <= 16);
});

test('astral pair is not split by truncation', () => {
  const output = sanitizeLogLine('x'.repeat(16) + '\u{1f600}', { maxLength: 16 });
  assert.equal(output, 'xxxxx[truncated]');
  assert.equal(output.includes('\ud800'), false);
  assert.equal(output.includes('\udc00'), false);
});

test('custom truncation marker is honored', () => {
  const output = sanitizeLogLine('abcdefghijklmnopqrstuvwxyz', { maxLength: 16, truncationMarker: '[cut]' });
  assert.equal(output, 'abcdefghijk[cut]');
  assert.equal(output.length, 16);
});

test('terminal sequence after capacity does not itself count as truncation', () => {
  assert.equal(sanitizeLogLine('abcde\x1b[31m', { maxLength: 16 }), 'abcde');
});

test('unsafe scalar after maxLength counts as truncation in escape mode', () => {
  assert.equal(sanitizeLogLine('x'.repeat(16) + '\n', { maxLength: 16 }), 'xxxxx[truncated]');
});

test('stripped scalar after maxLength does not count as truncation in strip mode', () => {
  assert.equal(sanitizeLogLine('x'.repeat(16) + '\n', { maxLength: 16, mode: 'strip' }), 'x'.repeat(16));
});

test('long visible input remains bounded in strip mode', () => {
  const output = sanitizeLogLine('x'.repeat(1000), { maxLength: 32, mode: 'strip' });
  assert.equal(output.length, 32);
  assert.ok(output.endsWith('[truncated]'));
});

test('empty input returns empty output', () => {
  assert.equal(sanitizeLogLine(''), '');
});

test('only terminal sequences returns empty output', () => {
  assert.equal(sanitizeLogLine('\x1b[31m\x1b]0;x\x07\x90y\x9c'), '');
});

test('100KB pathological control and terminal input is bounded quickly', () => {
  const unit = '\x1b[31m\x1b]52;c;AAAA\x07\x90abc\x1b\\\n\x00\u2028\u202e';
  const input = unit.repeat(Math.ceil(100 * 1024 / unit.length));
  assert.ok(input.length >= 100 * 1024);
  let best = Infinity;
  let output = '';
  for (let round = 0; round < 8; round += 1) {
    const start = performance.now();
    output = sanitizeLogLine(input, { maxLength: 8192 });
    best = Math.min(best, performance.now() - start);
  }
  assert.ok(output.length <= 8192);
  assertNoTerminalControls(output);
  assert.ok(best < 150, '100KB pathological input best-of-eight took ' + best.toFixed(3) + 'ms');
});
