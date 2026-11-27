import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function walk(directory, output = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'coverage') continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(full, output);
    else if (entry.isFile()) output.push(full);
  }
  return output;
}

function trackedTextFiles() {
  return walk(root).filter((file) => {
    const base = path.basename(file);
    return !base.endsWith('.tgz') && !base.endsWith('.log');
  });
}

function readFile(file) {
  return fs.readFileSync(file, 'utf8');
}

test('repository has the required contributor surface files', () => {
  for (const file of [
    'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'GOOD_FIRST_ISSUES.md',
    'LICENSE', '.gitattributes', '.github/workflows/ci.yml',
    '.github/ISSUE_TEMPLATE/bug_report.md',
    '.github/ISSUE_TEMPLATE/feature_request.md',
    '.github/PULL_REQUEST_TEMPLATE.md'
  ]) {
    assert.equal(fs.existsSync(path.join(root, file)), true, file);
  }
});

test('license is the MIT license text', () => {
  const license = readFile(path.join(root, 'LICENSE'));
  assert.match(license, /MIT License/);
  assert.match(license, /Permission is hereby granted/);
  assert.match(license, /logcage contributors/);
});

test('good first issues file contains exactly 10 scoped ideas', () => {
  const text = readFile(path.join(root, 'GOOD_FIRST_ISSUES.md'));
  const count = (text.match(/^## \d+\./gm) || []).length;
  assert.equal(count, 10);
});

test('README reports a numeric verified test count', () => {
  const readme = readFile(path.join(root, 'README.md'));
  assert.match(readme, /\*\*Tests:\*\* [1-9][0-9]+ passing with `npm test`/);
});

test('README test count is at least the required red-team floor', () => {
  const readme = readFile(path.join(root, 'README.md'));
  const match = /\*\*Tests:\*\* ([0-9]+) passing/.exec(readme);
  assert.ok(match, 'missing test count');
  assert.ok(Number(match[1]) >= 300, 'test count below floor');
});

test('README documents honest scope and limitations', () => {
  const readme = readFile(path.join(root, 'README.md'));
  assert.match(readme, /## Scope and limitations/);
  assert.match(readme, /not a perfect secret scanner/);
  assert.match(readme, /not a general data-loss-prevention system/);
  assert.match(readme, /does not validate log transport integrity/);
});

test('README documents terminal sequence behavior', () => {
  const readme = readFile(path.join(root, 'README.md'));
  assert.match(readme, /OSC-8 hyperlinks/);
  assert.match(readme, /OSC-52 clipboard writes/);
  assert.match(readme, /Terminal sequences are removed atomically/);
});

test('README documents that standalone redaction is composable', () => {
  const readme = readFile(path.join(root, 'README.md'));
  assert.match(readme, /Standalone `redactSecrets` does not remove ANSI sequences or line breaks/);
});

test('SECURITY documents private reporting and scope', () => {
  const security = readFile(path.join(root, 'SECURITY.md'));
  assert.match(security, /Report a vulnerability/i);
  assert.match(security, /## Scope/);
  assert.match(security, /out of scope/);
  assert.match(security, /Never include a real token/);
});

test('no tracked file contains em dash or en dash characters', () => {
  const emDash = String.fromCharCode(8212);
  const enDash = String.fromCharCode(8211);
  const offenders = [];
  for (const file of trackedTextFiles()) {
    const text = readFile(file);
    if (text.includes(emDash) || text.includes(enDash)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('no tracked file contains a local absolute user path', () => {
  const offenders = [];
  const unixHome = '/' + 'Users' + '/';
  const windowsHome = 'C:' + '\\' + 'Users' + '\\';
  for (const file of trackedTextFiles()) {
    const text = readFile(file);
    if (text.includes(unixHome) || text.includes(windowsHome)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('no tracked file contains personal contact or address markers', () => {
  const offenders = [];
  const markers = [
    'someone@' + 'gmail.com',
    'handle-redacted' + '286',
    'Exampleton' + ' Manor'
  ];
  for (const file of trackedTextFiles()) {
    const text = readFile(file);
    if (markers.some((marker) => text.includes(marker))) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('no tracked file contains a co-author trailer', () => {
  const trailer = 'Co-' + 'Authored-' + 'By:';
  const offenders = [];
  for (const file of trackedTextFiles()) {
    if (readFile(file).includes(trailer)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('tracked files use LF line endings', () => {
  const offenders = [];
  for (const file of trackedTextFiles()) {
    if (readFile(file).includes('\r\n')) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('package manifest has no install lifecycle scripts', () => {
  const pkg = JSON.parse(readFile(path.join(root, 'package.json')));
  for (const key of ['preinstall', 'install', 'postinstall', 'prepublish', 'prepare']) {
    assert.equal(pkg.scripts[key], undefined, key);
  }
});

test('package manifest keywords include the core security topics', () => {
  const pkg = JSON.parse(readFile(path.join(root, 'package.json')));
  for (const keyword of ['security', 'logging', 'log-injection', 'cwe-117', 'ansi', 'secret-redaction', 'zero-dependency']) {
    assert.ok(pkg.keywords.includes(keyword), keyword);
  }
});

test('gitignore excludes dependency output logs and tarballs', () => {
  const gitignore = readFile(path.join(root, '.gitignore'));
  assert.match(gitignore, /node_modules\//);
  assert.match(gitignore, /\*\.tgz/);
  assert.match(gitignore, /npm-debug\.log\*/);
});

test('contributing documentation forbids real secret fixtures', () => {
  const contributing = readFile(path.join(root, 'CONTRIBUTING.md'));
  assert.match(contributing, /Never fixture a real token/);
  assert.match(contributing, /Zero runtime dependencies/);
});

test('issue templates warn against real secrets', () => {
  const bug = readFile(path.join(root, '.github', 'ISSUE_TEMPLATE', 'bug_report.md'));
  assert.match(bug, /synthetic secrets/i);
  assert.match(bug, /do not paste real tokens/i);
});

test('pull request template requires exact test count and packaging checks', () => {
  const pr = readFile(path.join(root, '.github', 'PULL_REQUEST_TEMPLATE.md'));
  assert.match(pr, /exact test count/);
  assert.match(pr, /npm pack --dry-run/);
  assert.match(pr, /build-cjs\.mjs --check/);
});
