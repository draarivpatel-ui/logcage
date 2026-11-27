# Contributing to logcage

Thanks for helping make application logs safer. This project is deliberately small and dependency free, so contributions are reviewed with an emphasis on correctness, clarity and auditability.

## Ground rules

- Zero runtime dependencies. Shipped library code must not import third-party packages.
- No network calls, subprocesses or dynamic code evaluation in library code.
- Every behavior change needs a deterministic test. No network, no sleeps and no reliance on wall-clock time except bounded performance regression checks.
- Keep ESM, CJS and the TypeScript definitions in sync. Generate CJS with `node scripts/build-cjs.mjs` and verify it with `node scripts/build-cjs.mjs --check`.
- Never fixture a real token, cookie, password, private key or real personal data. Construct synthetic shaped values in tests.
- Use ASCII punctuation in prose. No em dashes or en dashes.

## Development setup

No install step is required. The package has no dependencies.

```sh
node --version        # 18 or newer
npm test              # node --test tests/*.test.mjs
node scripts/build-cjs.mjs --check
npm pack --dry-run
```

The suite covers CWE-117 input, terminal escape sequences, Unicode spoofing controls, secret and PII redaction, structured records, circular and oversized inputs, deterministic performance bounds, ESM/CJS parity, TypeScript declaration surface and repository hygiene. A change is not done until every test passes.

Windows contributors should run the test command from Git Bash. The explicit `tests/*.test.mjs` glob is kept for the project packaging standard, CI invokes it with `shell: bash`, and Node 18 does not expand glob patterns itself when the Windows command shell passes the wildcard through literally.

## Project layout

```text
src/index.mjs         ESM implementation and source of truth
scripts/build-cjs.mjs deterministic CommonJS generator
cjs/index.cjs         generated CommonJS entry point
types/index.d.ts      strict TypeScript declarations
tests/*.test.mjs      node:test suites
tests/helpers.mjs     shared fixtures and assertion helpers
```

## How to propose a change

1. Open an issue describing the behavior or vulnerability you are addressing. For a security bug, follow SECURITY.md instead of opening a public issue.
2. Add a failing test first. Name it after the specific vector or behavior.
3. Make the smallest change that fixes it. Prefer explicit character-code checks over clever regex composition.
4. Run `npm test` and report the exact count.
5. In your pull request, explain the attack scenario and why the fix generalizes beyond the single example.

## Commit and PR style

- Use plain, descriptive commit subjects.
- Do not add badge edits, formatting churn or unrelated refactors to security fixes.
- If a change alters an error code or a public option, update README.md and types/index.d.ts in the same commit.

## Good first contributions

See GOOD_FIRST_ISSUES.md for 10 scoped, modular tasks. Each is independent and has an explicit acceptance checklist. Claim one by commenting on the corresponding issue before starting.

## Code of conduct

Be respectful and assume good intent. Review the code, not the person. Harassment of any kind is not welcome.
