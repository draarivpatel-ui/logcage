# Good first issues

These 10 tasks are intentionally narrow. Each can be completed without changing the public architecture. Before starting, read CONTRIBUTING.md and open or claim the matching issue.

## 1. Unicode format-control matrix

Add a complete character-class test matrix for every format-control range currently handled by the sanitizer. Identify characters by numeric code point and keep the implementation unchanged unless a matrix entry proves a mismatch.

Acceptance checklist:

- Cover the first and last code point of every documented range.
- Separate bidi controls, zero-width controls, tag characters and noncharacters.
- No implementation change without a documented Unicode reference in the pull request.

## 2. OSC termination regression corpus

Add deterministic tests for OSC sequences terminated by BEL, 7-bit ST and 8-bit ST, including OSC-8 and OSC-52 shaped payloads.

Acceptance checklist:

- Include empty, terminated and unterminated forms.
- Prove printable text after the terminator is preserved.
- Prove unterminated payload text is not emitted.

## 3. Key-value detector false-positive corpus

Add a table of benign prose and configuration examples that must not be redacted, alongside synthetic key-value secrets that must be redacted.

Acceptance checklist:

- Cover `tokenize`, `passwordless`, `secretary` and ordinary prose.
- Cover JSON-style quoted keys and query-string separators.
- Do not weaken existing secret detection without maintainer approval.

## 4. TypeScript compile fixture

Add a small TypeScript compile fixture in tests or CI without adding runtime dependencies. If the TypeScript compiler is needed, it must be a development-only CI tool rather than a package dependency.

Acceptance checklist:

- Exercise every public function and option surface.
- Prove `LogCage` method overloads and `WrappedConsole` are typed.
- `dependencies` and `devDependencies` in package.json remain empty.

## 5. Redaction precedence documentation

Document and test what happens when a JWT appears inside a Bearer token, a secret appears inside a URL userinfo component, or two caller-supplied secrets overlap.

Acceptance checklist:

- Examples use only synthetic values.
- Output precedence is deterministic and described in README.md.
- Tests cover longest-first exact extra-secret behavior.

## 6. Cross-module structured record tests

Add tests that sanitize a record through ESM and CJS in both directions and compare JSON serialization, including Error cause, Map, Set and typed arrays.

Acceptance checklist:

- Inputs are frozen before sanitization where practical.
- Outputs are byte-identical after `JSON.stringify`.
- No prototype key is present in either output.

## 7. Package tarball audit automation

Extend the package hygiene test with explicit expectations for the files included by `npm pack --dry-run`.

Acceptance checklist:

- The test does not require network access.
- It verifies source, CJS, types, README, SECURITY, CONTRIBUTING, GOOD_FIRST_ISSUES and LICENSE inclusion.
- It verifies tests and git metadata are not published.

## 8. Unicode-aware truncation tests

Add tests proving truncation never splits a surrogate pair or emits half of an escape token.

Acceptance checklist:

- Use BMP and astral visible characters around the exact capacity boundary.
- Test escape and strip modes.
- Assert the final output length is never above `maxLength`.

## 9. Console wrapper compatibility matrix

Add tests for format strings, multiple arguments, Error objects, circular objects and a target that implements only `log`.

Acceptance checklist:

- The target is never mutated.
- Missing non-log methods fall back to `log`.
- Secret-shaped synthetic strings are redacted before forwarding.

## 10. Deterministic mutation corpus expansion

Add a fixed-seed mutation corpus for hostile control characters, ANSI fragments and redaction-shaped tokens. The goal is crash freedom and stable output invariants, not random coverage that changes between runs.

Acceptance checklist:

- Use a fixed seed and fixed iteration count.
- Assert output has no raw line breaks or terminal control characters.
- Assert no object prototype is polluted.
- Keep total added runtime below 100 ms on a typical development machine.
