# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Please report security issues privately using GitHub's "Report a vulnerability" feature on the repository's Security tab. Do not open a public issue for an exploitable finding.

Include:

- A minimal proof of concept using synthetic secrets and synthetic personal data only.
- The affected version and Node.js version.
- The expected security boundary and the observed violation.
- Whether the issue permits log forging, terminal escape injection, secret disclosure, prototype pollution, output-size bypass or a documented limit bypass.

Never include a real token, cookie, password, private key, production log line or real personal data in a report. Use synthetic shaped values that reproduce the behavior.

You should receive an acknowledgement within 7 days. We will work with you on a fix and coordinate disclosure. Please give maintainers a reasonable window to release a patch before public disclosure.

## Scope

The following are in scope:

- Raw CR, LF, NEL, U+2028, U+2029, NUL, C0, DEL or C1 control characters reaching `sanitizeLogLine` output.
- Executable ANSI CSI, OSC, DCS, SOS, PM or APC sequences reaching sanitized output.
- Unicode bidirectional override or isolate controls reaching sanitized output.
- Documented private key block, authorization token, URL userinfo, cookie value, JWT, vendor token or exact extra-secret forms surviving redaction.
- Sensitive record keys being read or copied instead of redacted.
- Prototype pollution through record keys or output object construction.
- Circular-reference, depth, key-count, array-length or node-limit bypasses.
- `formatSafeJsonLog` returning a string containing a line break.
- Raw secrets appearing in errors, `toJSON()` output or other diagnostics.
- Documented output-size or linear-scanning bounds being exceeded disproportionately to input size.

The following are generally out of scope:

- Secrets in formats not covered by the documented detectors and not supplied through `extraSecrets` or sensitive record keys.
- Personal data classes not enabled through the documented PII options.
- An attacker who can already execute JavaScript in the same process or inspect process memory.
- Side effects caused by attacker-controlled getters, proxies or object conversion before plain data reaches the library.
- Resource use within documented input and output size limits that is proportional to input size.
- Format characters assigned by future Unicode versions after the current deterministic table.
- Protection of data already stored in a downstream log system.

## Security design notes

- Terminal-control parsing is a character-code state machine rather than a backtracking regex parser.
- ANSI string controls are removed atomically, including unterminated sequences through end of input.
- Record strings are redacted before and after canonical line sanitization, then truncated only after the final redaction pass, so direct and terminal-control-obfuscated secrets are covered without exposing a truncation-boundary prefix.
- Sensitive record values are redacted before their properties are read.
- Output objects are created with a null prototype and dangerous keys are omitted.
- Errors use fixed reason strings and never echo untrusted input or secret values.
- NDJSON output is size-checked and invariant-checked before it is returned.

## Disclosure history

No published advisories yet. Fixed versions will be listed here with their advisory links.
