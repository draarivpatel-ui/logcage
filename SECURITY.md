# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. [Report a vulnerability privately through GitHub](https://github.com/draarivpatel-ui/logcage/security/advisories/new).

Please include:

- A minimal reproduction that uses synthetic input only.
- The affected project version, commit or action ref, and Node.js version.
- The expected security boundary and the observed violation.
- Logs, output, or proof-of-concept code needed to reproduce the finding, with real secrets removed.

Never include a real token, cookie, password, private key, production log line or real personal data in a report.

Vulnerability handling steps:

1. The maintainer acknowledges the private report within 72 hours.
2. The maintainer reproduces the finding against the latest supported version and confirms severity within 14 days when enough information is available.
3. A fix is developed privately, with regression coverage where practical.
4. The maintainer coordinates the advisory, affected versions, reporter credit and disclosure date with the reporter.
5. The target coordinated disclosure window is 90 days or less from acknowledgment. If more time is needed, the maintainer and reporter agree on a new date before disclosure.

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
