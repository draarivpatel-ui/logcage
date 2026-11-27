# logcage

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draarivpatel-ui/logcage/badge)](https://scorecard.dev/viewer/?uri=github.com/draarivpatel-ui/logcage)

Zero-dependency CWE-117 log injection, terminal escape sanitization and automatic secret redaction for Node.js.

`logcage` is a small, auditable security library for applications that write untrusted values into text logs. It neutralizes line breaks, terminal control sequences, bidirectional overrides, invisible format characters and lone surrogates; redacts common credential shapes and caller-supplied secrets; sanitizes structured records without mutating them; and emits single-line NDJSON entries that cannot be split into multiple log lines by input-controlled characters. It works in ESM and CommonJS with strict TypeScript declarations and no runtime dependencies.

- **Zero dependencies.** No runtime or development dependencies and no install scripts.
- **Dual module.** Native ESM (`import`) and CommonJS (`require`) entry points generated from one source of truth.
- **Fail closed.** Non-string input to string APIs, invalid options, unknown option keys and oversized NDJSON output throw `LogCageError`.
- **Linear scanning.** The terminal and control-character sanitizer is a character-code state machine, not a backtracking regex parser.
- **Terminal sequence removal.** CSI, OSC, DCS, SOS, PM and APC sequences, including OSC-8 hyperlinks and OSC-52 clipboard writes, are removed atomically.
- **Secret masking.** Authorization tokens, cookies, URL userinfo, JWTs, PEM private key blocks, common vendor token shapes and caller-supplied secrets are replaced with `[REDACTED]`.
- **Structured defense.** Sensitive keys are redacted, dangerous object keys are omitted, circular references are bounded, and depth, key, array and node limits are enforced.

**Tests:** 726 passing with `npm test` (Node 18+).

## Install

```sh
npm install logcage
```

No install scripts, no native builds, no transitive dependencies.

## Quick start

### ESM

```js
import { createLogCage } from 'logcage';

const log = createLogCage({
  maxLength: 2048,
  extraSecrets: [process.env.INTERNAL_SIGNING_SECRET].filter(Boolean),
  pii: { email: true, luhnCard: true }
});

const line = log.json('info', 'user completed checkout', {
  userId: 1234,
  email: 'person@example.test',
  userAgent: req.headers['user-agent']
});

process.stdout.write(line + '\n');
```

### CommonJS

```js
const { sanitizeLogLine, redactSecrets, formatSafeJsonLog } = require('logcage');
```

## Core API

### `sanitizeLogLine(input, options?)`

Returns a single-line string. Input must be a string. Non-string input is rejected because converting arbitrary objects with `String(input)` can execute attacker-controlled conversion methods.

The scanner handles these input classes:

- CR, LF, NEL, U+2028 and U+2029.
- NUL, C0 controls, DEL and C1 controls.
- ANSI CSI sequences, including the 8-bit C1 CSI form.
- OSC sequences terminated by BEL or ST, including OSC-8 hyperlinks and OSC-52 clipboard writes.
- DCS, SOS, PM and APC string controls in both 7-bit and 8-bit forms.
- Lone ESC and other terminal escape sequences.
- Unicode bidirectional controls, zero-width and format spoofing characters, noncharacters and lone UTF-16 surrogates.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `mode` | `'escape'` | `'escape'` renders unsafe scalar characters as visible escapes such as `\n` or `\u2028`. `'strip'` removes them. Terminal sequences are removed atomically in both modes. |
| `maxLength` | `4096` | Maximum output length in UTF-16 code units, including the truncation marker. |
| `truncationMarker` | `'[truncated]'` | Marker appended when visible output exceeds the reserved output capacity. The marker may not contain controls, format characters or lone surrogates. |

Example:

```js
sanitizeLogLine('safe\nnext\x1b[31mred');
// 'safe\\nnextred'
```

The output length never exceeds `maxLength`. The scanner still consumes terminal-control state correctly after the output cap is reached, so trailing input cannot change the already bounded output.

### `redactSecrets(text, options?)`

Redacts sensitive values in a string without otherwise sanitizing it. This function is intentionally composable: use `sanitizeLogLine`, `sanitizeLogRecord`, `formatSafeJsonLog` or a configured guard when output also needs CWE-117 and terminal protection.

Built-in detectors cover:

- `Authorization: Bearer ...` and `Authorization: Basic ...` header tokens. Standalone Bearer or Basic uses are redacted when they have a token-like shape; the Authorization header context is stricter and redacts every non-empty token.
- `Cookie:` and `Set-Cookie:` values through the end of their line.
- URL userinfo, so `https://user:pass@example.test/path` becomes `https://[REDACTED]@example.test/path`.
- Three-part JSON Web Tokens with a JSON-looking `eyJ` header segment.
- `-----BEGIN ... PRIVATE KEY-----` blocks. A complete block is replaced through its matching END marker; an unterminated block is replaced through end of input.
- Common AWS access key id, GitHub, Stripe, Slack, OpenAI, Anthropic, npm, PyPI and Google API token shapes.
- Common key-value forms such as `password=...`, `api_key: ...`, `accessToken=...` and JSON-style `"client_secret":"..."`.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `replacement` | `'[REDACTED]'` | Replacement text. Controls, format characters and lone surrogates are rejected. |
| `extraSecrets` | `[]` | Up to 64 exact caller secrets, each up to 4096 UTF-16 code units. Matches include the exact value, percent-encoding with case-insensitive hex digits, form encoding with `+` for spaces, standard base64, unpadded standard base64, URL-safe base64 and unpadded URL-safe base64. Longer forms are replaced before shorter overlapping forms. |
| `pii` | all false | Optional detectors. `email`, `luhnCard`, `ssn` and `ipv4` are independent booleans. |

PII detectors are conservative:

- Email uses a bounded address-shaped pattern.
- `luhnCard` redacts only 13 to 19 digit sequences, optionally separated by single spaces or hyphens, whose Luhn checksum is valid.
- `ssn` accepts dashed values only and excludes invalid area, group and serial combinations.
- `ipv4` accepts four decimal octets from 0 through 255.

### `sanitizeLogRecord(record, options?)`

Deeply copies an untrusted structured log value into JSON-compatible data without mutating the input. Plain object outputs have a null prototype. Keys are sanitized and redacted with the same string pipeline as values. `__proto__`, `constructor` and `prototype` keys are omitted case-insensitively before output object creation.

Sensitive values are redacted by key name before their value is read. Built-in normalized key names include password, passwd, secret, token, API key, authorization, cookie, Set-Cookie, private key, access token, refresh token, client secret, session id, SSN and credit card forms. Matching is case-insensitive and ignores underscores, hyphens, dots, spaces and tabs. Add names with `sensitiveKeys` and exact structural locations with `redactPaths`.

Type handling:

| Input type | Output |
| --- | --- |
| string | sanitized then redacted single-line string |
| finite number, boolean, null | unchanged |
| `NaN`, `Infinity`, `-Infinity` | corresponding string spelling |
| `bigint` | decimal string with a trailing `n` |
| `undefined` | `null` |
| `symbol` | sanitized `Symbol(description)` text |
| function | sanitized `[Function name]` or `[Function]` text |
| `Error` | object preserving sanitized `name`, `message`, optional `code`, optional sanitized `stack`, recursive `errors` and `cause`, plus enumerable custom properties through the same safe pipeline |
| `Date` | ISO string, or `[Invalid Date]` |
| `URL` | sanitized and redacted href, including userinfo redaction |
| array | array bounded by `maxArrayLength` |
| typed array | array bounded by `maxArrayLength`; `DataView` becomes `[DataView]` |
| `Map` | array of `[key, value]` pairs bounded by `maxArrayLength` |
| `Set` | array bounded by `maxArrayLength` |
| circular object or array | `[Circular]` |
| object beyond depth or node budget | `[MaxDepth]` or `[Truncated]` |
| other object | null-prototype object of enumerable own keys |

Limits:

| Option | Default | Meaning |
| --- | --- | --- |
| `maxDepth` | `12` | Maximum object nesting depth. |
| `maxKeys` | `200` | Maximum own enumerable keys processed per object. Extra keys are represented by a `[truncated]` marker property. |
| `maxArrayLength` | `200` | Maximum entries processed per array, typed array, Map or Set. Extra entries are represented by a `[Truncated]` element. |
| `maxNodes` | `2000` | Maximum total container and child nodes expanded in one record. |
| `sensitiveKeys` | `[]` | Additional normalized key names to redact. |
| `redactPaths` | `[]` | Dot-separated paths or arrays of path segments. Matching is exact and normalized. |

The function never invokes `toJSON`, never copies prototype properties and never writes to the input. Getter reads are guarded; a throwing getter becomes `[Unreadable]`. Objects from the same process can still have side-effectful property enumeration or proxy behavior, so prefer plain data at trust boundaries.

### `formatSafeJsonLog(level, message, meta?, options?)`

Produces one NDJSON object in deterministic key order:

```json
{"ts":"2026-01-01T00:00:00.000Z","level":"info","msg":"message","meta":{"requestId":"abc"}}
```

The `meta` key is present when a third argument is supplied. Level, timestamp, message and every meta string pass through the sanitization and redaction pipeline. The serialized output is checked for line breaks before return. If the UTF-8 serialized size exceeds `maxOutputBytes` (default 262144), the function throws `ERR_LOGCAGE_LIMIT_EXCEEDED` instead of returning a partial line.

`timestamp` may be an ISO string, epoch milliseconds number or valid `Date`. It is still sanitized before serialization. The default timestamp is the current time.

Important calling detail: because `meta` is optional, options are the fourth argument when meta is used. To use options without meta, pass `undefined` explicitly as meta:

```js
formatSafeJsonLog('info', 'started', undefined, {
  timestamp: '2026-01-01T00:00:00.000Z'
});
```

### `createLogCage(options)`

Creates a frozen reusable guard with validated configuration:

```js
const cage = createLogCage({ maxLength: 2048 });

cage.line(userInput);
cage.redact(text);
cage.record(errorOrObject);
cage.json('info', 'message', { requestId });
const safeConsole = cage.wrapConsole(console);
```

Methods accept per-call option overrides of the same shape as their underlying public function. Unknown override keys are rejected. `wrapConsole(target?)` does not mutate the target. It returns a frozen console-like object whose `log`, `info`, `warn`, `error`, `debug` and `trace` methods sanitize strings, records and errors before forwarding. Missing non-`log` methods fall back to the target's `log` function; a target without `log` is rejected.

## Security guarantees

Within the documented input and option limits:

- `sanitizeLogLine` output contains no raw CR, LF, NEL, U+2028, U+2029, NUL, C0, DEL or C1 control characters.
- Complete and unterminated ANSI/terminal control sequences cannot survive into output as executable sequences.
- Unicode bidi override and isolate controls do not survive into output.
- `formatSafeJsonLog` returns either one newline-free JSON string or no string at all.
- Structured strings are redacted after terminal and control canonicalization but before output truncation, so a truncation boundary cannot expose the prefix of a canonicalized caller-supplied secret.
- Record sanitization does not mutate its input and strips keys that are dangerous for object construction.
- Options and errors never echo raw untrusted log text or secret values.
- Scanning is iterative or uses bounded, non-nested patterns. The line sanitizer's terminal parser is a character-code state machine.

## Scope and limitations

- `redactSecrets` is not a perfect secret scanner. It uses high-precision shapes and caller-supplied exact secrets rather than entropy guessing. Unknown token formats can still leak if the application logs them outside a sensitive record key.
- Standalone `redactSecrets` does not remove ANSI sequences or line breaks. Compose it with the sanitizer or use `sanitizeLogRecord` or `formatSafeJsonLog` for log output.
- Unicode format-control coverage is intentionally table-driven for cross-version deterministic behavior. Newly assigned Unicode format characters in future standards may require a library update.
- PII detectors are optional and conservative. They are not a general data-loss-prevention system.
- Key-value secret detection expects ASCII `:` or `=` separators. Prose such as "the password is ..." is not treated as a key-value leak.
- Circular references are detected along the active object ancestry. A repeated non-circular object is copied again, subject to `maxNodes`.
- Typed arrays, including Node.js Buffer values, are represented as bounded numeric arrays. They are not decoded as strings for secret detection, so do not log secret-bearing binary data outside a sensitive key.
- Getter methods and proxies are same-process JavaScript objects and can have side effects before this library can inspect them. Use plain data for fully untrusted records.
- This library does not validate log transport integrity, encrypt logs, or protect secrets already stored in a downstream log system.

## Development

No install step is required.

```sh
node --version        # 18 or newer
npm test              # node --test tests/*.test.mjs
node scripts/build-cjs.mjs --check
npm pack --dry-run
```

## License

MIT. See LICENSE.
