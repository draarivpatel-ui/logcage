/** Error codes emitted by logcage. */
export const CODE: Readonly<{
  INVALID_INPUT: 'ERR_LOGCAGE_INVALID_INPUT';
  INVALID_OPTIONS: 'ERR_LOGCAGE_INVALID_OPTIONS';
  LIMIT_EXCEEDED: 'ERR_LOGCAGE_LIMIT_EXCEEDED';
  OUTPUT_INVARIANT: 'ERR_LOGCAGE_OUTPUT_INVARIANT';
}>;

export type LogCageErrorCode =
  'ERR_LOGCAGE_INVALID_INPUT' | 'ERR_LOGCAGE_INVALID_OPTIONS' |
  'ERR_LOGCAGE_LIMIT_EXCEEDED' | 'ERR_LOGCAGE_OUTPUT_INVARIANT';

/** Structured error thrown for invalid input, invalid options and output invariant failures. */
export declare class LogCageError extends Error {
  constructor(code: LogCageErrorCode | string, reason: string, details?: {
    field?: string;
    limit?: number;
    actual?: number;
  });
  readonly name: 'LogCageError';
  readonly code: LogCageErrorCode | string;
  readonly reason: string;
  readonly field?: string;
  readonly limit?: number;
  readonly actual?: number;
  toJSON(): {
    name: string;
    code: string;
    reason: string;
    message: string;
    field?: string;
    limit?: number;
    actual?: number;
  };
}

export type SanitizeMode = 'escape' | 'strip';

export interface SanitizeLogLineOptions {
  /** escape renders controls as visible escapes; strip removes them. Default escape. */
  mode?: SanitizeMode;
  /** Maximum output length in UTF-16 code units, including the truncation marker. Default 4096. */
  maxLength?: number;
  /** Deterministic marker appended when visible output is truncated. Default [truncated]. */
  truncationMarker?: string;
}

export interface PiiRedactionOptions {
  /** Redact RFC-style email addresses. Default false. */
  email?: boolean;
  /** Redact 13 to 19 digit card-like values only when the Luhn checksum is valid. Default false. */
  luhnCard?: boolean;
  /** Redact dashed US SSN-shaped values with invalid area, group and serial combinations excluded. Default false. */
  ssn?: boolean;
  /** Redact dotted decimal IPv4 addresses with octets from 0 through 255. Default false. */
  ipv4?: boolean;
}

export interface RedactSecretsOptions {
  /** Replacement inserted for every detected secret or enabled PII value. Default [REDACTED]. */
  replacement?: string;
  /** Exact caller secrets, also matched in percent-encoded form with case-insensitive hex digits, form-encoded spaces and base64 forms. Maximum 64 entries. */
  extraSecrets?: readonly string[];
  /** Optional high-precision PII detectors. All are off by default. */
  pii?: PiiRedactionOptions;
}

export type RedactPath = string | readonly string[];

export interface SanitizeLogRecordOptions extends SanitizeLogLineOptions, RedactSecretsOptions {
  /** Maximum object nesting depth. Default 12. */
  maxDepth?: number;
  /** Maximum own enumerable keys processed per object. Default 200. */
  maxKeys?: number;
  /** Maximum entries processed per array, Map, Set or typed array. Default 200. */
  maxArrayLength?: number;
  /** Maximum total container and child nodes expanded in one record. Default 2000. */
  maxNodes?: number;
  /** Additional key names to redact. Matching is case-insensitive and ignores underscores, hyphens, dots, spaces and tabs. */
  sensitiveKeys?: readonly string[];
  /** Exact dot-separated paths or arrays of path segments to redact, using the same normalized key matching. */
  redactPaths?: readonly RedactPath[];
}

export interface FormatSafeJsonLogOptions extends SanitizeLogRecordOptions {
  /** Injected timestamp as an ISO string, epoch milliseconds number or valid Date. Default is the current time. */
  timestamp?: string | number | Date;
  /** Maximum serialized UTF-8 output bytes. Default 262144. Oversized entries fail closed. */
  maxOutputBytes?: number;
}

export type LogCageOptions = FormatSafeJsonLogOptions;

export interface ConsoleLike {
  log(...args: unknown[]): unknown;
  info?(...args: unknown[]): unknown;
  warn?(...args: unknown[]): unknown;
  error?(...args: unknown[]): unknown;
  debug?(...args: unknown[]): unknown;
  trace?(...args: unknown[]): unknown;
}

export interface WrappedConsole {
  log(...args: unknown[]): void;
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
  debug(...args: unknown[]): void;
  trace(...args: unknown[]): void;
}

export interface LogCage {
  line(input: string, options?: SanitizeLogLineOptions): string;
  redact(text: string, options?: RedactSecretsOptions): string;
  record(record: unknown, options?: SanitizeLogRecordOptions): unknown;
  json(level: string, message: string): string;
  json(level: string, message: string, meta: unknown, options?: FormatSafeJsonLogOptions): string;
  wrapConsole(target?: ConsoleLike): WrappedConsole;
}

/** Neutralize CWE-117 line forging, terminal control sequences, bidirectional controls and unsafe format characters. */
export declare function sanitizeLogLine(input: string, options?: SanitizeLogLineOptions): string;

/** Redact credentials, tokens, private key blocks, URL userinfo, caller secrets and optionally enabled PII. */
export declare function redactSecrets(text: string, options?: RedactSecretsOptions): string;

/** Deeply copy and sanitize a structured log record without mutating the input. */
export declare function sanitizeLogRecord(record: unknown, options?: SanitizeLogRecordOptions): unknown;

/** Serialize a guaranteed single-line NDJSON log entry. Oversized or unsafe output fails closed. */
export declare function formatSafeJsonLog(level: string, message: string): string;
export declare function formatSafeJsonLog(level: string, message: string, meta: unknown, options?: FormatSafeJsonLogOptions): string;

/** Create a reusable configured guard. The returned object is frozen and does not mutate console targets. */
export declare function createLogCage(options?: LogCageOptions): LogCage;

declare const logcage: Readonly<{
  CODE: typeof CODE;
  LogCageError: typeof LogCageError;
  sanitizeLogLine: typeof sanitizeLogLine;
  redactSecrets: typeof redactSecrets;
  sanitizeLogRecord: typeof sanitizeLogRecord;
  formatSafeJsonLog: typeof formatSafeJsonLog;
  createLogCage: typeof createLogCage;
}>;

export default logcage;
