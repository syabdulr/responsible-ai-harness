/**
 * Jev transport boundary — versioned independently of the question catalog,
 * the threshold policy, and the report builder.
 *
 * `JevJudge` never imports `@typesafe-ai/sdk` directly and never touches an
 * API key. It only depends on this narrow interface. The production
 * implementation (`jev-transport-typesafe.ts`) wraps the official SDK;
 * automated tests inject a fake that never performs I/O.
 */

import type { EntryType, Questions } from "@typesafe-ai/sdk";

export const JEV_TRANSPORT_VERSION = "1.0.0";

export interface JevTransportRequest {
  state: EntryType;
  questions: Questions;
  /** Model override. Production callers default to the SDK's `jev-latest`. */
  model?: string;
}

export interface JevTransportUsage {
  inputTokens: number;
  outputTokens: number;
}

export interface JevTransportResult {
  model: string;
  /** Raw, untrusted answers keyed by question id — validated by the threshold policy. */
  answers: unknown;
  usage: JevTransportUsage;
  latencyMs: number;
}

export interface JevTransportCallOptions {
  /** Per-attempt timeout in milliseconds. The call must make exactly one attempt. */
  timeoutMs: number;
}

/**
 * One bounded call, no retries. Implementations must reject/throw rather
 * than silently return a second attempt's result.
 */
export interface JevClient {
  systemOne(request: JevTransportRequest, options: JevTransportCallOptions): Promise<JevTransportResult>;
}

/**
 * Normalized transport failure. Production and fake clients alike reject
 * with this (never a raw SDK exception) so the orchestration layer never
 * needs to know about `@typesafe-ai/sdk`'s error classes.
 */
export class JevTransportError extends Error {
  readonly code: string;
  readonly timeout: boolean;
  constructor(code: string, message: string, timeout: boolean) {
    super(message);
    this.name = "JevTransportError";
    this.code = code;
    this.timeout = timeout;
  }
}
