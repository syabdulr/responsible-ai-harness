/**
 * Production Jev transport: the official `@typesafe-ai/sdk`, pinned exact
 * version 0.6.0, behind the narrow `JevClient` interface.
 *
 * Secret handling: the API key is handed to `TypeSafeClient`'s constructor
 * and then this module keeps no reference to it. The key necessarily
 * enters this process's memory — the SDK needs it to sign requests — but
 * it never enters this module's own fields, never gets logged (log level
 * is hardcoded to "warn", never "debug", which is the only level that
 * would otherwise dump request/response bodies), never gets included in
 * any config object we serialize, and is never read from or written to
 * this repository.
 *
 * One bounded call: `maxRetries: 0` both at the client and per-call, plus
 * an explicit per-attempt timeout. A network failure or non-2xx response
 * is a single failed attempt, not a retried one.
 */

import { APIConnectionError, APITimeoutError, APIError, TypeSafeClient, TypeSafeError } from "@typesafe-ai/sdk";
import type { Fetch } from "@typesafe-ai/sdk";
import { JevTransportError } from "./jev-transport.ts";
import type { JevClient, JevTransportCallOptions, JevTransportRequest, JevTransportResult } from "./jev-transport.ts";

/** Classify an SDK exception into a normalized, non-sensitive transport error. */
function classifySdkError(error: unknown): JevTransportError {
  if (error instanceof APITimeoutError) {
    return new JevTransportError("jev_transport_timeout", error.message, true);
  }
  if (error instanceof APIConnectionError) {
    return new JevTransportError("jev_transport_connection_error", error.message, false);
  }
  if (error instanceof APIError) {
    return new JevTransportError(`jev_transport_api_error_${String(error.status)}`, error.message, false);
  }
  if (error instanceof TypeSafeError) {
    return new JevTransportError("jev_transport_sdk_error", error.message, false);
  }
  const message = error instanceof Error ? error.message : "unknown transport failure";
  return new JevTransportError("jev_transport_unknown_error", message, false);
}

export interface TypeSafeJevTransportOptions {
  baseURL?: string;
  /** Overridable for tests that stub `fetch`; production callers omit this. */
  fetch?: Fetch;
}

/**
 * Build a production `JevClient`. `apiKey` must come from the runtime
 * secret provider boundary, never from a literal, an environment read
 * inside harness code, a config file, or a CLI argument.
 */
export function createTypeSafeJevTransport(apiKey: string, options: TypeSafeJevTransportOptions = {}): JevClient {
  const client = new TypeSafeClient({
    apiKey,
    logLevel: "warn",
    retry: { maxRetries: 0 },
    ...(options.baseURL !== undefined ? { baseURL: options.baseURL } : {}),
    ...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
  });

  return {
    async systemOne(request: JevTransportRequest, callOptions: JevTransportCallOptions): Promise<JevTransportResult> {
      const startedAt = Date.now();
      let response;
      try {
        response = await client.systemOne(
          { state: request.state, questions: request.questions, ...(request.model !== undefined ? { model: request.model } : {}) },
          { timeout: callOptions.timeoutMs, retry: { maxRetries: 0 } },
        );
      } catch (error) {
        throw classifySdkError(error);
      }
      const latencyMs = Date.now() - startedAt;
      return {
        model: response.model,
        answers: response.answers,
        usage: { inputTokens: response.usage.input_tokens, outputTokens: response.usage.output_tokens },
        latencyMs,
      };
    },
  };
}
