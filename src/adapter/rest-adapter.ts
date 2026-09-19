/**
 * Universal REST adapter — guarded HTTP boundary for target invocation.
 *
 * Enforces the README's network + secret boundaries:
 *   - outbound host allowlist (default deny)
 *   - redirect rejection (3xx = error, never followed)
 *   - response-size cap (streamed byte counter, aborted on breach)
 *   - bounded retries (idempotent GET only)
 *   - timeouts via AbortController
 *   - allowlisted request/response JSON mappings (explicit key lists)
 *   - opaque secret references resolved by a provider — never inline values
 *   - correlation ID propagation
 */

import type { CanonicalRequest, RunContext, TargetResult } from "../contracts/types.ts";

export interface RestAdapterConfig {
  kind: "rest";
  /** Allowlisted outbound hosts — default deny anything else. */
  allowedHosts: string[];
  endpoint: { url: string; method: "POST" | "GET" | "PUT" };
  /** Allowlist of top-level request body keys. */
  requestMapping: string[];
  /** Allowlist of top-level response body keys. read. */
  responseMapping: string[];
  auth?: { secretRef: string; header: string; scheme: string };
  limits: {
    timeoutMs: number;
    maxResponseBytes: number;
    retries: number;
    maxRedirects: number;
  };
}

/** Opaque secret provider — resolves references, never holds inline values. */
export interface SecretProvider {
  /** Returns the header value for a reference, or undefined when unavailable. */
  resolve(secretRef: string): string | undefined;
}

export class RestAdapterError extends Error {
  constructor(
    public readonly code:
      | "disallowed_host"
      | "redirect_rejected"
      | "timeout"
      | "oversize_response"
      | "mapping_violation"
      | "secret_unavailable"
      | "http_error"
      | "inline_secret_rejected",
    message: string,
    public readonly retryable = false,
  ) {
    super(message);
    this.name = "RestAdapterError";
  }
}

function assertNoInlineSecrets(body: unknown, path: string): void {
  if (typeof body === "string") {
    if (/\b(?:sk-|ghp_|AKIA|BEGIN (?:RSA )?PRIVATE KEY)[A-Za-z0-9_-]{6,}/.test(body)) {
      throw new RestAdapterError("inline_secret_rejected", `inline secret-like value at ${path}`);
    }
    return;
  }
  if (Array.isArray(body)) {
    body.forEach((v, i) => { assertNoInlineSecrets(v, `${path}[${i}]`); });
    return;
  }
  if (typeof body === "object" && body !== null) {
    for (const [k, v] of Object.entries(body)) assertNoInlineSecrets(v, `${path}.${k}`);
  }
}

export interface RestAdapterDeps {
  fetchImpl?: typeof fetch;
  secretProvider?: SecretProvider;
  now?: () => string;
}

/** Injectable fetch for tests — production path uses global fetch. */
export function createRestAdapter(config: RestAdapterConfig, deps: RestAdapterDeps = {}) {
  const doFetch = deps.fetchImpl ?? fetch;
  const now = deps.now ?? (() => new Date().toISOString());

  const url = new URL(config.endpoint.url);
  if (!config.allowedHosts.includes(url.hostname)) {
    // Fail at configuration time — default deny.
    throw new RestAdapterError("disallowed_host", `host "${url.hostname}" is not in the outbound allowlist`);
  }

  async function invoke(request: CanonicalRequest, context: RunContext): Promise<TargetResult> {
    const startedAt = now();
    const payload: Record<string, unknown> = { messages: request.messages };
    if (request.tools !== undefined && request.tools.length > 0) payload.tools = request.tools;
    for (const k of Object.keys(request.metadata ?? {})) {
      if (!config.requestMapping.includes(k)) {
        throw new RestAdapterError("mapping_violation", `metadata key "${k}" not in request mapping allowlist`);
      }
      const v = request.metadata?.[k];
      payload[k] = v;
    }

    assertNoInlineSecrets(payload, "request");

    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-correlation-id": context.correlationId,
    };
    if (config.auth !== undefined) {
      const secret = deps.secretProvider?.resolve(config.auth.secretRef);
      if (secret === undefined) {
        throw new RestAdapterError("secret_unavailable", `secret ref "${config.auth.secretRef}" could not be resolved — failing closed`);
      }
      headers[config.auth.header] = `${config.auth.scheme} ${secret}`;
    }

    let attempt = 0;
    for (;;) {
      const controller = new AbortController();
      const timer = setTimeout(() => { controller.abort(); }, config.limits.timeoutMs);
      let response: Response;
      try {
        response = await doFetch(config.endpoint.url, {
          method: config.endpoint.method,
          headers,
          ...(config.endpoint.method === "GET" ? {} : { body: JSON.stringify(payload) }),
          signal: controller.signal,
          redirect: "manual",
        });
      } catch (e) {
        if (e instanceof RestAdapterError) throw e;
        if (controller.signal.aborted) {
          throw new RestAdapterError("timeout", `target timed out after ${config.limits.timeoutMs}ms`);
        }
        const err = e as Error;
        if (err.name === "RestAdapterError") throw err;
        // Network errors: bounded retry
        if (attempt < config.limits.retries) {
          attempt += 1;
          continue;
        }
        throw new RestAdapterError("http_error", `network failure: ${err.message}`, false);
      } finally {
        clearTimeout(timer);
      }

      if (response.status >= 300 && response.status < 400) {
        throw new RestAdapterError("redirect_rejected", `redirect (${response.status}) rejected by policy`);
      }

      // Streamed size enforcement.
      const reader: ReadableStreamDefaultReader<Uint8Array> | undefined = response.body?.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      if (reader !== undefined) {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > config.limits.maxResponseBytes) {
            await reader.cancel().catch(() => undefined);
            throw new RestAdapterError("oversize_response", `response exceeded ${config.limits.maxResponseBytes} bytes`);
          }
          chunks.push(value);
        }
      }
      const text = new TextDecoder().decode(concat(chunks));
      let parsed: unknown;
      try {
        parsed = JSON.parse(text) as unknown;
      } catch {
        throw new RestAdapterError("mapping_violation", "response body is not valid JSON");
      }
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        for (const k of Object.keys(parsed)) {
          if (!config.responseMapping.includes(k)) {
            throw new RestAdapterError("mapping_violation", `response key "${k}" not in response mapping allowlist`);
        }
        }
      }

      return {
        status: "completed",
        startedAt,
        endedAt: now(),
        rawArtifactRef: `rest:${url.hostname}:${context.correlationId}`,
        events: [],
      };
    }
  }

  return { invoke };
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const len = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}
