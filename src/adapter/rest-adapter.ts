/**
 * Universal REST adapter — guarded HTTP boundary for target invocation.
 *
 * Enforces the README's network + secret boundaries:
 *   - allowed schemes (http/https only, https by default)
 *   - outbound host allowlist (default deny)
 *   - SSRF guard: loopback, link-local, metadata service (169.254.169.254),
 *     private IPv4, local/private IPv6, and 0.0.0.0 are blocked unless the
 *     config explicitly opts in for a local synthetic target
 *   - DNS rebinding mitigation: hostname resolved and EVERY address validated
 *     before the request is issued (re-validated on each retry attempt)
 *   - redirect rejection (3xx = error, never followed)
 *   - non-2xx responses are errors (with status code)
 *   - response-size cap (streamed byte counter, aborted on breach)
 *   - retries ONLY for demonstrably idempotent operations:
 *       GET (idempotent by contract), or POST/PUT when the config enables
 *       an idempotency key (single-use per invocation, reused across that
 *       invocation's attempts). Non-idempotent POST/PUT never auto-retries.
 *   - timeouts via AbortController
 *   - allowlisted request/response JSON mappings (explicit key lists)
 *   - response mapping into TargetResult canonical events (not `events: []`)
 *   - opaque secret references resolved by a provider — never inline values
 *   - correlation ID propagation
 */

import { randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { validateCanonicalEvent } from "../contracts/validation.ts";
import type { CanonicalEvent, CanonicalRequest, RunContext, TargetResult } from "../contracts/types.ts";

export const PROTECTED_HEADERS: readonly string[] = [
  "content-type",
  "content-length",
  "host",
  "connection",
  "transfer-encoding",
  "x-correlation-id",
  "idempotency-key",
];

export interface RestAdapterConfig {
  kind: "rest";
  /** Allowlisted outbound hosts — default deny anything else. */
  allowedHosts: string[];
  /** Allowed URL schemes. Default ["https:"]. */
  allowedSchemes?: string[];
  endpoint: { url: string; method: "POST" | "GET" | "PUT" };
  /** Allowlist of top-level request body keys (beyond messages/tools). */
  requestMapping: string[];
  /** Allowlist of top-level response body keys. */
  responseMapping: string[];
  /** How allowlisted response fields become canonical events. */
  responseEventMap?: {
    /** Response key holding assistant text -> message.output event. */
    outputTextField?: string;
    /** Response key holding an array of raw canonical events (validated). */
    eventsField?: string;
  };
  auth?: { secretRef: string; header: string; scheme: string };
  idempotency?: {
    enabled: boolean;
    /** Header carrying the single-use idempotency key. */
    header: string;
  };
  limits: {
    timeoutMs: number;
    maxResponseBytes: number;
    retries: number;
    maxRedirects: number;
  };
  /**
   * Explicit opt-in for local synthetic targets (demo/tests only).
   * When false (default), loopback/private/link-local/metadata hosts are
   * rejected even if listed in allowedHosts.
   */
  allowLoopback?: boolean;
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
      | "disallowed_scheme"
      | "blocked_address"
      | "redirect_rejected"
      | "timeout"
      | "oversize_response"
      | "mapping_violation"
      | "secret_unavailable"
      | "http_error"
      | "inline_secret_rejected"
      | "invalid_config",
    message: string,
    public readonly retryable: boolean = false,
  ) {
    super(message);
    this.name = "RestAdapterError";
  }
}

/** Validate and bound adapter configuration. Throws invalid_config. */
export function validateAdapterConfig(config: RestAdapterConfig): void {
  const bad = (msg: string): never => { throw new RestAdapterError("invalid_config", msg); };
  if (config.kind !== "rest") bad("kind must be 'rest'");
  if (!Array.isArray(config.allowedHosts) || config.allowedHosts.length === 0) bad("allowedHosts must be a non-empty array");
  if (!Array.isArray(config.requestMapping)) bad("requestMapping must be an array");
  if (!Array.isArray(config.responseMapping) || config.responseMapping.length === 0) bad("responseMapping must be a non-empty array");
  const schemes = config.allowedSchemes ?? ["https:"];
  if (!Array.isArray(schemes) || schemes.length === 0) bad("allowedSchemes must be non-empty");
  for (const s of schemes) if (s !== "http:" && s !== "https:") bad(`allowedSchemes: unsupported scheme "${s}"`);
  for (const v of Object.values(config.limits)) {
    if (typeof v !== "number" || !Number.isFinite(v) || v < 0) bad("limits must be non-negative finite numbers");
  }
  if (config.limits.timeoutMs < 1 || config.limits.timeoutMs > 300_000) bad("limits.timeoutMs must be within 1..300000");
  if (config.limits.maxResponseBytes < 1 || config.limits.maxResponseBytes > 10 * 1024 * 1024) bad("limits.maxResponseBytes must be within 1..10MiB");
  if (config.limits.retries > 5) bad("limits.retries must be <= 5");
  if (config.limits.maxRedirects !== 0) bad("redirects are never followed; limits.maxRedirects must be 0");
  if (config.auth !== undefined) {
    if (typeof config.auth.header !== "string" || config.auth.header.length === 0) bad("auth.header must be a non-empty string");
    if (PROTECTED_HEADERS.includes(config.auth.header.toLowerCase())) {
      bad(`auth.header "${config.auth.header}" is protected and cannot be overwritten`);
    }
  }
  if (config.idempotency !== undefined) {
    if (typeof config.idempotency.header !== "string" || config.idempotency.header.length === 0) bad("idempotency.header must be a non-empty string");
    if (PROTECTED_HEADERS.includes(config.idempotency.header.toLowerCase())) {
      bad(`idempotency.header "${config.idempotency.header}" is protected`);
    }
    if (config.idempotency.header.toLowerCase() === (config.auth?.header ?? "").toLowerCase()) {
      bad("idempotency.header must differ from auth.header");
    }
  }
}

function ipv4ToInt(ip: string): number | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (m === null) return undefined;
  const parts: number[] = m.slice(1).map((g) => Number(g));
  if (parts.some((p) => p > 255)) return undefined;
  const [a, b, c, d] = parts;
  if (a === undefined || b === undefined || c === undefined || d === undefined) return undefined;
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

function inCidr4(ip: string, prefix: string, bits: number): boolean {
  const ipInt = ipv4ToInt(ip);
  const preInt = ipv4ToInt(prefix);
  if (ipInt === undefined || preInt === undefined) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (preInt & mask);
}

/** True when the address is safe for outbound requests. */
export function isSafeAddress(ip: string): boolean {
  // IPv6 forms
  const v6 = ip.toLowerCase();
  if (v6 === "::" || v6 === "::1") return false;
  if (v6.startsWith("fe80") || v6.startsWith("fc") || v6.startsWith("fd")) return false;
  if (v6.startsWith("::ffff:")) return isSafeAddress(v6.slice(7));
  // IPv4
  const v4 = ipv4ToInt(ip);
  if (v4 === undefined) return true; // not an IPv4 literal (IPv6 handled above)
  if (v4 === 0) return false; // 0.0.0.0
  if (inCidr4(ip, "10.0.0.0", 8)) return false;
  if (inCidr4(ip, "172.16.0.0", 12)) return false;
  if (inCidr4(ip, "192.168.0.0", 16)) return false;
  if (inCidr4(ip, "127.0.0.0", 8)) return false;
  if (inCidr4(ip, "169.254.0.0", 16)) return false; // link-local + cloud metadata
  if (inCidr4(ip, "100.64.0.0", 10)) return false; // CGNAT
  if (inCidr4(ip, "192.0.0.0", 24)) return false;
  if (inCidr4(ip, "198.18.0.0", 15)) return false; // benchmarking
  return true;
}

function assertNoInlineSecrets(body: unknown, path: string): void {
  if (typeof body === "string") {
    if (/\b(?:sk-|ghp_|AKIA|BEGIN (?:RSA )?PRIVATE KEY)[A-Za-z0-9_-]{6,}/.test(body)) {
      throw new RestAdapterError("inline_secret_rejected", `inline secret-like value at ${path}`);
    }
    return;
  }
  if (Array.isArray(body)) {
    body.forEach((v, i) => assertNoInlineSecrets(v, `${path}[${i}]`));
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
  dnsLookup?: (host: string) => Promise<string[]>;
}

type RestAdapterResponseMap = RestAdapterConfig["responseEventMap"];

interface MapResponseToEvents {
  (parsed: Record<string, unknown>, context: { runId: string; caseId: string; now: string }): CanonicalEvent[];
}

/** Map allowlisted response fields into canonical events. */
export const mapResponseToEvents: MapResponseToEvents = (parsed, ctx) => {
  const events: CanonicalEvent[] = [];
  const map = ADAPTER_RESPONSE_MAP;
  if (map?.eventsField !== undefined) {
    const rawEvents = parsed[map.eventsField];
    if (rawEvents !== undefined) {
      if (!Array.isArray(rawEvents)) throw new RestAdapterError("mapping_violation", `response key "${map.eventsField}" must be an array of events`);
      for (const [i, re] of rawEvents.entries()) {
        const v = validateCanonicalEvent(re);
        if (!v.ok) throw new RestAdapterError("mapping_violation", `response event[${i}]: ${v.error}`);
        events.push({ ...v.value, runId: ctx.runId });
      }
    }
  }
  if (map?.outputTextField !== undefined) {
    const text = parsed[map.outputTextField];
    if (text !== undefined) {
      if (typeof text !== "string") throw new RestAdapterError("mapping_violation", `response key "${map.outputTextField}" must be a string`);
      events.push({
        schemaVersion: "1.0",
        eventId: `evt_rest_${randomUUID()}`,
        runId: ctx.runId,
        sequence: events.length + 1,
        timestamp: ctx.now,
        type: "message.output",
        actor: "assistant",
        content: { text },
      });
    }
  }
  return events;
};

// Module-level response map set at adapter creation. Single-adapter
// process model; a multi-adapter host must pass the map per call instead.
let ADAPTER_RESPONSE_MAP: RestAdapterResponseMap | undefined;

/** Create the adapter. Validates config; throws invalid_config on bad input. */
export function createRestAdapter(config: RestAdapterConfig, deps: RestAdapterDeps = {}) {
  validateAdapterConfig(config);
  const doFetch = deps.fetchImpl ?? fetch;
  const now = deps.now ?? (() => new Date().toISOString());
  const dns = deps.dnsLookup ?? (async (host: string) => (await lookup(host, { all: true })).map((a) => a.address));

  const url = new URL(config.endpoint.url);
  const schemes = config.allowedSchemes ?? ["https:"];
  if (!schemes.includes(url.protocol)) {
    throw new RestAdapterError("disallowed_scheme", `scheme "${url.protocol}" not in allowed schemes [${schemes.join(", ")}]`);
  }
  if (!config.allowedHosts.includes(url.hostname)) {
    // Fail at configuration time — default deny.
    throw new RestAdapterError("disallowed_host", `host "${url.hostname}" is not in the outbound allowlist`);
  }
  ADAPTER_RESPONSE_MAP = config.responseEventMap;

  const isLoopbackAllowed = config.allowLoopback === true;

  async function assertResolvedHostsSafe(): Promise<void> {
    if (isLoopbackAllowed && (url.hostname === "localhost" || url.hostname === "127.0.0.1")) return;
    const addrs = await dns(url.hostname).catch(() => {
      throw new RestAdapterError("blocked_address", `DNS resolution failed for "${url.hostname}"`);
    });
    for (const a of addrs) {
      if (ipv4ToInt(a) !== undefined || a.includes(":")) {
        if (!isSafeAddress(a)) {
          throw new RestAdapterError("blocked_address", `host "${url.hostname}" resolves to blocked address ${a}`);
        }
      }
    }
  }

  const method = config.endpoint.method;
  const idempotencyEnabled = config.idempotency?.enabled === true;
  const canRetry = method === "GET" || (idempotencyEnabled && (method === "POST" || method === "PUT"));

  async function invoke(request: CanonicalRequest, context: RunContext): Promise<TargetResult> {
    const startedAt = now();
    const payload: Record<string, unknown> = { caseId: request.caseId, messages: request.messages };
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
    // Single-use idempotency key per invocation, reused across THIS
    // invocation's retry attempts (that is its purpose). Never reused
    // across invocations.
    const idemKey = randomUUID();
    if (idempotencyEnabled && config.idempotency !== undefined) headers[config.idempotency.header] = idemKey;

    let attempt = 0;
    for (;;) {
      // DNS rebinding mitigation: validate resolution before every attempt.
      await assertResolvedHostsSafe();

      const controller = new AbortController();
      const timer = setTimeout(() => { controller.abort(); }, config.limits.timeoutMs);
      let response: Response;
      try {
        response = await doFetch(config.endpoint.url, {
          method,
          headers,
          ...(method === "GET" ? {} : { body: JSON.stringify(payload) }),
          signal: controller.signal,
          redirect: "manual",
        });
      } catch (e) {
        if (e instanceof RestAdapterError) throw e;
        if (controller.signal.aborted) {
          throw new RestAdapterError("timeout", `target timed out after ${config.limits.timeoutMs}ms`);
        }
        const err = e as Error;
        // Network errors: bounded retry ONLY for idempotent operations.
        if (canRetry && attempt < config.limits.retries) {
          attempt += 1;
          continue;
        }
        throw new RestAdapterError(
          "http_error",
          `network failure on ${method}${canRetry ? "" : " (non-idempotent: no retry)"}: ${err.message}`,
          false,
        );
      } finally {
        clearTimeout(timer);
      }

      if (response.status >= 300 && response.status < 400) {
        throw new RestAdapterError("redirect_rejected", `redirect (${response.status}) rejected by policy`);
      }
      if (response.status < 200 || response.status >= 300) {
        throw new RestAdapterError("http_error", `target returned HTTP ${response.status}`, false);
      }

      // Streamed size enforcement.
      const reader: ReadableStreamDefaultReader<Uint8Array> | undefined = response.body?.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      if (reader !== undefined) {
        for (;;) {
          const { done, value } = await reader.read();
          if (done === true) break;
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
      } else {
        throw new RestAdapterError("mapping_violation", "response body must be a JSON object");
      }

      const events = mapResponseToEvents(parsed as Record<string, unknown>, {
        runId: context.runId,
        caseId: context.caseId,
        now: now(),
      });

      return {
        status: "completed",
        startedAt,
        endedAt: now(),
        rawArtifactRef: `rest:${url.hostname}:${context.correlationId}`,
        events,
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

