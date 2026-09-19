import { describe, expect, it } from "vitest";
import { createRestAdapter, RestAdapterError, isSafeAddress, validateAdapterConfig, PROTECTED_HEADERS } from "../src/adapter/rest-adapter.ts";
import type { CanonicalRequest, RunContext } from "../src/contracts/types.ts";

/** Structural fetch type (avoids global DOM lib dependency in this lib set). */
type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;



function makeContext(): RunContext {
  return { runId: "run_test", caseId: "case_test", correlationId: "corr-test-1", startedAt: new Date().toISOString() };
}

function makeRequest(): CanonicalRequest {
  return { caseId: "case_test", messages: [{ role: "user", content: "hello" }] };
}

const baseConfig = {
  kind: "rest" as const,
  allowedHosts: ["api.target.local"],
  endpoint: { url: "https://api.target.local/v1/agent", method: "POST" as const },
  requestMapping: ["scenario"],
  responseMapping: ["reply", "events"],
  responseEventMap: { outputTextField: "reply" },
  limits: { timeoutMs: 50, maxResponseBytes: 2048, retries: 1, maxRedirects: 0 },
};

function response(init: { status?: number; body?: unknown; headers?: Record<string, string> }): Response {
  return new Response(init.body === undefined ? null : JSON.stringify(init.body), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...init.headers },
  });
}

const localConfig = {
  ...baseConfig,
  allowedHosts: ["127.0.0.1"],
  endpoint: { url: "http://127.0.0.1:9999/v1/agent", method: "POST" as const },
  allowedSchemes: ["http:", "https:"],
  allowLoopback: true,
};

const dnsOk = async () => ["93.184.216.34"];

describe("REST adapter — host allowlist + schemes", () => {
  it("rejects a disallowed host at configuration time (default deny)", () => {
    expect(() =>
      createRestAdapter({ ...baseConfig, endpoint: { ...baseConfig.endpoint, url: "https://evil.example/api" } }, { dnsLookup: dnsOk }),
    ).toThrow(/not in the outbound allowlist/);
  });

  it("rejects non-http(s) schemes", () => {
    expect(() =>
      createRestAdapter({ ...baseConfig, endpoint: { ...baseConfig.endpoint, url: "file:///etc/passwd" } }, { dnsLookup: dnsOk }),
    ).toThrow(/scheme/);
  });

  it("accepts an allowlisted https host", () => {
    const adapter = createRestAdapter(baseConfig, { dnsLookup: dnsOk });
    expect(typeof adapter.invoke).toBe("function");
  });
});

describe("REST adapter — SSRF address guard", () => {
  it("blocks loopback/private/link-local/metadata addresses by default", () => {
    for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "::1", "fe80::1", "fd12::1"]) {
      expect(isSafeAddress(ip), ip).toBe(false);
    }
  });

  it("allows public addresses", () => {
    for (const ip of ["93.184.216.34", "1.1.1.1", "2606:4700::1111"]) {
      expect(isSafeAddress(ip), ip).toBe(true);
    }
  });

  it("blocks the FULL fe80::/10 link-local range (fe80..febf)", () => {
    for (const ip of ["fe80::1", "fe8f::", "fe90::1", "feab::2", "febf::ffff"]) {
      expect(isSafeAddress(ip), ip).toBe(false);
    }
    // fec0::/10 (site-local, deprecated) is outside the blocked range but
    // still private-ish; we explicitly do NOT claim it is blocked.
  });

  it("blocks alternate hexadecimal IPv4-mapped forms", () => {
    // ::ffff:7f00:1 == 127.0.0.1 ; ::ffff:0a00:0001 == 10.0.0.1
    expect(isSafeAddress("::ffff:7f00:1")).toBe(false);
    expect(isSafeAddress("::ffff:0a00:0001")).toBe(false);
    expect(isSafeAddress("::ffff:a00:1")).toBe(false); // 10.0.0.1 short form
    expect(isSafeAddress("::ffff:ac10:0001")).toBe(false); // 172.16.0.1
    expect(isSafeAddress("::ffff:c0a8:0101")).toBe(false); // 192.168.1.1
    // A public address in mapped form must still pass.
    expect(isSafeAddress("::ffff:0101:0101")).toBe(true); // 1.1.1.1
    // Dotted mapped form still blocked for private v4.
    expect(isSafeAddress("::ffff:127.0.0.1")).toBe(false);
  });

  it("blocks IPv4 multicast 224.0.0.0/4 and reserved 240.0.0.0/4", () => {
    for (const ip of ["224.0.0.1", "230.1.2.3", "239.255.255.254"]) {
      expect(isSafeAddress(ip), `${ip} multicast`).toBe(false);
    }
    for (const ip of ["240.0.0.1", "250.10.20.30", "255.255.255.255"]) {
      expect(isSafeAddress(ip), `${ip} reserved/broadcast`).toBe(false);
    }
    // Edge: last unicast address still safe.
    expect(isSafeAddress("223.255.255.255")).toBe(true);
  });

  it("rejects when DNS resolution returns a blocked address (DNS rebinding)", async () => {
    const adapter = createRestAdapter(baseConfig, {
      dnsLookup: async () => ["169.254.169.254"], // public name, private address
      fetchImpl: (async () => response({ body: { reply: "ok" } })),
    });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "blocked_address" });
  });

  it("re-validates DNS on every retry attempt (rebinding between attempts)", async () => {
    let dnsCalls = 0;
    const resolutions: string[][] = [["93.184.216.34"], ["10.0.0.5"]];
    let fetchCalls = 0;
    const getAdapter = createRestAdapter(
      { ...baseConfig, endpoint: { ...baseConfig.endpoint, method: "GET" }, limits: { ...baseConfig.limits, retries: 2 } },
      {
        dnsLookup: async () => resolutions[dnsCalls++] ?? ["93.184.216.34"],
        fetchImpl: (async () => {
          fetchCalls += 1;
          if (fetchCalls === 1) throw new TypeError("fetch failed");
          return response({ body: { reply: "ok" } });
        }),
      },
    );
    await expect(getAdapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "blocked_address" });
    expect(fetchCalls).toBe(1); // first attempt happened; retry was refused
    expect(dnsCalls).toBe(2); // re-resolution DID happen before the retry
  });
});

describe("REST adapter — idempotency-gated retries", () => {
  it("NEVER retries a non-idempotent POST on network failure", async () => {
    let calls = 0;
    const adapter = createRestAdapter(baseConfig, {
      dnsLookup: dnsOk,
      fetchImpl: (async () => {
        calls += 1;
        throw new TypeError("fetch failed");
      }),
    });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "http_error" });
    expect(calls).toBe(1); // single attempt — no automatic retry
  });

  it("retries GET (idempotent) up to the bound", async () => {
    let calls = 0;
    const adapter = createRestAdapter(
      { ...baseConfig, endpoint: { ...baseConfig.endpoint, method: "GET" }, limits: { ...baseConfig.limits, retries: 1 } },
      {
        dnsLookup: dnsOk,
        fetchImpl: (async () => {
          calls += 1;
          if (calls === 1) throw new TypeError("fetch failed");
          return response({ body: { reply: "ok" } });
        }),
      },
    );
    const result = await adapter.invoke(makeRequest(), makeContext());
    expect(result.status).toBe("completed");
    expect(calls).toBe(2);
  });

  it("retries POST only when an idempotency key is configured, sending one stable key across attempts", async () => {
    const seenKeys: Array<string | undefined> = [];
    let calls = 0;
    const adapter = createRestAdapter(
      { ...baseConfig, idempotency: { enabled: true, header: "x-idempotency-key" } },
      {
        dnsLookup: dnsOk,
        fetchImpl: (async (_u: string | URL, init?: RequestInit) => {
          calls += 1;
          seenKeys.push(new Headers(init?.headers).get("x-idempotency-key") ?? undefined);
          if (calls === 1) throw new TypeError("fetch failed");
          return response({ body: { reply: "ok" } });
        }) as typeof fetch,
      },
    );
    const r = await adapter.invoke(makeRequest(), makeContext());
    expect(r.status).toBe("completed");
    expect(calls).toBe(2);
    expect(seenKeys[0]).toBeDefined();
    expect(seenKeys[0]).toBe(seenKeys[1]); // same key across THIS invocation's attempts
  });

  it("uses a fresh idempotency key per invocation (single-use)", async () => {
    const keys: string[] = [];
    const adapter = createRestAdapter(
      { ...baseConfig, idempotency: { enabled: true, header: "x-idempotency-key" } },
      {
        dnsLookup: dnsOk,
        fetchImpl: (async (_u: string | URL, init?: RequestInit) => {
          keys.push(new Headers(init?.headers).get("x-idempotency-key") ?? "");
          return response({ body: { reply: "ok" } });
        }) as typeof fetch,
      },
    );
    await adapter.invoke(makeRequest(), makeContext());
    await adapter.invoke(makeRequest(), makeContext());
    expect(keys[0]).not.toBe(keys[1]); // different invocations, different keys
  });
});

describe("REST adapter — non-2xx handling", () => {
  it("treats 4xx/5xx as errors with the status code", async () => {
    for (const status of [400, 401, 403, 429, 500, 503]) {
      const fetchImpl: FetchLike = () => Promise.resolve(response({ status }));
      const adapter = createRestAdapter(baseConfig, { dnsLookup: dnsOk, fetchImpl });
      const rejection = await adapter.invoke(makeRequest(), makeContext()).then(
        () => undefined,
        (e: unknown) => e as { code?: string; message?: string },
      );
      expect(rejection?.code).toBe("http_error");
      expect(rejection?.message ?? "").toContain(String(status));
    }
  });
});

describe("REST adapter — response mapping into canonical events", () => {
  it("maps an allowlisted output-text field to a message.output event", async () => {
    const adapter = createRestAdapter(baseConfig, { dnsLookup: dnsOk, fetchImpl: (async () => response({ body: { reply: "hello there" } })) });
    const r = await adapter.invoke(makeRequest(), makeContext());
    expect(r.events).toHaveLength(1);
    expect(r.events[0]?.type).toBe("message.output");
    expect(r.events[0]?.content.text).toBe("hello there");
    expect(r.events[0]?.runId).toBe("run_test");
  });

  it("validates and maps a returned events array", async () => {
    const adapter = createRestAdapter(
      { ...baseConfig, responseEventMap: { eventsField: "events" } },
      {
        dnsLookup: dnsOk,
        fetchImpl: (async () =>
          response({
            body: {
              events: [
                { schemaVersion: "1.0", eventId: "e1", runId: "run_test", sequence: 1, timestamp: "2026-01-01T00:00:00.000Z", type: "message.output", actor: "assistant", content: { text: "from target" } },
              ],
            },
          })),
      },
    );
    const r = await adapter.invoke(makeRequest(), makeContext());
    expect(r.events).toHaveLength(1);
    expect(r.events[0]?.eventId).toBe("e1");
  });

  it("rejects malformed events in the response", async () => {
    const adapter = createRestAdapter(
      { ...baseConfig, responseEventMap: { eventsField: "events" } },
      {
        dnsLookup: dnsOk,
        fetchImpl: (async () => response({ body: { events: [{ bogus: true }] } })),
      },
    );
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "mapping_violation" });
  });

  it("rejects response keys outside the allowlist", async () => {
    const adapter = createRestAdapter(baseConfig, { dnsLookup: dnsOk, fetchImpl: (async () => response({ body: { reply: "ok", secret_internal: "x" } })) });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "mapping_violation" });
  });

  it("rejects non-object JSON bodies", async () => {
    const adapter = createRestAdapter(baseConfig, { dnsLookup: dnsOk, fetchImpl: (async () => new Response("[1,2,3]", { status: 200 })) });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "mapping_violation" });
  });
});

describe("REST adapter — config validation", () => {
  it("rejects auth headers that overwrite protected headers", () => {
    for (const h of ["content-type", "Content-Length", "HOST", "x-correlation-id"]) {
      expect(() =>
        validateAdapterConfig({ ...baseConfig, auth: { secretRef: "r", header: h, scheme: "Bearer" } }),
      ).toThrow(/protected/i);
    }
  });

  it("rejects idempotency header colliding with auth or protected headers", () => {
    expect(() =>
      validateAdapterConfig({ ...baseConfig, idempotency: { enabled: true, header: "content-type" } }),
    ).toThrow(/protected/i);
    expect(() =>
      validateAdapterConfig({ ...baseConfig, auth: { secretRef: "r", header: "x-auth", scheme: "Bearer" }, idempotency: { enabled: true, header: "x-auth" } }),
    ).toThrow(/differ/);
  });

  it("rejects out-of-bounds limits", () => {
    expect(() => validateAdapterConfig({ ...baseConfig, limits: { ...baseConfig.limits, timeoutMs: 0 } })).toThrow(/timeoutMs/);
    expect(() => validateAdapterConfig({ ...baseConfig, limits: { ...baseConfig.limits, timeoutMs: 1_000_000 } })).toThrow(/timeoutMs/);
    expect(() => validateAdapterConfig({ ...baseConfig, limits: { ...baseConfig.limits, maxResponseBytes: 0 } })).toThrow(/maxResponseBytes/);
    expect(() => validateAdapterConfig({ ...baseConfig, limits: { ...baseConfig.limits, retries: 9 } })).toThrow(/retries/);
    expect(() => validateAdapterConfig({ ...baseConfig, limits: { ...baseConfig.limits, maxRedirects: 1 } })).toThrow(/maxRedirects/);
  });

  it("exposes the protected-header list", () => {
    expect(PROTECTED_HEADERS).toContain("x-correlation-id");
  });
});

describe("REST adapter — loopback opt-in", () => {
  it("blocks loopback URLs by default even when allowlisted", () => {
    expect(() =>
      createRestAdapter({ ...baseConfig, endpoint: { url: "http://127.0.0.1:8080/x", method: "POST" }, allowedSchemes: ["http:", "https:"] } as never, { dnsLookup: async () => ["127.0.0.1"] }),
    ).toThrow(RestAdapterError);
  });

  it("permits loopback only with explicit allowLoopback for the demo target", async () => {
    const adapter = createRestAdapter(localConfig, {
      dnsLookup: async () => ["127.0.0.1"],
      fetchImpl: (async () => response({ body: { reply: "local ok" } })),
    });
    const r = await adapter.invoke(makeRequest(), makeContext());
    expect(r.status).toBe("completed");
    expect(r.events[0]?.content.text).toBe("local ok");
  });
});

describe("REST adapter — timeout / oversize / redirects / secrets", () => {
  it("aborts and reports timeout when the target never responds", async () => {
    const adapter = createRestAdapter(baseConfig, {
      dnsLookup: dnsOk,
      fetchImpl: (async (_u: string | URL, init?: RequestInit) => {
        return await new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
        });
      }) as typeof fetch,
    });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "timeout" });
  });

  it("aborts an oversized streamed response", async () => {
    const adapter = createRestAdapter(baseConfig, {
      dnsLookup: dnsOk,
      fetchImpl: (async () => response({ body: { reply: "x".repeat(64 * 1024) } })),
    });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "oversize_response" });
  });

  it("rejects 3xx redirects (manual, never followed)", async () => {
    const adapter = createRestAdapter(baseConfig, {
      dnsLookup: dnsOk,
      fetchImpl: (async () => response({ status: 302, headers: { location: "https://evil.example/x" } })),
    });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "redirect_rejected" });
  });

  it("refuses to send bodies containing secret-like inline values", async () => {
    const adapter = createRestAdapter(baseConfig, { dnsLookup: dnsOk, fetchImpl: (async () => response({ body: { reply: "ok" } })) });
    const req: CanonicalRequest = { ...makeRequest(), messages: [{ role: "user", content: "key is sk-abc123def456ghi789" }] };
    await expect(adapter.invoke(req, makeContext())).rejects.toMatchObject({ code: "inline_secret_rejected" });
  });

  it("fails closed when auth is configured but the provider cannot resolve the ref", async () => {
    const adapter = createRestAdapter(
      { ...baseConfig, auth: { secretRef: "target/prod/token", header: "authorization", scheme: "Bearer" } },
      { dnsLookup: dnsOk, fetchImpl: (async () => response({ body: { reply: "ok" } })), secretProvider: { resolve: () => undefined } },
    );
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "secret_unavailable" });
  });

  it("attaches the resolved secret as an auth header", async () => {
    let seenHeaders: Headers | undefined;
    const adapter = createRestAdapter(
      { ...baseConfig, auth: { secretRef: "target/prod/token", header: "authorization", scheme: "Bearer" } },
      {
        dnsLookup: dnsOk,
        fetchImpl: (async (_u: string | URL, init?: RequestInit) => {
          seenHeaders = new Headers(init?.headers);
          return response({ body: { reply: "ok" } });
        }) as typeof fetch,
        secretProvider: { resolve: () => "opaque-token-value" },
      },
    );
    const result = await adapter.invoke(makeRequest(), makeContext());
    expect(result.status).toBe("completed");
    expect(seenHeaders?.get("authorization")).toBe("Bearer opaque-token-value");
    expect(seenHeaders?.get("x-correlation-id")).toBe("corr-test-1");
  });
});
