import { describe, expect, it } from "vitest";
import { createRestAdapter, RestAdapterError } from "../src/adapter/rest-adapter.ts";
import type { CanonicalRequest, RunContext } from "../src/contracts/types.ts";

function makeContext(): RunContext {
  return { runId: "run_test", caseId: "case_test", correlationId: "corr-test-1", startedAt: new Date().toISOString() };
}

function makeRequest(): CanonicalRequest {
  return { caseId: "case_test", messages: [{ role: "user", content: "hello" }] };
}

const baseConfig = {
  kind: "rest" as const,
  allowedHosts: ["api.target.local"],
  endpoint: { url: "http://api.target.local/v1/agent", method: "POST" as const },
  requestMapping: ["scenario"],
  responseMapping: ["reply", "events"],
  limits: { timeoutMs: 50, maxResponseBytes: 2048, retries: 1, maxRedirects: 0 },
};

function response(init: { status?: number; body?: unknown; headers?: Record<string, string> }): Response {
  return new Response(init.body === undefined ? null : JSON.stringify(init.body), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...init.headers },
  });
}

describe("REST adapter — host allowlist", () => {
  it("rejects a disallowed host at configuration time (default deny)", () => {
    expect(() =>
      createRestAdapter({ ...baseConfig, endpoint: { ...baseConfig.endpoint, url: "http://evil.example/api" } }),
    ).toThrow(RestAdapterError);
    expect(() =>
      createRestAdapter({ ...baseConfig, endpoint: { ...baseConfig.endpoint, url: "http://evil.example/api" } }),
    ).toThrow(/not in the outbound allowlist/);
  });

  it("accepts an allowlisted host", () => {
    const adapter = createRestAdapter(baseConfig);
    expect(typeof adapter.invoke).toBe("function");
  });
});

describe("REST adapter — redirects", () => {
  it("rejects 3xx responses (redirect: manual, never followed)", async () => {
    const adapter = createRestAdapter(baseConfig, {
      fetchImpl: (async () => response({ status: 302, headers: { location: "http://evil.example/x" } })),
    });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({
      code: "redirect_rejected",
    });
  });
});

describe("REST adapter — timeout", () => {
  it("aborts and reports timeout when the target never responds", async () => {
    const adapter = createRestAdapter(baseConfig, {
      fetchImpl: (async (_url: string | URL, init?: RequestInit) => {
        return await new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
        });
      }) as typeof fetch,
    });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "timeout" });
  });
});

describe("REST adapter — response size limit", () => {
  it("aborts an oversized streamed response", async () => {
    const bigPayload = { reply: "x".repeat(64 * 1024) };
    const adapter = createRestAdapter(baseConfig, {
      fetchImpl: (async () => response({ body: bigPayload })),
    });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "oversize_response" });
  });
});

describe("REST adapter — mapping enforcement", () => {
  it("rejects response keys outside the allowlist", async () => {
    const adapter = createRestAdapter(baseConfig, {
      fetchImpl: (async () => response({ body: { reply: "ok", secret_internal: "sk-live-123" } })),
    });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "mapping_violation" });
  });

  it("rejects request metadata keys outside the allowlist", async () => {
    const adapter = createRestAdapter(baseConfig, {
      fetchImpl: (async () => response({ body: { reply: "ok" } })),
    });
    const req = { ...makeRequest(), metadata: { unauthorized_key: "x" } };
    await expect(adapter.invoke(req, makeContext())).rejects.toMatchObject({ code: "mapping_violation" });
  });

  it("rejects non-JSON response bodies", async () => {
    const adapter = createRestAdapter(baseConfig, {
      fetchImpl: (async () => new Response("<html>not json</html>", { status: 200 })),
    });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "mapping_violation" });
  });
});

describe("REST adapter — inline secret rejection", () => {
  it("refuses to send bodies containing secret-like inline values", async () => {
    const adapter = createRestAdapter(baseConfig, {
      fetchImpl: (async () => response({ body: { reply: "ok" } })),
    });
    const req: CanonicalRequest = { ...makeRequest(), messages: [{ role: "user", content: "key is sk-abc123def456ghi789" }] };
    await expect(adapter.invoke(req, makeContext())).rejects.toMatchObject({ code: "inline_secret_rejected" });
  });
});

describe("REST adapter — secret provider (opaque refs, fail closed)", () => {
  it("fails closed when auth is configured but the provider cannot resolve the ref", async () => {
    const adapter = createRestAdapter(
      { ...baseConfig, auth: { secretRef: "target/prod/token", header: "authorization", scheme: "Bearer" } },
      { fetchImpl: (async () => response({ body: { reply: "ok" } })), secretProvider: { resolve: () => undefined } },
    );
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "secret_unavailable" });
  });

  it("attaches the resolved secret as an auth header when available", async () => {
    let seenHeaders: Headers | undefined;
    const adapter = createRestAdapter(
      { ...baseConfig, auth: { secretRef: "target/prod/token", header: "authorization", scheme: "Bearer" } },
      {
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

describe("REST adapter — bounded retries", () => {
  it("retries a network failure once, then reports http_error", async () => {
    let calls = 0;
    const adapter = createRestAdapter(baseConfig, {
      fetchImpl: (async () => {
        calls += 1;
        throw new TypeError("fetch failed");
      }),
    });
    await expect(adapter.invoke(makeRequest(), makeContext())).rejects.toMatchObject({ code: "http_error" });
    expect(calls).toBe(2); // initial + 1 retry
  });
});

describe("REST adapter — repeatability", () => {
  it("produces identical rawArtifactRef deterministically for identical input", async () => {
    const adapter = createRestAdapter(baseConfig, {
      fetchImpl: (async () => response({ body: { reply: "ok" } })),
      now: () => "2026-01-01T00:00:00.000Z",
    });
    const a = await adapter.invoke(makeRequest(), makeContext());
    const b = await adapter.invoke(makeRequest(), makeContext());
    expect(a.rawArtifactRef).toBe(b.rawArtifactRef);
    expect(a.startedAt).toBe(b.startedAt);
  });
});
