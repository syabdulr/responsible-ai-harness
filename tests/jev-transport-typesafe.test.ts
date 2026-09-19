import { describe, expect, it, vi } from "vitest";
import type { Fetch } from "@typesafe-ai/sdk";
import { createTypeSafeJevTransport } from "../src/judges/jev-transport-typesafe.ts";
import { JevTransportError } from "../src/judges/jev-transport.ts";
import { noul } from "@typesafe-ai/sdk";

const FAKE_KEY = "sk-fake-jev-key-for-tests-only-never-real";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

interface RecordedCall {
  url: string;
  init: RequestInit | undefined;
}

function fakeFetch(responses: Response[]): { fetch: Fetch; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  let i = 0;
  const fetchImpl: Fetch = (input: string, init?: RequestInit) => {
    calls.push({ url: input, init });
    const r = responses[i];
    i += 1;
    if (r === undefined) return Promise.reject(new Error("fakeFetch: no more stubbed responses"));
    return Promise.resolve(r);
  };
  return { fetch: fetchImpl, calls };
}

describe("production Jev transport — real @typesafe-ai/sdk client, fake fetch, zero network", () => {
  it("maps a successful response into JevTransportResult", async () => {
    const { fetch, calls } = fakeFetch([jsonResponse({ model: "jev-latest", answers: { q1: { type: "noul", noul: 0.42 } }, usage: { input_tokens: 7, output_tokens: 3 } })]);
    const transport = createTypeSafeJevTransport(FAKE_KEY, { fetch });
    const result = await transport.systemOne({ state: "hello", questions: { q1: noul("is this ok?") } }, { timeoutMs: 2000 });
    expect(result.model).toBe("jev-latest");
    expect(result.answers).toEqual({ q1: { type: "noul", noul: 0.42 } });
    expect(result.usage).toEqual({ inputTokens: 7, outputTokens: 3 });
    expect(typeof result.latencyMs).toBe("number");
    expect(calls.length).toBe(1);
  });

  it("makes exactly one HTTP attempt even for a retryable 500, because maxRetries is forced to 0", async () => {
    const { fetch, calls } = fakeFetch([jsonResponse({ error: "boom" }, 500)]);
    const transport = createTypeSafeJevTransport(FAKE_KEY, { fetch });
    await expect(transport.systemOne({ state: "x", questions: { q1: noul("q?") } }, { timeoutMs: 2000 })).rejects.toBeInstanceOf(JevTransportError);
    expect(calls.length).toBe(1);
  });

  it("classifies a 401 as a normalized, non-timeout transport error", async () => {
    const { fetch } = fakeFetch([jsonResponse({ error: "unauthorized" }, 401)]);
    const transport = createTypeSafeJevTransport(FAKE_KEY, { fetch });
    try {
      await transport.systemOne({ state: "x", questions: { q1: noul("q?") } }, { timeoutMs: 2000 });
      expect.unreachable("expected a rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(JevTransportError);
      if (error instanceof JevTransportError) {
        expect(error.code).toBe("jev_transport_api_error_401");
        expect(error.timeout).toBe(false);
      }
    }
  });

  it("never reflects a malicious/compromised response body into the classified error message", async () => {
    // A hostile or compromised endpoint (or a MITM) could echo request
    // content, including the API key or evidence, back in an error body.
    // classifySdkError must use a fixed message regardless of body content.
    const hostileBody = { error: `your key ${FAKE_KEY} is invalid and here is a secret=zzz-should-never-surface` };
    const { fetch } = fakeFetch([jsonResponse(hostileBody, 400)]);
    const transport = createTypeSafeJevTransport(FAKE_KEY, { fetch });
    try {
      await transport.systemOne({ state: "x", questions: { q1: noul("q?") } }, { timeoutMs: 2000 });
      expect.unreachable("expected a rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(JevTransportError);
      if (error instanceof JevTransportError) {
        expect(error.message).not.toContain(FAKE_KEY);
        expect(error.message).not.toContain("secret=");
        expect(error.message).toBe("the Jev API returned an unsuccessful response (status 400)");
      }
    }
  });

  it("never puts the API key in the request body", async () => {
    const { fetch, calls } = fakeFetch([jsonResponse({ model: "jev-latest", answers: { q1: { type: "noul", noul: 0.1 } }, usage: { input_tokens: 1, output_tokens: 1 } })]);
    const transport = createTypeSafeJevTransport(FAKE_KEY, { fetch });
    await transport.systemOne({ state: "some evidence text", questions: { q1: noul("q?") } }, { timeoutMs: 2000 });
    const call = calls[0];
    expect(call).toBeDefined();
    const bodyText = typeof call?.init?.body === "string" ? call.init.body : "";
    expect(bodyText).not.toContain(FAKE_KEY);
  });

  it("carries the key only in the Authorization header, never logged at the client's fixed \"warn\" level", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => undefined);
    const debugSpy = vi.spyOn(console, "debug").mockImplementation(() => undefined);
    try {
      const { fetch, calls } = fakeFetch([jsonResponse({ model: "jev-latest", answers: { q1: { type: "noul", noul: 0.1 } }, usage: { input_tokens: 1, output_tokens: 1 } })]);
      const transport = createTypeSafeJevTransport(FAKE_KEY, { fetch });
      await transport.systemOne({ state: "x", questions: { q1: noul("q?") } }, { timeoutMs: 2000 });

      const headers = calls[0]?.init?.headers;
      const authHeader =
        headers instanceof Headers
          ? headers.get("authorization")
          : Array.isArray(headers)
            ? (headers.find(([k]) => k?.toLowerCase() === "authorization")?.[1] ?? undefined)
            : headers !== undefined
              ? ((headers as Record<string, string>)["authorization"] ?? (headers as Record<string, string>)["Authorization"])
              : undefined;
      expect(authHeader).toBe(`Bearer ${FAKE_KEY}`);

      for (const spy of [logSpy, infoSpy, debugSpy]) {
        for (const call of spy.mock.calls) {
          for (const arg of call) {
            expect(String(arg)).not.toContain(FAKE_KEY);
          }
        }
      }
      // "warn" level logs nothing on a clean success — request/response
      // summaries only appear at "info" and above, which is disabled.
      expect(logSpy).not.toHaveBeenCalled();
      expect(infoSpy).not.toHaveBeenCalled();
      expect(debugSpy).not.toHaveBeenCalled();
    } finally {
      logSpy.mockRestore();
      infoSpy.mockRestore();
      debugSpy.mockRestore();
    }
  });
});
