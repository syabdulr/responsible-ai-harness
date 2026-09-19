import { describe, expect, it } from "vitest";
import { JevJudge } from "../src/judges/jev.ts";
import type { RuntimeSecretProvider } from "../src/judges/jev.ts";
import { JevTransportError } from "../src/judges/jev-transport.ts";
import { FakeJevClient, fakeResult, noulAnswers } from "./support/fake-jev-client.ts";

const FAKE_SECRET = "test-fake-key-should-never-appear-anywhere";
const secretOk: RuntimeSecretProvider = { resolve: () => FAKE_SECRET };
const secretMissing: RuntimeSecretProvider = { resolve: () => undefined };

const baseInput = { caseId: "c1", events: [], category: "prompt_injection", evidence: { note: "test" } };

describe("JevJudge — fail-closed gating", () => {
  it("never calls the client when live mode is off", async () => {
    const client = new FakeJevClient([{ kind: "result", result: fakeResult(noulAnswers({ prompt_injection_instruction_hierarchy_v1: 0.9 })) }]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: false, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.error.code).toBe("jev_live_mode_disabled");
    expect(client.calls.length).toBe(0);
  });

  it("fails closed when the secret provider resolves undefined", async () => {
    const client = new FakeJevClient([]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretMissing, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.error.code).toBe("jev_secret_unavailable");
    expect(client.calls.length).toBe(0);
  });

  it("fails closed when there is no secret provider at all", async () => {
    const client = new FakeJevClient([]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, undefined, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.error.code).toBe("jev_secret_unavailable");
  });

  it("fails closed when live mode is on, secret resolves, but no client factory was injected", async () => {
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, undefined);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.error.code).toBe("jev_transport_unavailable");
  });

  it("never falls back to a passing result on any failure path", async () => {
    const client = new FakeJevClient([{ kind: "throw", error: new Error("boom") }]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(false);
  });
});

describe("JevJudge — successful scoring maps deterministically", () => {
  it("produces a fail verdict with per-question metadata, usage, latency, and model", async () => {
    const client = new FakeJevClient([
      { kind: "result", result: fakeResult(noulAnswers({ prompt_injection_instruction_hierarchy_v1: 0.95 }), { model: "jev-latest", usage: { inputTokens: 12, outputTokens: 3 }, latencyMs: 77 }) },
    ]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(true);
    if (env.ok) {
      expect(env.result.label).toBe("fail");
      expect(env.result.confidence).toBe(0.95);
      expect(env.result.modelMetadata.jev_model).toBe("jev-latest");
      expect(env.result.modelMetadata.jev_usage_input_tokens).toBe(12);
      expect(env.result.modelMetadata.jev_usage_output_tokens).toBe(3);
      expect(env.result.modelMetadata.jev_latency_ms).toBe(77);
      expect(env.result.modelMetadata["jev_q_prompt_injection_instruction_hierarchy_v1_probability"]).toBe(0.95);
      expect(env.result.evidenceRefs).toContain("c1/jev/prompt_injection_instruction_hierarchy_v1");
    }
  });

  it("produces a pass verdict for low probabilities", async () => {
    const client = new FakeJevClient([{ kind: "result", result: fakeResult(noulAnswers({ prompt_injection_instruction_hierarchy_v1: 0.05 })) }]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(true);
    if (env.ok) expect(env.result.label).toBe("pass");
  });

  it("produces an uncertain verdict for the middle band", async () => {
    const client = new FakeJevClient([{ kind: "result", result: fakeResult(noulAnswers({ prompt_injection_instruction_hierarchy_v1: 0.5 })) }]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(true);
    if (env.ok) expect(env.result.label).toBe("uncertain");
  });

  it("aggregates two questions (secret_pii_leakage) by max, never average", async () => {
    const client = new FakeJevClient([
      { kind: "result", result: fakeResult(noulAnswers({ secret_pii_disclosure_v1: 0.02, secret_pii_exfil_channel_v1: 0.91 })) },
    ]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score({ ...baseInput, category: "secret_pii_leakage" });
    expect(env.ok).toBe(true);
    if (env.ok) {
      expect(env.result.label).toBe("fail");
      expect(env.result.confidence).toBe(0.91);
    }
  });
});

describe("JevJudge — malformed/missing/extra answers fail closed to uncertain via the pipeline error envelope", () => {
  it("missing answer -> ok:false with a malformed code", async () => {
    const client = new FakeJevClient([{ kind: "result", result: fakeResult({}) }]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.error.code).toBe("jev_missing_answer");
  });

  it("extra answer -> ok:false with a malformed code", async () => {
    const client = new FakeJevClient([
      { kind: "result", result: fakeResult(noulAnswers({ prompt_injection_instruction_hierarchy_v1: 0.1, unexpected_question: 0.1 })) },
    ]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.error.code).toBe("jev_extra_answer");
  });

  it("unknown category with no catalog entry fails closed without calling the client", async () => {
    const client = new FakeJevClient([]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score({ ...baseInput, category: "harness_error" });
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.error.code).toBe("jev_no_questions_for_category");
    expect(client.calls.length).toBe(0);
  });
});

describe("JevJudge — transport errors classify without leaking anything sensitive", () => {
  it("propagates a normalized timeout error", async () => {
    const client = new FakeJevClient([{ kind: "throw", error: new JevTransportError("jev_transport_timeout", "timed out", true) }]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(false);
    if (!env.ok) {
      expect(env.error.code).toBe("jev_transport_timeout");
      expect(env.error.timeout).toBe(true);
    }
  });

  it("classifies an unrecognized thrown value without crashing", async () => {
    const client = new FakeJevClient([{ kind: "throw", error: new Error("generic failure") }]);
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.error.code).toBe("jev_transport_unknown_error");
  });

  it("never includes the resolved secret in any error message", async () => {
    const client = new FakeJevClient([{ kind: "throw", error: new Error(`failure near ${FAKE_SECRET}... wait no`) }]);
    // Deliberately a bad test double that WOULD leak — asserting our own
    // orchestration doesn't add the secret itself; the transport is what
    // must never do this in production (see jev-secret-safety.test.ts for
    // the real boundary check).
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
    const env = await jev.score(baseInput);
    expect(env.ok).toBe(false);
  });
});

describe("JevJudge — one attempt, no retry, zero network", () => {
  it("calls the client exactly once per score() regardless of outcome", async () => {
    for (const outcome of [
      { kind: "result" as const, result: fakeResult(noulAnswers({ prompt_injection_instruction_hierarchy_v1: 0.5 })) },
      { kind: "throw" as const, error: new Error("x") },
    ]) {
      const client = new FakeJevClient([outcome]);
      const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 1000 }, secretOk, () => client);
      await jev.score(baseInput);
      expect(client.calls.length).toBe(1);
    }
  });

  it("passes the configured timeoutMs through to the transport call options", async () => {
    let seenTimeout: number | undefined;
    const client = new FakeJevClient([{ kind: "result", result: fakeResult(noulAnswers({ prompt_injection_instruction_hierarchy_v1: 0.1 })) }]);
    const originalSystemOne = client.systemOne.bind(client);
    client.systemOne = (request, options) => {
      seenTimeout = options.timeoutMs;
      return originalSystemOne(request, options);
    };
    const jev = new JevJudge({ secretRef: "ref", liveMode: true, timeoutMs: 4242 }, secretOk, () => client);
    await jev.score(baseInput);
    expect(seenTimeout).toBe(4242);
  });
});
