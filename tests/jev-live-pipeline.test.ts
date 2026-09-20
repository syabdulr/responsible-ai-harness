import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runDemoPipeline } from "../scripts/lib/demo-bundle.ts";
import { DEMO_CASES } from "../src/fixtures/cases.ts";
import { JevJudge } from "../src/judges/jev.ts";
import { buildJevEvidence } from "../src/judges/evidence-mapper.ts";
import { CATEGORY_QUESTION_IDS, JEV_QUESTION_CATALOG_VERSION } from "../src/judges/jev-questions.ts";
import { FakeJevClient, fakeResult, noulAnswers } from "./support/fake-jev-client.ts";
import type { CaseOutcome } from "../src/pipeline/assess.ts";

const FAKE_SECRET = "test-fake-key-never-real";

/** Builds the live-shaped call: real orchestration, real evidence mapper, FAKE transport (zero network). */
function buildLiveJudge(client: FakeJevClient) {
  return new JevJudge({ secretRef: "jev/test", liveMode: true, timeoutMs: 5000 }, { resolve: () => FAKE_SECRET }, () => client);
}

describe("live Jev pipeline — exactly one call per case, catalog 2.0.0 question counts [2,2,3,1]", () => {
  it("runs all four fixed demo cases through one JevJudge.score() call each, sequential, no retries", async () => {
    expect(JEV_QUESTION_CATALOG_VERSION).toBe("2.0.0");
    expect(DEMO_CASES.map((c) => c.caseId)).toEqual(["case_injection_doc", "case_canary_leak", "case_unauthorized_send", "case_ambiguous_bypass"]);

    // Scripted with plausible pass-band probabilities so the run completes cleanly.
    const script = DEMO_CASES.map((c) => {
      const ids = CATEGORY_QUESTION_IDS[c.category];
      return { kind: "result" as const, result: fakeResult(noulAnswers(Object.fromEntries(ids.map((id) => [id, 0.05])))) };
    });
    const client = new FakeJevClient(script);
    const judge = buildLiveJudge(client);

    const outDir = mkdtempSync(join(tmpdir(), "rai-live-"));
    const result = await runDemoPipeline({
      outDir,
      judge,
      buildJudgeEvidence: (c, events) => buildJevEvidence(c.caseId, c.category, events),
    });

    // Exactly 4 calls total, one per case.
    expect(client.calls).toHaveLength(4);

    // Question counts per call match the catalog: [2, 2, 3, 1] in case order.
    const questionCounts = client.calls.map((call) => Object.keys(call.questions).length);
    expect(questionCounts).toEqual([2, 2, 3, 1]);

    // Every case actually got a judge result (fail-closed pipeline never skips scoring).
    expect(result.outcomes).toHaveLength(4);
    for (const { outcome } of result.outcomes) {
      expect(outcome.judgeResult).toBeDefined();
      expect(outcome.judgeResult?.judgeId).toBe("jev");
    }

    // Bundle + report still self-verify through the unmodified evidence/report pipeline.
    expect(result.verify.ok).toBe(true);
  });

  it("evidence sent per case never includes the judge_hint fixture marker", async () => {
    const script = DEMO_CASES.map((c) => ({
      kind: "result" as const,
      result: fakeResult(noulAnswers(Object.fromEntries(CATEGORY_QUESTION_IDS[c.category].map((id) => [id, 0.05])))),
    }));
    const client = new FakeJevClient(script);
    const judge = buildLiveJudge(client);
    const outDir = mkdtempSync(join(tmpdir(), "rai-live-noh-"));
    await runDemoPipeline({ outDir, judge, buildJudgeEvidence: (c, events) => buildJevEvidence(c.caseId, c.category, events) });

    for (const call of client.calls) {
      const state = call.state as Record<string, unknown>;
      expect(state).not.toHaveProperty("judge_hint");
      const evidence = state.evidence as Record<string, unknown>;
      expect(evidence).not.toHaveProperty("judge_hint");
    }
  });
});

describe("live Jev pipeline — a failed or malformed call becomes uncertain + review, never a pass", () => {
  it("a thrown transport error never produces a pass and always routes to review", async () => {
    const script = [
      { kind: "throw" as const, error: new Error("simulated network failure") },
      ...DEMO_CASES.slice(1).map((c) => ({
        kind: "result" as const,
        result: fakeResult(noulAnswers(Object.fromEntries(CATEGORY_QUESTION_IDS[c.category].map((id) => [id, 0.05])))),
      })),
    ];
    const client = new FakeJevClient(script);
    const judge = buildLiveJudge(client);
    const outDir = mkdtempSync(join(tmpdir(), "rai-live-fail-"));
    const result = await runDemoPipeline({ outDir, judge, buildJudgeEvidence: (c, events) => buildJevEvidence(c.caseId, c.category, events) });

    const first = result.outcomes[0]?.outcome as CaseOutcome;
    expect(first.judgeResult?.label).toBe("uncertain");
    expect(first.judgeResult?.confidence).toBe(0);
    expect(first.judgeResult?.label).not.toBe("pass");
    expect(first.review).toBeDefined();
  });

  it("a malformed answers payload never produces a pass and always routes to review", async () => {
    const script = [
      { kind: "result" as const, result: fakeResult({ not: "a noul answer set" }) },
      ...DEMO_CASES.slice(1).map((c) => ({
        kind: "result" as const,
        result: fakeResult(noulAnswers(Object.fromEntries(CATEGORY_QUESTION_IDS[c.category].map((id) => [id, 0.05])))),
      })),
    ];
    const client = new FakeJevClient(script);
    const judge = buildLiveJudge(client);
    const outDir = mkdtempSync(join(tmpdir(), "rai-live-malformed-"));
    const result = await runDemoPipeline({ outDir, judge, buildJudgeEvidence: (c, events) => buildJevEvidence(c.caseId, c.category, events) });

    const first = result.outcomes[0]?.outcome as CaseOutcome;
    expect(first.judgeResult?.label).toBe("uncertain");
    expect(first.review).toBeDefined();
  });
});

describe("assess-jev-live.ts — structural guarantees", () => {
  it("never imports StubJudge — a fallback to it is impossible, not just avoided (doc comments may still name it)", () => {
    const src = readFileSync(new URL("../scripts/assess-jev-live.ts", import.meta.url), "utf8");
    expect(src).not.toMatch(/^\s*import\b.*StubJudge/m);
    expect(src).not.toMatch(/from\s+["']..\/src\/judges\/stub\.ts["']/);
  });

  it("checks JEV_SMOKE_CONFIRM and TYPESAFE_API_KEY before constructing any Jev client", () => {
    const src = readFileSync(new URL("../scripts/assess-jev-live.ts", import.meta.url), "utf8");
    const gateIdx = src.indexOf("checkGate();");
    const clientIdx = src.indexOf("createTypeSafeJevTransport(key)");
    expect(gateIdx).toBeGreaterThan(-1);
    expect(clientIdx).toBeGreaterThan(-1);
    expect(gateIdx).toBeLessThan(clientIdx);
  });
});

describe("offline demo remains the default and is unaffected", () => {
  it("npm run demo's pipeline (no judge override) still uses StubJudge and its own toolVersions", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "rai-offline-default-"));
    const result = await runDemoPipeline({ outDir });
    for (const { outcome } of result.outcomes) {
      expect(outcome.judgeResult?.judgeId).toBe("stub-judge");
    }
    expect(result.manifest.toolVersions.stubJudge).toBe("1.0.0");
    expect(result.manifest.toolVersions.jev).toBeUndefined();
  });
});

describe("evidence-mapper writes usable evidence for every category present in DEMO_CASES", () => {
  it("category coverage exactly matches the catalog's [2,2,3,1] question layout", () => {
    const counts = DEMO_CASES.map((c) => CATEGORY_QUESTION_IDS[c.category].length);
    expect(counts).toEqual([2, 2, 3, 1]);
  });
});
