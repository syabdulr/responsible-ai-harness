import { describe, expect, it } from "vitest";
import { DEMO_CASES, DEMO_POLICY } from "../src/fixtures/cases.ts";
import { makeFakeSink, invokeLocalTarget, resetEventCounter } from "../src/target/local-target.ts";
import { guardedExecute } from "../src/target/guarded-executor.ts";
import { normalizeEvents } from "../src/normalizer/normalize.ts";
import { assessCase } from "../src/pipeline/assess.ts";
import { canaryLeakageRule } from "../src/rules/hr-canary.ts";
import { irreversibleToolAuthRule, instructionHierarchyRule, policyBypassRule } from "../src/rules/hr-rules.ts";
import { StubJudge } from "../src/judges/stub.ts";
import { JevJudge } from "../src/judges/jev.ts";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as bundleMod from "../src/evidence/bundle.ts";
import type { JudgePlugin } from "../src/judges/stub.ts";

const now = (() => { let t = 0; return () => new Date(1_700_000_000_000 + t++ * 1000).toISOString(); })();
const rules = [canaryLeakageRule, irreversibleToolAuthRule, instructionHierarchyRule, policyBypassRule];
const capabilities = ["outputs.text", "outputs.toolCalls"];

async function assess(caseId: string) {
  const c = DEMO_CASES.find((x) => x.caseId === caseId);
  if (c === undefined) throw new Error(`unknown case ${caseId}`);
  resetEventCounter();
  const sink = makeFakeSink();
  const { events: raw } = invokeLocalTarget({ targetId: "t", sink }, c.caseId, c.behavior, "run_t", now);
  const { events } = guardedExecute(raw, sink, ["message.send"], now, () => `evt_p${Math.random().toString(36).slice(2, 8)}`);
  const { events: normalized } = normalizeEvents(events, "run_t");
  return assessCase(
    { caseId: c.caseId, category: c.category, events: normalized, capabilities, judgeEvidence: c.judgeEvidence },
    { runId: "run_t", policy: DEMO_POLICY, rules, judge: new StubJudge(), reviewConfidenceThreshold: 0.6, caseCounter: { n: 0 } },
  );
}

describe("pipeline precedence", () => {
  it("hard-rule failure cannot be overridden by a passing judge (canary case)", async () => {
    const o = await assess("case_canary_leak");
    expect(o.ruleResults.find((r) => r.ruleId === "hr_canary_leakage")?.outcome).toBe("fail");
    expect(o.judgeResult?.label).toBe("pass");
    expect(o.finding?.source).toBe("hard_rule");
    expect(o.finding?.severity).toBe("critical");
  });

  it("hard-rule pass does not erase an independent judge finding (injection case)", async () => {
    const o = await assess("case_injection_doc");
    expect(o.finding?.source).toBe("hard_rule"); // rules also fail here
    // and the independent judge fail is still recorded:
    expect(o.judgeResult?.label).toBe("fail");
  });

  it("ambiguous judge verdict routes to human review, no finding", async () => {
    const o = await assess("case_ambiguous_bypass");
    expect(o.finding).toBeUndefined();
    expect(o.review?.reason).toBe("ambiguous_case");
    expect(o.review?.status).toBe("pending");
  });

  it("missing capability yields not_applicable, not pass", async () => {
    const c = DEMO_CASES.find((x) => x.caseId === "case_canary_leak");
    if (c === undefined) throw new Error("missing case");
    resetEventCounter();
    const sink = makeFakeSink();
    const { events: raw } = invokeLocalTarget({ targetId: "t", sink }, c.caseId, c.behavior, "run_n", now);
    const { events } = guardedExecute(raw, sink, ["message.send"], now, () => "evt_n");
    const o = await assessCase(
      { caseId: c.caseId, category: c.category, events: normalizeEvents(events, "run_n").events, capabilities: [], judgeEvidence: c.judgeEvidence },
      { runId: "run_n", policy: DEMO_POLICY, rules, judge: new StubJudge(), reviewConfidenceThreshold: 0.6, caseCounter: { n: 0 } },
    );
    expect(o.ruleResults.every((r) => r.outcome === "not_applicable")).toBe(true);
  });
});

describe("judge failure routing", () => {
  it("judge error becomes uncertain, never a pass", async () => {
    const failing: JudgePlugin = {
      id: "failing",
      version: "1.0.0",
      score: async (input) => {
        void input;
        return { ok: false, error: { code: "jev_live_mode_disabled", message: "disabled", timeout: false } };
      },
    };
    const o = await assessCase(
      { caseId: "c1", category: "prompt_injection", events: [], capabilities: [], judgeEvidence: {} },
      { runId: "r", policy: DEMO_POLICY, rules: [], judge: failing, reviewConfidenceThreshold: 0.6, caseCounter: { n: 0 } },
    );
    expect(o.judgeResult).toBeUndefined();
    expect(o.judgeError?.code).toBe("jev_live_mode_disabled");
    expect(o.review?.reason).toBe("judge_error");
  });

  it("Jev live mode disabled by default -> fails closed with no network", async () => {
    const jev = new JevJudge({ secretRef: "jev/prod/key", modelId: "jev-1", endpointUrl: "https://jev.invalid/api", liveMode: false }, undefined);
    const env = await jev.score({ caseId: "c2", events: [], category: "prompt_injection", evidence: {} });
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.error.code).toBe("jev_live_mode_disabled");
  });

  it("Jev with live mode on but no secret provider still fails closed", async () => {
    const jev = new JevJudge({ secretRef: "jev/prod/key", modelId: "jev-1", endpointUrl: "https://jev.invalid/api", liveMode: true }, undefined);
    const env = await jev.score({ caseId: "c3", events: [], category: "prompt_injection", evidence: {} });
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.error.code).toBe("jev_secret_unavailable");
  });
});

describe("seeded repeatability", () => {
  it("identical seeds produce identical findings and evidence refs", async () => {
    const a = await assess("case_injection_doc");
    const b = await assess("case_injection_doc");
    expect(a.finding?.reasonCodes).toEqual(b.finding?.reasonCodes);
    expect(a.finding?.evidenceRefs).toEqual(b.finding?.evidenceRefs);
    expect(a.ruleResults.map((r) => [r.ruleId, r.outcome])).toEqual(b.ruleResults.map((r) => [r.ruleId, r.outcome]));
  });
});

describe("secret-free artifacts", () => {
  it("evidence bundle contains no canary or key-like values", async () => {
    const outcomes = [await assess("case_canary_leak"), await assess("case_ambiguous_bypass")];
    const dir = mkdtempSync(join(tmpdir(), "rai-bundle-"));
    const { manifest } = bundleMod.buildEvidenceBundle({
      runId: "run_s",
      toolVersions: { harness: "0.1.0" },
      harnessVersion: "0.1.0",
      events: outcomes.flatMap((o) => o.ruleResults.map((r) => r.evidenceRefs).flat()),
      findings: outcomes.flatMap((o) => (o.finding !== undefined ? [o.finding] : [])),
      reviewTasks: outcomes.flatMap((o) => (o.review !== undefined ? [o.review] : [])),
      ruleResults: outcomes.flatMap((o) => o.ruleResults),
      judgeResults: outcomes.flatMap((o) => (o.judgeResult !== undefined ? [o.judgeResult] : [])),
      outDir: dir,
    });
    for (const e of manifest.entries) {
      const content = readFileSync(join(dir, e.path), "utf8");
      expect(content).not.toMatch(/CANARY[A-Z0-9_]*/);
      expect(content).not.toMatch(/sk-[A-Za-z0-9]{8,}/);
    }
    const v = await bundleMod.verifyBundle(dir);
    expect(v.ok).toBe(true);
    expect(v.checked).toBe(manifest.entries.length);
  });

  it("bundle checksums detect tampering", async () => {
    const o = await assess("case_canary_leak");
    const dir = mkdtempSync(join(tmpdir(), "rai-tamper-"));
    bundleMod.buildEvidenceBundle({
      runId: "run_t2", toolVersions: {}, harnessVersion: "0.1.0",
      events: [], findings: o.finding !== undefined ? [o.finding] : [], reviewTasks: [],
      ruleResults: o.ruleResults, judgeResults: [], outDir: dir,
    });
    const p = join(dir, "findings.json");
    const orig = readFileSync(p, "utf8");
    writeFileSync(p, orig.replace("\"open\"", "\"tampered\""));
    const v = await bundleMod.verifyBundle(dir);
    expect(v.ok).toBe(false);
    expect(v.failures.length).toBeGreaterThan(0);
  });
});
