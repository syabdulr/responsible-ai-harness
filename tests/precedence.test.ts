import { describe, expect, it } from "vitest";
import type { CanonicalEvent, FindingCategory, JudgeEnvelope } from "../src/contracts/types.ts";
import type { HardRule } from "../src/rules/types.ts";
import type { JudgePlugin } from "../src/judges/stub.ts";
import { assessCase } from "../src/pipeline/assess.ts";
import { DEMO_POLICY } from "../src/fixtures/cases.ts";

const now = () => "2026-01-01T00:00:00.000Z";

function mkEvent(overrides: Partial<CanonicalEvent> = {}): CanonicalEvent {
  return {
    schemaVersion: "1.0",
    eventId: "evt_1",
    runId: "run_p",
    sequence: 1,
    timestamp: now(),
    type: "message.output",
    actor: "assistant",
    content: {},
    ...overrides,
  };
}

const passRule: HardRule = {
  id: "hr_always_pass",
  version: "1.0.0",
  requiredCapability: "outputs.text",
  evaluate: (_events, _policy, caseId) => ({
    ruleId: "hr_always_pass", ruleVersion: "1.0.0", caseId,
    outcome: "pass", reasonCode: "no_violation", evidenceRefs: ["evt_1"],
  }),
};

const failRule: HardRule = {
  id: "hr_always_fail",
  version: "1.0.0",
  requiredCapability: "outputs.text",
  evaluate: (_events, _policy, caseId) => ({
    ruleId: "hr_always_fail", ruleVersion: "1.0.0", caseId,
    outcome: "fail", reasonCode: "synthetic_fail", evidenceRefs: ["evt_1"],
  }),
};

const errorRule: HardRule = {
  id: "hr_throws",
  version: "1.0.0",
  requiredCapability: "outputs.text",
  evaluate: (_events, _policy, caseId) => ({
    ruleId: "hr_throws", ruleVersion: "1.0.0", caseId,
    outcome: "error", reasonCode: "rule_crashed", evidenceRefs: [],
  }),
};

function mkJudge(label: "pass" | "fail" | "uncertain", confidence: number, evidenceRefs: string[] = ["evt_j"]): JudgePlugin {
  return {
    id: "tj",
    version: "1.0.0",
    async score(input) {
      const env: JudgeEnvelope = {
        ok: true,
        result: {
          judgeId: "tj", judgeVersion: "1.0.0", caseId: input.caseId,
          label, confidence,
          reasonCodes: [`judge_${label}`],
          evidenceRefs,
          modelMetadata: {},
        },
      };
      return env;
    },
  };
}

function assessWith(rules: HardRule[], judge: JudgePlugin, category: FindingCategory = "prompt_injection") {
  return assessCase(
    { caseId: "case_p", category, events: [mkEvent()], capabilities: ["outputs.text"], judgeEvidence: {} },
    { runId: "run_p", policy: DEMO_POLICY, rules, judge, reviewConfidenceThreshold: 0.6, caseCounter: { n: 0 } },
  );
}

describe("rule/judge precedence (P0 #5)", () => {
  it("hard-rule fail + judge pass => finding AND rule_judge_conflict review", async () => {
    const o = await assessWith([failRule], mkJudge("pass", 0.99));
    expect(o.finding?.source).toBe("hard_rule");
    expect(o.finding?.severity).toBe("high");
    expect(o.review?.reason).toBe("rule_judge_conflict");
    expect(o.review?.status).toBe("pending");
  });

  it("hard-rule fail + independent judge fail => finding preserves BOTH sources", async () => {
    const o = await assessWith([failRule], mkJudge("fail", 0.9, ["evt_j1", "evt_1"]));
    expect(o.finding?.source).toBe("hard_rule");
    expect(o.finding?.reasonCodes).toContain("synthetic_fail");
    expect(o.finding?.reasonCodes).toContain("judge_fail");
    // evidence merged, deduped
    expect(o.finding?.evidenceRefs).toContain("evt_1");
    expect(o.finding?.evidenceRefs).toContain("evt_j1");
    expect(new Set(o.finding?.evidenceRefs).size).toBe(o.finding?.evidenceRefs.length);
    expect(o.review).toBeUndefined();
  });

  it("hard-rule fail in a sensitive category => sensitive_evidence review", async () => {
    const o = await assessWith([failRule], mkJudge("fail", 0.95), "secret_pii_leakage");
    expect(o.finding?.severity).toBe("critical");
    expect(o.review?.reason).toBe("sensitive_evidence");
  });

  it("rule error routes to review (never silent pass)", async () => {
    const o = await assessWith([errorRule], mkJudge("pass", 0.99));
    expect(o.ruleResults[0]?.outcome).toBe("error");
    expect(o.review?.reason).toBe("rule_error");
    expect(o.finding).toBeUndefined();
  });

  it("judge error => uncertain result, review required, never a pass", async () => {
    const judge: JudgePlugin = {
      id: "broken", version: "1.0.0",
      async score(input) {
        void input;
        return { ok: false, error: { code: "judge_crashed", message: "boom", timeout: false } };
      },
    };
    const o = await assessWith([passRule], judge);
    expect(o.judgeResult?.label).toBe("uncertain");
    expect(o.judgeError?.code).toBe("judge_crashed");
    expect(o.review?.reason).toBe("judge_error");
    expect(o.finding).toBeUndefined();
  });

  it("judge timeout => uncertain + judge_timeout review", async () => {
    const judge: JudgePlugin = {
      id: "slow", version: "1.0.0",
      async score(input) {
        void input;
        return { ok: false, error: { code: "judge_timeout", message: "too slow", timeout: true } };
      },
    };
    const o = await assessWith([passRule], judge);
    expect(o.judgeResult?.label).toBe("uncertain");
    expect(o.review?.reason).toBe("judge_timeout");
  });

  it("judge fail with low confidence => finding + low_confidence review", async () => {
    const o = await assessWith([passRule], mkJudge("fail", 0.4));
    expect(o.finding?.source).toBe("judge");
    expect(o.review?.reason).toBe("low_confidence");
  });

  it("judge pass + rules pass + high confidence => clean, no review", async () => {
    const o = await assessWith([passRule], mkJudge("pass", 0.95));
    expect(o.finding).toBeUndefined();
    expect(o.review).toBeUndefined();
  });

  it("hard-rule fail takes priority over rule error routing (fail wins)", async () => {
    const o = await assessWith([failRule, errorRule], mkJudge("pass", 0.99));
    expect(o.finding?.source).toBe("hard_rule");
    expect(o.review?.reason).toBe("rule_judge_conflict");
  });

  it("judge uncertain (ambiguous) with rules passing => ambiguous_case review", async () => {
    const o = await assessWith([passRule], mkJudge("uncertain", 0.45));
    expect(o.finding).toBeUndefined();
    expect(o.review?.reason).toBe("ambiguous_case");
  });
});
