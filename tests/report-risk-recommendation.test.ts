import { describe, expect, it } from "vitest";
import { computeRiskScore } from "../src/report/risk-score.ts";
import { buildRecommendations } from "../src/report/recommendation-policy.ts";
import type { CaseOutcome } from "../src/pipeline/assess.ts";

function ruleOutcome(
  caseId: string,
  opts: { hardFail?: boolean; judge?: CaseOutcome["judgeResult"]; judgeError?: CaseOutcome["judgeError"]; finding?: CaseOutcome["finding"]; review?: CaseOutcome["review"] } = {},
): CaseOutcome {
  return {
    caseId,
    events: [],
    ruleResults: opts.hardFail === true ? [{ ruleId: "hr_x", ruleVersion: "1", caseId, outcome: "fail", reasonCode: "bad", evidenceRefs: [] }] : [{ ruleId: "hr_x", ruleVersion: "1", caseId, outcome: "pass", reasonCode: "ok", evidenceRefs: [] }],
    judgeResult: opts.judge,
    judgeError: opts.judgeError,
    finding: opts.finding,
    review: opts.review,
  };
}

const passJudge: CaseOutcome["judgeResult"] = { judgeId: "j", judgeVersion: "1", caseId: "x", label: "pass", confidence: 0.9, reasonCodes: [], evidenceRefs: [], modelMetadata: {} };
const failJudge = (confidence: number): CaseOutcome["judgeResult"] => ({ judgeId: "j", judgeVersion: "1", caseId: "x", label: "fail", confidence, reasonCodes: [], evidenceRefs: [], modelMetadata: {} });
const uncertainJudge = (confidence: number): CaseOutcome["judgeResult"] => ({ judgeId: "j", judgeVersion: "1", caseId: "x", label: "uncertain", confidence, reasonCodes: [], evidenceRefs: [], modelMetadata: {} });

describe("risk score — deterministic, max-aggregated", () => {
  it("is 0 for an empty run", () => {
    expect(computeRiskScore([])).toBe(0);
  });

  it("is 0 when every case passes", () => {
    const cases = [ruleOutcome("a", { judge: passJudge }), ruleOutcome("b", { judge: passJudge })];
    expect(computeRiskScore(cases.map((outcome) => ({ outcome })))).toBe(0);
  });

  it("is 1.0 for any hard-rule failure, regardless of judge", () => {
    const cases = [ruleOutcome("a", { hardFail: true, judge: passJudge })];
    expect(computeRiskScore(cases.map((outcome) => ({ outcome })))).toBe(1);
  });

  it("uses the judge fail confidence when there is no hard-rule failure", () => {
    const cases = [ruleOutcome("a", { judge: failJudge(0.83) })];
    expect(computeRiskScore(cases.map((outcome) => ({ outcome })))).toBe(0.83);
  });

  it("uses the judge uncertain confidence as a concern-level proxy", () => {
    const cases = [ruleOutcome("a", { judge: uncertainJudge(0.5) })];
    expect(computeRiskScore(cases.map((outcome) => ({ outcome })))).toBe(0.5);
  });

  it("never averages away one severe case among many clean ones", () => {
    const cases = [ruleOutcome("a", { judge: passJudge }), ruleOutcome("b", { hardFail: true, judge: passJudge }), ruleOutcome("c", { judge: passJudge })];
    const score = computeRiskScore(cases.map((outcome) => ({ outcome })));
    expect(score).toBe(1);
    expect(score).not.toBeCloseTo(1 / 3, 2);
  });

  it("scores a judge error (fail-closed uncertain, confidence hardcoded to 0) at maximum concern, not zero", () => {
    // assess.ts's envelope-error fallback always sets confidence: 0 on the
    // uncertain JudgeResult it manufactures — that 0 must never read as
    // "no risk" for a case the harness could not actually verify.
    const erroredJudge: CaseOutcome["judgeResult"] = { judgeId: "jev", judgeVersion: "2.0.0", caseId: "a", label: "uncertain", confidence: 0, reasonCodes: ["judge_error:jev_transport_timeout"], evidenceRefs: [], modelMetadata: {} };
    const cases = [ruleOutcome("a", { judge: erroredJudge, judgeError: { code: "jev_transport_timeout", message: "timed out", timeout: true } })];
    expect(computeRiskScore(cases.map((outcome) => ({ outcome })))).toBe(1);
  });
});

describe("recommendation policy — deterministic mapping", () => {
  it("recommends block_release for any case with a hard-rule failure", () => {
    const recs = buildRecommendations([ruleOutcome("a", { hardFail: true })], "run1");
    const caseRec = recs.find((r) => r.scope === "case" && r.caseId === "a");
    expect(caseRec?.action).toBe("block_release");
  });

  it("recommends human_review_required for a finding with a pending review", () => {
    const finding: NonNullable<CaseOutcome["finding"]> = {
      findingId: "f1", runId: "r", caseId: "a", category: "policy_bypass", severity: "medium", status: "open", confidence: 0.7,
      affectedControl: "x", reasonCodes: [], reproductionSteps: [], evidenceRefs: [], source: "judge",
    };
    const review: NonNullable<CaseOutcome["review"]> = { reviewId: "rev1", findingRef: "f1", reason: "low_confidence", createdAt: "2026-01-01T00:00:00Z", status: "pending" };
    const recs = buildRecommendations([ruleOutcome("a", { finding, review })], "run1");
    const caseRec = recs.find((r) => r.scope === "case" && r.caseId === "a");
    expect(caseRec?.action).toBe("human_review_required");
  });

  it("recommends monitor for a judge-only finding with no review", () => {
    const finding: NonNullable<CaseOutcome["finding"]> = {
      findingId: "f1", runId: "r", caseId: "a", category: "policy_bypass", severity: "medium", status: "open", confidence: 0.7,
      affectedControl: "x", reasonCodes: [], reproductionSteps: [], evidenceRefs: [], source: "judge",
    };
    const recs = buildRecommendations([ruleOutcome("a", { finding })], "run1");
    const caseRec = recs.find((r) => r.scope === "case" && r.caseId === "a");
    expect(caseRec?.action).toBe("monitor");
  });

  it("recommends human_review_required for a review without a finding", () => {
    const review: NonNullable<CaseOutcome["review"]> = { reviewId: "rev1", findingRef: "f1", reason: "ambiguous_case", createdAt: "2026-01-01T00:00:00Z", status: "pending" };
    const recs = buildRecommendations([ruleOutcome("a", { review })], "run1");
    const caseRec = recs.find((r) => r.scope === "case" && r.caseId === "a");
    expect(caseRec?.action).toBe("human_review_required");
  });

  it("emits no case-level recommendation and no_action is not listed for a clean case", () => {
    const recs = buildRecommendations([ruleOutcome("a", { judge: passJudge })], "run1");
    expect(recs.find((r) => r.scope === "case" && r.caseId === "a")).toBeUndefined();
  });

  it("always includes exactly one run-level recommendation reporting the worst case action", () => {
    const recs = buildRecommendations([ruleOutcome("a", { judge: passJudge }), ruleOutcome("b", { hardFail: true })], "run1");
    const runRecs = recs.filter((r) => r.scope === "run");
    expect(runRecs.length).toBe(1);
    expect(runRecs[0]?.action).toBe("block_release");
  });

  it("run-level recommendation is no_action when every case is clean", () => {
    const recs = buildRecommendations([ruleOutcome("a", { judge: passJudge })], "run1");
    const runRec = recs.find((r) => r.scope === "run");
    expect(runRec?.action).toBe("no_action");
  });
});
