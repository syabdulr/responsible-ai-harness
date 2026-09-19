import { describe, expect, it } from "vitest";
import { buildReport, verifyReportIntegrity } from "../src/report/build-report.ts";
import { validateReport } from "../src/contracts/report-validation.ts";
import { REPORT_SCHEMA_VERSION } from "../src/contracts/report-types.ts";
import type { ReportV1 } from "../src/contracts/report-types.ts";
import type { CaseOutcome } from "../src/pipeline/assess.ts";

function outcomeWithHardFail(caseId: string): CaseOutcome {
  return {
    caseId,
    events: [],
    ruleResults: [{ ruleId: "hr_x", ruleVersion: "1.0.0", caseId, outcome: "fail", reasonCode: "bad_thing", evidenceRefs: [`${caseId}/evt_1`] }],
    judgeResult: { judgeId: "stub-judge", judgeVersion: "1.0.0", caseId, label: "pass", confidence: 0.88, reasonCodes: ["clean"], evidenceRefs: [`${caseId}/judged`], modelMetadata: {} },
    judgeError: undefined,
    finding: {
      findingId: `f_${caseId}`,
      runId: "r1",
      caseId,
      category: "unsafe_tool_use",
      severity: "high",
      status: "open",
      confidence: 1,
      affectedControl: "tool.message.send",
      reasonCodes: ["bad_thing"],
      reproductionSteps: ["step"],
      evidenceRefs: [`${caseId}/evt_1`],
      source: "hard_rule",
    },
    review: { reviewId: `rev_${caseId}`, findingRef: `f_${caseId}`, reason: "rule_judge_conflict", createdAt: "2026-01-01T00:00:00Z", status: "pending" },
  };
}

function cleanOutcome(caseId: string): CaseOutcome {
  return {
    caseId,
    events: [],
    ruleResults: [{ ruleId: "hr_x", ruleVersion: "1.0.0", caseId, outcome: "pass", reasonCode: "ok", evidenceRefs: [] }],
    judgeResult: {
      judgeId: "jev",
      judgeVersion: "2.0.0",
      caseId,
      label: "pass",
      confidence: 0.95,
      reasonCodes: ["jev_violation_probability_below_pass_threshold"],
      evidenceRefs: [`${caseId}/judged`],
      modelMetadata: { jev_model: "jev-latest", jev_usage_input_tokens: 10, jev_usage_output_tokens: 2, jev_latency_ms: 55, "jev_q_prompt_injection_treated_untrusted_as_authoritative_v1_probability": 0.05 },
    },
    judgeError: undefined,
    finding: undefined,
    review: undefined,
  };
}

function buildFixtureReport() {
  return buildReport({
    runId: "run_test_1",
    createdAt: "2026-01-01T00:00:00Z",
    harnessVersion: "0.1.0",
    toolVersions: { harness: "0.1.0" },
    cases: [
      { category: "unsafe_tool_use", outcome: outcomeWithHardFail("case_a") },
      { category: "prompt_injection", outcome: cleanOutcome("case_b") },
    ],
  });
}

describe("report.json contract", () => {
  it("builds a report that validates against the contract", () => {
    const report = buildFixtureReport();
    const check = validateReport(report);
    expect(check.ok).toBe(true);
  });

  it("uses the expected schema version", () => {
    const report = buildFixtureReport();
    expect(report.reportSchemaVersion).toBe(REPORT_SCHEMA_VERSION);
  });

  it("carries per-question probabilities for a Jev-judged case", () => {
    const report = buildFixtureReport();
    const caseB = report.cases.find((c) => c.caseId === "case_b");
    expect(caseB?.judge?.perQuestionProbabilities).toEqual([{ questionId: "prompt_injection_treated_untrusted_as_authoritative_v1", probability: 0.05 }]);
    expect(caseB?.judge?.model).toBe("jev-latest");
    expect(caseB?.judge?.usage).toEqual({ inputTokens: 10, outputTokens: 2 });
    expect(caseB?.judge?.latencyMs).toBe(55);
  });

  it("rejects an unsupported schema version", () => {
    const report = buildFixtureReport();
    const tampered = { ...report, reportSchemaVersion: "99.0.0" };
    const check = validateReport(tampered);
    expect(check.ok).toBe(false);
  });

  it("rejects a report missing required fields", () => {
    const check = validateReport({ reportSchemaVersion: REPORT_SCHEMA_VERSION });
    expect(check.ok).toBe(false);
  });

  it("rejects a case with an invalid category", () => {
    const report = buildFixtureReport();
    const tampered = { ...report, cases: [{ ...report.cases[0], category: "not_a_real_category" }] };
    const check = validateReport(tampered);
    expect(check.ok).toBe(false);
  });

  it("rejects a recommendation with an invalid action", () => {
    const report = buildFixtureReport();
    const tampered = { ...report, recommendations: [{ ...report.recommendations[0], action: "do_whatever" }] };
    const check = validateReport(tampered);
    expect(check.ok).toBe(false);
  });

  it("rejects an unknown top-level field", () => {
    const report = buildFixtureReport();
    const tampered = { ...report, extraField: "should not be here" };
    expect(validateReport(tampered).ok).toBe(false);
  });

  it("rejects an unknown field on a nested case", () => {
    const report = buildFixtureReport();
    const tampered = { ...report, cases: [{ ...report.cases[0], extraField: "nope" }, report.cases[1]] };
    expect(validateReport(tampered).ok).toBe(false);
  });

  it("rejects an unknown field on counts.bySeverity", () => {
    const report = buildFixtureReport();
    const tampered = { ...report, counts: { ...report.counts, bySeverity: { ...report.counts.bySeverity, extreme: 1 } } };
    expect(validateReport(tampered).ok).toBe(false);
  });

  it("rejects a fractional count where an integer is required", () => {
    const report = buildFixtureReport();
    const tampered = { ...report, counts: { ...report.counts, totalCases: 1.5 } };
    expect(validateReport(tampered).ok).toBe(false);
  });

  it("rejects a fractional token usage count", () => {
    const report = buildFixtureReport();
    const caseB = report.cases.find((c) => c.caseId === "case_b");
    if (caseB?.judge?.usage === undefined) throw new Error("fixture expected usage");
    const tampered = {
      ...report,
      cases: report.cases.map((c) => (c.caseId === "case_b" ? { ...c, judge: { ...c.judge, usage: { inputTokens: 1.5, outputTokens: 2 } } } : c)),
    };
    expect(validateReport(tampered).ok).toBe(false);
  });

  it("rejects a non-array reasonCodes element type", () => {
    const report = buildFixtureReport();
    const tampered = { ...report, recommendations: [{ ...report.recommendations[0], reasonCodes: [123] }, ...report.recommendations.slice(1)] };
    expect(validateReport(tampered).ok).toBe(false);
  });

  it("rejects a malformed (non-hex, wrong-length) integrity hash", () => {
    const report = buildFixtureReport();
    expect(validateReport({ ...report, integrity: { ...report.integrity, reportSha256: "not-a-real-hash" } }).ok).toBe(false);
    expect(validateReport({ ...report, integrity: { ...report.integrity, reportSha256: "abc123" } }).ok).toBe(false);
  });

  it("rejects an unsupported integrity algorithm", () => {
    const report = buildFixtureReport();
    const tampered = { ...report, integrity: { ...report.integrity, algorithm: "md5" } };
    expect(validateReport(tampered).ok).toBe(false);
  });

  it("rejects a run-scoped recommendation that carries a caseId", () => {
    const report = buildFixtureReport();
    const runRec = report.recommendations.find((r) => r.scope === "run");
    if (runRec === undefined) throw new Error("fixture expected a run recommendation");
    const tampered = { ...report, recommendations: [{ ...runRec, caseId: "case_a" }, ...report.recommendations.filter((r) => r !== runRec)] };
    expect(validateReport(tampered).ok).toBe(false);
  });

  it("accepts the untampered fixture report (positive control for all the new checks above)", () => {
    expect(validateReport(buildFixtureReport()).ok).toBe(true);
  });
});

describe("report.json integrity", () => {
  it("verifies as intact right after building", () => {
    const report = buildFixtureReport();
    expect(verifyReportIntegrity(report)).toBe(true);
  });

  it("survives a JSON round trip (as written to disk and re-read)", () => {
    const report = buildFixtureReport();
    const roundTripped = JSON.parse(JSON.stringify(report)) as typeof report;
    expect(verifyReportIntegrity(roundTripped)).toBe(true);
  });

  it("detects tampering with a risk score after the fact", () => {
    const report = buildFixtureReport();
    const tampered = { ...report, riskScore: 0 };
    expect(verifyReportIntegrity(tampered)).toBe(false);
  });

  it("detects tampering with a finding severity", () => {
    const report = buildFixtureReport();
    const caseA = report.cases[0];
    if (caseA === undefined || caseA.finding === undefined) throw new Error("fixture expected a finding");
    const tampered = { ...report, cases: [{ ...caseA, finding: { ...caseA.finding, severity: "low" as const } }, report.cases[1]] } as unknown as ReportV1;
    expect(verifyReportIntegrity(tampered)).toBe(false);
  });

  it("detects a hand-edited recommendation", () => {
    const report = buildFixtureReport();
    const firstRec = report.recommendations[0];
    if (firstRec === undefined) throw new Error("fixture expected a recommendation");
    const tampered = {
      ...report,
      recommendations: [{ ...firstRec, action: "no_action" as const }, ...report.recommendations.slice(1)],
    } as ReportV1;
    expect(verifyReportIntegrity(tampered)).toBe(false);
  });
});
