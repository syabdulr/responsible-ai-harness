/**
 * Report assembler — versioned independently of the risk score and
 * recommendation policy components it composes. Pure function over
 * already-computed pipeline outcomes; it invents no new judgment and
 * generates no prose. `integrity.reportSha256` lets a GUI or reviewer
 * verify the report was not altered after the harness produced it,
 * mirroring `verifyBundle`'s offline-verification pattern.
 */

import type { CaseOutcome } from "../pipeline/assess.ts";
import type { FindingCategory, JudgeResult, Severity } from "../contracts/types.ts";
import type { ReportCase, ReportCounts, ReportJudgeSummary, ReportV1 } from "../contracts/report-types.ts";
import { REPORT_SCHEMA_VERSION } from "../contracts/report-types.ts";
import { computeRiskScore, RISK_SCORE_POLICY_VERSION } from "./risk-score.ts";
import { buildRecommendations, RECOMMENDATION_POLICY_VERSION } from "./recommendation-policy.ts";
import { sha256 } from "../normalizer/normalize.ts";
import { redactValue } from "../contracts/validation.ts";

export const REPORT_BUILDER_VERSION = "1.0.0";

export interface ReportableCase {
  category: FindingCategory;
  outcome: CaseOutcome;
}

export interface BuildReportInput {
  runId: string;
  createdAt: string;
  harnessVersion: string;
  toolVersions: Record<string, string>;
  cases: ReportableCase[];
}

const JEV_QUESTION_METADATA_KEY = /^jev_q_(.+)_probability$/;

function extractJudgeSummary(judgeResult: JudgeResult): ReportJudgeSummary {
  const perQuestionProbabilities: { questionId: string; probability: number }[] = [];
  let model: string | undefined;
  let inputTokens: number | undefined;
  let outputTokens: number | undefined;
  let latencyMs: number | undefined;

  for (const [key, value] of Object.entries(judgeResult.modelMetadata)) {
    const match = JEV_QUESTION_METADATA_KEY.exec(key);
    if (match !== null && typeof value === "number") {
      const questionId = match[1];
      if (questionId !== undefined) perQuestionProbabilities.push({ questionId, probability: value });
      continue;
    }
    if (key === "jev_model" && typeof value === "string") model = value;
    else if (key === "jev_usage_input_tokens" && typeof value === "number") inputTokens = value;
    else if (key === "jev_usage_output_tokens" && typeof value === "number") outputTokens = value;
    else if (key === "jev_latency_ms" && typeof value === "number") latencyMs = value;
  }

  return {
    judgeId: judgeResult.judgeId,
    judgeVersion: judgeResult.judgeVersion,
    label: judgeResult.label,
    confidence: judgeResult.confidence,
    reasonCodes: judgeResult.reasonCodes,
    perQuestionProbabilities,
    ...(model !== undefined ? { model } : {}),
    ...(inputTokens !== undefined && outputTokens !== undefined ? { usage: { inputTokens, outputTokens } } : {}),
    ...(latencyMs !== undefined ? { latencyMs } : {}),
  };
}

function buildReportCase(item: ReportableCase): ReportCase {
  const { category, outcome } = item;
  const judge = outcome.judgeResult !== undefined ? extractJudgeSummary(outcome.judgeResult) : undefined;
  const evidenceRefs = [
    ...new Set([...outcome.ruleResults.flatMap((r) => r.evidenceRefs), ...(outcome.judgeResult?.evidenceRefs ?? []), ...(outcome.finding?.evidenceRefs ?? [])]),
  ];
  return {
    caseId: outcome.caseId,
    category,
    ruleResults: outcome.ruleResults,
    ...(judge !== undefined ? { judge } : {}),
    ...(outcome.judgeError !== undefined ? { judgeError: outcome.judgeError } : {}),
    ...(outcome.finding !== undefined ? { finding: outcome.finding } : {}),
    ...(outcome.review !== undefined ? { review: outcome.review } : {}),
    evidenceRefs,
  };
}

/** Severity and category counts are both over FINDINGS, not raw cases. */
function buildCounts(items: ReportableCase[]): ReportCounts {
  const bySeverity: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  const byCategory: Record<FindingCategory, number> = { prompt_injection: 0, secret_pii_leakage: 0, unsafe_tool_use: 0, policy_bypass: 0, harness_error: 0 };
  let totalFindings = 0;
  let totalReviews = 0;
  for (const { category, outcome } of items) {
    if (outcome.finding !== undefined) {
      totalFindings += 1;
      bySeverity[outcome.finding.severity] += 1;
      byCategory[category] += 1;
    }
    if (outcome.review !== undefined) totalReviews += 1;
  }
  return { bySeverity, byCategory, totalCases: items.length, totalFindings, totalReviews };
}

export function buildReport(input: BuildReportInput): ReportV1 {
  const cases = input.cases.map(buildReportCase);
  const counts = buildCounts(input.cases);
  const riskScore = computeRiskScore(input.cases.map((c) => ({ outcome: c.outcome })));
  const recommendations = buildRecommendations(
    input.cases.map((c) => c.outcome),
    input.runId,
  );
  const toolVersions: Record<string, string> = {
    ...input.toolVersions,
    reportBuilder: REPORT_BUILDER_VERSION,
    riskScorePolicy: RISK_SCORE_POLICY_VERSION,
    recommendationPolicy: RECOMMENDATION_POLICY_VERSION,
  };

  const draft: Omit<ReportV1, "integrity"> = {
    reportSchemaVersion: REPORT_SCHEMA_VERSION,
    runId: input.runId,
    createdAt: input.createdAt,
    harnessVersion: input.harnessVersion,
    toolVersions,
    riskScorePolicyVersion: RISK_SCORE_POLICY_VERSION,
    riskScore,
    counts,
    cases,
    recommendations,
  };
  // Redact BEFORE hashing so the embedded integrity hash matches the exact
  // (already-redacted) bytes this module and `attachReports` ultimately
  // write to disk — the same "redact, then persist" order used everywhere
  // else in the evidence path.
  const withoutHash = redactValue(draft) as Omit<ReportV1, "integrity">;
  const blank: ReportV1 = { ...withoutHash, integrity: { algorithm: "sha256", reportSha256: "" } };
  const reportSha256 = sha256(JSON.stringify(blank));
  return { ...withoutHash, integrity: { algorithm: "sha256", reportSha256 } };
}

/** Recompute `integrity.reportSha256` and compare — offline, no side effects. */
export function verifyReportIntegrity(report: ReportV1): boolean {
  const blank: ReportV1 = { ...report, integrity: { algorithm: "sha256", reportSha256: "" } };
  return sha256(JSON.stringify(blank)) === report.integrity.reportSha256;
}
