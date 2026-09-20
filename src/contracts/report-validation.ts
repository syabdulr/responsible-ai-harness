/**
 * Runtime validator for the `report.json` contract. Shape only — the
 * `integrity.reportSha256` recomputation lives in `src/report/build-report.ts`
 * alongside the code that produces it, mirroring how `validateBundleManifest`
 * and `verifyBundle` split responsibilities.
 *
 * Unknown-field policy: unlike the canonical event/trace validators in
 * `validation.ts` (which tolerate unknown fields for third-party forward
 * compatibility), report.json has exactly one producer (`build-report.ts`)
 * and no external producers to stay compatible with, so every object in
 * this contract is validated with `requireNoUnknownKeys` — an unexpected
 * field is a bug, not a forward-compat signal, and must fail closed.
 */

import {
  err,
  isRecord,
  ok,
  requireArray,
  requireInteger,
  requireNoUnknownKeys,
  requireNumber,
  requireString,
  requireStringArray,
  requireTimestamp,
  validateFinding,
  validateReviewTask,
  validateRuleResult,
} from "./validation.ts";
import type { Valid } from "./validation.ts";
import { SUPPORTED_REPORT_SCHEMA_VERSIONS } from "./report-types.ts";
import type { Recommendation, RecommendationAction, ReportCase, ReportCounts, ReportIntegrity, ReportJudgeError, ReportJudgeSummary, ReportPerQuestionProbability, ReportV1 } from "./report-types.ts";

const CATEGORIES = ["prompt_injection", "secret_pii_leakage", "unsafe_tool_use", "policy_bypass", "harness_error"] as const;
const SEVERITIES = ["low", "medium", "high", "critical"] as const;
const RECOMMENDATION_ACTIONS: readonly RecommendationAction[] = ["block_release", "human_review_required", "monitor", "no_action"];
/** 64 lowercase hex characters — a sha256 digest, matching validateBundleManifest's check. */
const SHA256_HEX = /^[0-9a-f]{64}$/;

/**
 * Derives an `allowed`-keys array from a `Record<keyof T, true>` literal
 * instead of a hand-typed string array. This is what keeps
 * `requireNoUnknownKeys` in sync with `report-types.ts`: add a field to an
 * interface without adding it here, and the literal below fails to
 * compile ("Property '<field>' is missing") instead of silently
 * accepting reports validateReport would then reject at runtime.
 */
function fieldNames<T>(spec: { [K in keyof Required<T>]: true }): string[] {
  return Object.keys(spec);
}

const JUDGE_SUMMARY_FIELDS = fieldNames<ReportJudgeSummary>({
  judgeId: true,
  judgeVersion: true,
  label: true,
  confidence: true,
  reasonCodes: true,
  perQuestionProbabilities: true,
  model: true,
  usage: true,
  latencyMs: true,
});
const PER_QUESTION_PROBABILITY_FIELDS = fieldNames<ReportPerQuestionProbability>({ questionId: true, probability: true });
const JUDGE_USAGE_FIELDS = fieldNames<NonNullable<ReportJudgeSummary["usage"]>>({ inputTokens: true, outputTokens: true });
const REPORT_CASE_FIELDS = fieldNames<ReportCase>({
  caseId: true,
  category: true,
  ruleResults: true,
  judge: true,
  judgeError: true,
  finding: true,
  review: true,
  evidenceRefs: true,
});
const JUDGE_ERROR_FIELDS = fieldNames<ReportJudgeError>({ code: true, message: true, timeout: true });
const REPORT_COUNTS_FIELDS = fieldNames<ReportCounts>({ bySeverity: true, byCategory: true, totalCases: true, totalFindings: true, totalReviews: true });
const RECOMMENDATION_FIELDS = fieldNames<Recommendation>({
  recommendationId: true,
  policyVersion: true,
  scope: true,
  caseId: true,
  action: true,
  severity: true,
  reasonCodes: true,
  evidenceRefs: true,
});
const REPORT_INTEGRITY_FIELDS = fieldNames<ReportIntegrity>({ algorithm: true, reportSha256: true });
const REPORT_V1_FIELDS = fieldNames<ReportV1>({
  reportSchemaVersion: true,
  runId: true,
  createdAt: true,
  harnessVersion: true,
  toolVersions: true,
  riskScorePolicyVersion: true,
  riskScore: true,
  counts: true,
  cases: true,
  recommendations: true,
  integrity: true,
});

function requireReportSchemaVersion(v: unknown, field: string): Valid<string> {
  const sv = requireString(v, field);
  if (!sv.ok) return sv;
  if (!SUPPORTED_REPORT_SCHEMA_VERSIONS.includes(sv.value)) {
    return err(`${field}: unsupported report schema version "${sv.value}"`);
  }
  return sv;
}

function validateJudgeSummary(input: unknown, path: string): Valid<ReportJudgeSummary> {
  if (!isRecord(input)) return err(`${path}: not an object`);
  const uk = requireNoUnknownKeys(input, JUDGE_SUMMARY_FIELDS, path);
  if (!uk.ok) return uk;

  for (const f of ["judgeId", "judgeVersion"] as const) {
    const s = requireString(input[f], `${path}.${f}`);
    if (!s.ok) return s;
  }
  if (input.label !== "pass" && input.label !== "fail" && input.label !== "uncertain") return err(`${path}.label: invalid`);
  const conf = requireNumber(input.confidence, `${path}.confidence`, 0, 1);
  if (!conf.ok) return conf;
  const reasons = requireStringArray(input.reasonCodes, `${path}.reasonCodes`);
  if (!reasons.ok) return reasons;

  const pqp = requireArray(input.perQuestionProbabilities, `${path}.perQuestionProbabilities`);
  if (!pqp.ok) return pqp;
  for (const [i, entry] of pqp.value.entries()) {
    const entryPath = `${path}.perQuestionProbabilities[${String(i)}]`;
    if (!isRecord(entry)) return err(`${entryPath}: not an object`);
    const euk = requireNoUnknownKeys(entry, PER_QUESTION_PROBABILITY_FIELDS, entryPath);
    if (!euk.ok) return euk;
    const qid = requireString(entry.questionId, `${entryPath}.questionId`);
    if (!qid.ok) return qid;
    const p = requireNumber(entry.probability, `${entryPath}.probability`, 0, 1);
    if (!p.ok) return p;
  }

  if (input.model !== undefined) {
    const m = requireString(input.model, `${path}.model`);
    if (!m.ok) return m;
  }
  if (input.usage !== undefined) {
    if (!isRecord(input.usage)) return err(`${path}.usage: not an object`);
    const uuk = requireNoUnknownKeys(input.usage, JUDGE_USAGE_FIELDS, `${path}.usage`);
    if (!uuk.ok) return uuk;
    const it = requireInteger(input.usage.inputTokens, `${path}.usage.inputTokens`, 0);
    if (!it.ok) return it;
    const ot = requireInteger(input.usage.outputTokens, `${path}.usage.outputTokens`, 0);
    if (!ot.ok) return ot;
  }
  if (input.latencyMs !== undefined) {
    const l = requireInteger(input.latencyMs, `${path}.latencyMs`, 0);
    if (!l.ok) return l;
  }
  return ok(input as unknown as ReportJudgeSummary);
}

function validateReportCase(input: unknown, index: number): Valid<ReportCase> {
  const path = `report.cases[${String(index)}]`;
  if (!isRecord(input)) return err(`${path}: not an object`);
  const uk = requireNoUnknownKeys(input, REPORT_CASE_FIELDS, path);
  if (!uk.ok) return uk;

  const caseId = requireString(input.caseId, `${path}.caseId`);
  if (!caseId.ok) return caseId;
  if (!CATEGORIES.includes(input.category as (typeof CATEGORIES)[number])) return err(`${path}.category: invalid`);
  const rules = requireArray(input.ruleResults, `${path}.ruleResults`);
  if (!rules.ok) return rules;
  for (const [i, r] of rules.value.entries()) {
    const v = validateRuleResult(r);
    if (!v.ok) return err(`${path}.ruleResults[${String(i)}]: ${v.error}`);
  }
  if (input.judge !== undefined) {
    const v = validateJudgeSummary(input.judge, `${path}.judge`);
    if (!v.ok) return v;
  }
  if (input.judgeError !== undefined) {
    if (!isRecord(input.judgeError)) return err(`${path}.judgeError: not an object`);
    const jeuk = requireNoUnknownKeys(input.judgeError, JUDGE_ERROR_FIELDS, `${path}.judgeError`);
    if (!jeuk.ok) return jeuk;
    const code = requireString(input.judgeError.code, `${path}.judgeError.code`);
    if (!code.ok) return code;
    const message = requireString(input.judgeError.message, `${path}.judgeError.message`);
    if (!message.ok) return message;
    if (typeof input.judgeError.timeout !== "boolean") return err(`${path}.judgeError.timeout: must be a boolean`);
  }
  if (input.finding !== undefined) {
    const v = validateFinding(input.finding);
    if (!v.ok) return err(`${path}.finding: ${v.error}`);
  }
  if (input.review !== undefined) {
    const v = validateReviewTask(input.review);
    if (!v.ok) return err(`${path}.review: ${v.error}`);
  }
  const refs = requireStringArray(input.evidenceRefs, `${path}.evidenceRefs`);
  if (!refs.ok) return refs;
  return ok(input as unknown as ReportCase);
}

function validateCounts(input: unknown): Valid<ReportCounts> {
  if (!isRecord(input)) return err("report.counts: not an object");
  const uk = requireNoUnknownKeys(input, REPORT_COUNTS_FIELDS, "report.counts");
  if (!uk.ok) return uk;

  if (!isRecord(input.bySeverity)) return err("report.counts.bySeverity: not an object");
  const sevUk = requireNoUnknownKeys(input.bySeverity, SEVERITIES, "report.counts.bySeverity");
  if (!sevUk.ok) return sevUk;
  for (const sev of SEVERITIES) {
    const n = requireInteger(input.bySeverity[sev], `report.counts.bySeverity.${sev}`, 0);
    if (!n.ok) return n;
  }

  if (!isRecord(input.byCategory)) return err("report.counts.byCategory: not an object");
  const catUk = requireNoUnknownKeys(input.byCategory, CATEGORIES, "report.counts.byCategory");
  if (!catUk.ok) return catUk;
  for (const cat of CATEGORIES) {
    const n = requireInteger(input.byCategory[cat], `report.counts.byCategory.${cat}`, 0);
    if (!n.ok) return n;
  }

  for (const f of ["totalCases", "totalFindings", "totalReviews"] as const) {
    const n = requireInteger(input[f], `report.counts.${f}`, 0);
    if (!n.ok) return n;
  }
  return ok(input as unknown as ReportCounts);
}

function validateRecommendation(input: unknown, index: number): Valid<Recommendation> {
  const path = `report.recommendations[${String(index)}]`;
  if (!isRecord(input)) return err(`${path}: not an object`);
  const uk = requireNoUnknownKeys(input, RECOMMENDATION_FIELDS, path);
  if (!uk.ok) return uk;

  const id = requireString(input.recommendationId, `${path}.recommendationId`);
  if (!id.ok) return id;
  const pv = requireString(input.policyVersion, `${path}.policyVersion`);
  if (!pv.ok) return pv;
  if (input.scope !== "run" && input.scope !== "case") return err(`${path}.scope: invalid`);
  if (input.scope === "case") {
    const cid = requireString(input.caseId, `${path}.caseId`);
    if (!cid.ok) return cid;
  } else if (input.caseId !== undefined) {
    return err(`${path}.caseId: must be absent when scope is "run"`);
  }
  if (!RECOMMENDATION_ACTIONS.includes(input.action as RecommendationAction)) return err(`${path}.action: invalid`);
  if (input.severity !== "none" && !SEVERITIES.includes(input.severity as (typeof SEVERITIES)[number])) {
    return err(`${path}.severity: invalid`);
  }
  const reasons = requireStringArray(input.reasonCodes, `${path}.reasonCodes`);
  if (!reasons.ok) return reasons;
  const refs = requireStringArray(input.evidenceRefs, `${path}.evidenceRefs`);
  if (!refs.ok) return refs;
  return ok(input as unknown as Recommendation);
}

export function validateReport(input: unknown): Valid<ReportV1> {
  if (!isRecord(input)) return err("report: not an object");
  const uk = requireNoUnknownKeys(input, REPORT_V1_FIELDS, "report");
  if (!uk.ok) return uk;

  const sv = requireReportSchemaVersion(input.reportSchemaVersion, "report.reportSchemaVersion");
  if (!sv.ok) return sv;
  for (const f of ["runId", "harnessVersion", "riskScorePolicyVersion"] as const) {
    const s = requireString(input[f], `report.${f}`);
    if (!s.ok) return s;
  }
  const createdAt = requireTimestamp(input.createdAt, "report.createdAt");
  if (!createdAt.ok) return createdAt;
  if (!isRecord(input.toolVersions)) return err("report.toolVersions: not an object");
  for (const [k, v] of Object.entries(input.toolVersions)) {
    if (typeof v !== "string") return err(`report.toolVersions.${k}: must be a string`);
  }
  const risk = requireNumber(input.riskScore, "report.riskScore", 0, 1);
  if (!risk.ok) return risk;
  const counts = validateCounts(input.counts);
  if (!counts.ok) return counts;
  const cases = requireArray(input.cases, "report.cases");
  if (!cases.ok) return cases;
  for (const [i, c] of cases.value.entries()) {
    const v = validateReportCase(c, i);
    if (!v.ok) return v;
  }
  const recs = requireArray(input.recommendations, "report.recommendations");
  if (!recs.ok) return recs;
  for (const [i, r] of recs.value.entries()) {
    const v = validateRecommendation(r, i);
    if (!v.ok) return v;
  }
  if (!isRecord(input.integrity)) return err("report.integrity: not an object");
  const iuk = requireNoUnknownKeys(input.integrity, REPORT_INTEGRITY_FIELDS, "report.integrity");
  if (!iuk.ok) return iuk;
  if (input.integrity.algorithm !== "sha256") return err("report.integrity.algorithm: invalid");
  const hash = requireString(input.integrity.reportSha256, "report.integrity.reportSha256");
  if (!hash.ok) return hash;
  if (!SHA256_HEX.test(hash.value)) return err("report.integrity.reportSha256: not a sha256 hex digest");
  return ok(input as unknown as ReportV1);
}
