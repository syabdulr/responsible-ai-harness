/**
 * Pure, framework-free mapping from an already-validated harness report
 * (report.json, per src/contracts/report-types.ts) into a UI view model.
 *
 * This module makes NO scoring, recommendation, redaction, or authorization
 * decisions of its own — the harness has already computed riskScore,
 * recommendations, findings, and review routing (see src/report/*.ts and
 * src/pipeline/assess.ts). Everything here is presentational relabeling
 * and grouping of that already-decided data: which of five display
 * "domains" a category renders under, what plain-language text a risk
 * band gets, what color tone a severity gets. None of it feeds back into
 * report.json, the evidence bundle, or any pass/fail/authorization
 * decision.
 *
 * Plain ES module, no build step: imported unmodified by both the browser
 * (ui/app.js) and vitest (tests/report-ui-view-model.test.ts), so there is
 * exactly one copy of this mapping logic to keep correct.
 */

export const RISK_VERDICT_POLICY_VERSION = "1.0.0";
export const DOMAIN_MAP_VERSION = "1.0.0";

/** riskScore band -> plain-language verdict. Same bands the report's own recommendation policy treats as escalating concern (see src/report/risk-score.ts doc comment: max-aggregated 0..1). */
export function riskVerdict(riskScore) {
  if (typeof riskScore !== "number" || !Number.isFinite(riskScore)) {
    return { tone: "unknown", label: "Risk score unavailable", detail: "The report did not include a valid numeric risk score." };
  }
  if (riskScore >= 0.8) {
    return { tone: "critical", label: "Critical risk", detail: "At least one case failed a deterministic hard rule, or a case could not be verified. Release should be blocked pending remediation." };
  }
  if (riskScore >= 0.5) {
    return { tone: "high", label: "High risk", detail: "A high-confidence finding was detected. Treat as blocking until reviewed." };
  }
  if (riskScore >= 0.2) {
    return { tone: "medium", label: "Moderate risk", detail: "Findings exist but confidence or severity is limited. Human review is recommended." };
  }
  return { tone: "low", label: "Low risk", detail: "No blocking findings were detected in this run." };
}

/** Severity -> display tone. Crimson is reserved for "critical" only, per the product's color rule. */
export function severityTone(severity) {
  switch (severity) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    default: return "none";
  }
}

const SEVERITY_RANK = { critical: 3, high: 2, medium: 1, low: 0 };
const ACTION_RANK = { block_release: 3, human_review_required: 2, monitor: 1, no_action: 0 };

/**
 * Presentational grouping of the harness's existing FindingCategory values
 * into five product-facing domains. `fairness` has no mapped category
 * today — the harness ships prompt-injection, secret/PII leakage, unsafe
 * tool use, and policy-bypass test plugins only (see README "Initial
 * tests"), so it is deliberately shown as "not yet evaluated" rather than
 * invented. Re-labeling only: does not change which category a finding
 * actually belongs to.
 */
export const DOMAINS = [
  { id: "security", label: "Security", categories: ["prompt_injection", "unsafe_tool_use"], description: "Instruction-hierarchy integrity and authorized, in-scope tool execution." },
  { id: "privacy", label: "Privacy", categories: ["secret_pii_leakage"], description: "Secrets and personal data never cross an undeclared output boundary." },
  { id: "safety", label: "Safety", categories: ["policy_bypass"], description: "Prohibited content stays refused under obfuscation, role-play, or encoding." },
  { id: "fairness", label: "Fairness", categories: [], description: "Not yet covered by an initial test plugin in this harness version." },
  { id: "governance", label: "Governance", categories: ["harness_error"], description: "Pipeline integrity, review routing, and audit lineage." },
];

const CATEGORY_LABEL = {
  prompt_injection: "Prompt injection",
  secret_pii_leakage: "Secret / PII leakage",
  unsafe_tool_use: "Unsafe tool use",
  policy_bypass: "Policy bypass",
  harness_error: "Harness error",
};

export function categoryLabel(category) {
  return CATEGORY_LABEL[category] ?? category;
}

function domainForCategory(category) {
  return DOMAINS.find((d) => d.categories.includes(category));
}

/** One summary card per domain: case/finding counts and worst severity, over the domain's mapped categories only. */
export function buildDomainSummaries(report) {
  const cases = Array.isArray(report?.cases) ? report.cases : [];
  return DOMAINS.map((domain) => {
    const domainCases = cases.filter((c) => domain.categories.includes(c.category));
    const findings = domainCases.filter((c) => c.finding !== undefined);
    let worstSeverity = "none";
    for (const c of findings) {
      const sev = c.finding.severity;
      if (worstSeverity === "none" || SEVERITY_RANK[sev] > SEVERITY_RANK[worstSeverity]) worstSeverity = sev;
    }
    const reviewCount = domainCases.filter((c) => c.review !== undefined).length;
    return {
      id: domain.id,
      label: domain.label,
      description: domain.description,
      inScope: domain.categories.length > 0,
      totalCases: domainCases.length,
      totalFindings: findings.length,
      worstSeverity,
      worstSeverityTone: worstSeverity === "none" ? "none" : severityTone(worstSeverity),
      reviewCount,
      status: domain.categories.length === 0
        ? "not_evaluated"
        : domainCases.length === 0
          ? "no_cases"
          : findings.length === 0
            ? "clean"
            : "findings",
    };
  });
}

/** Extract a stable confidence percentage (0-100) for display, or null when there is none. */
function confidencePct(caseItem) {
  if (caseItem.judge !== undefined) return Math.round(caseItem.judge.confidence * 100);
  if (caseItem.finding !== undefined) return Math.round(caseItem.finding.confidence * 100);
  return null;
}

/** Per-case findings-view rows: severity, control/question ids, evidence count, confidence, review state. */
export function buildFindingsView(report) {
  const cases = Array.isArray(report?.cases) ? report.cases : [];
  return cases.map((c) => {
    const domain = domainForCategory(c.category);
    const questionIds = c.judge?.perQuestionProbabilities?.map((q) => q.questionId) ?? [];
    return {
      caseId: c.caseId,
      category: c.category,
      categoryLabel: categoryLabel(c.category),
      domainId: domain?.id ?? "governance",
      domainLabel: domain?.label ?? "Governance",
      hasFinding: c.finding !== undefined,
      severity: c.finding?.severity ?? "none",
      severityTone: c.finding !== undefined ? severityTone(c.finding.severity) : "none",
      affectedControl: c.finding?.affectedControl ?? null,
      questionIds,
      evidenceCount: c.evidenceRefs?.length ?? 0,
      confidencePct: confidencePct(c),
      judgeLabel: c.judge?.label ?? (c.judgeError !== undefined ? "error" : null),
      judgeId: c.judge?.judgeId ?? null,
      reviewState: c.review !== undefined ? c.review.reason : (c.finding !== undefined ? "no_review_required" : "clean"),
      reviewStatus: c.review?.status ?? null,
      reasonCodes: c.finding?.reasonCodes ?? c.judge?.reasonCodes ?? [],
      ruleResults: c.ruleResults ?? [],
      evidenceRefs: c.evidenceRefs ?? [],
      reproductionSteps: c.finding?.reproductionSteps ?? [],
    };
  });
}

/** Run-level Jev/judge classification summary shown in the risk hero. */
export function buildJevSummary(report) {
  const cases = Array.isArray(report?.cases) ? report.cases : [];
  const judged = cases.filter((c) => c.judge !== undefined);
  const byLabel = { pass: 0, fail: 0, uncertain: 0 };
  let confSum = 0;
  const judgeIds = new Set();
  for (const c of judged) {
    byLabel[c.judge.label] = (byLabel[c.judge.label] ?? 0) + 1;
    confSum += c.judge.confidence;
    judgeIds.add(c.judge.judgeId);
  }
  const errorCount = cases.filter((c) => c.judgeError !== undefined).length;
  return {
    judgeIds: [...judgeIds],
    usesLiveJev: judgeIds.has("jev"),
    totalJudged: judged.length,
    totalErrored: errorCount,
    byLabel,
    avgConfidencePct: judged.length > 0 ? Math.round((confSum / judged.length) * 100) : null,
    humanReviewCount: report?.counts?.totalReviews ?? 0,
  };
}

/** Recommendations, worst-first: run-level card pinned first, then case-level cards ranked by action then severity. */
export function buildRecommendationCards(report) {
  const recs = Array.isArray(report?.recommendations) ? report.recommendations : [];
  const runLevel = recs.filter((r) => r.scope === "run");
  const caseLevel = recs
    .filter((r) => r.scope === "case")
    .slice()
    .sort((a, b) => {
      const actionDiff = (ACTION_RANK[b.action] ?? 0) - (ACTION_RANK[a.action] ?? 0);
      if (actionDiff !== 0) return actionDiff;
      const sevRank = (s) => (s === "none" ? -1 : SEVERITY_RANK[s] ?? -1);
      return sevRank(b.severity) - sevRank(a.severity);
    });
  return [...runLevel, ...caseLevel];
}

/** Integrity panel: schema version, report hash, bundle manifest, offline-verification result. */
export function buildIntegritySummary(report, manifest, verify) {
  return {
    reportSchemaVersion: report?.reportSchemaVersion ?? null,
    reportSha256: report?.integrity?.reportSha256 ?? null,
    harnessVersion: report?.harnessVersion ?? null,
    toolVersions: report?.toolVersions ?? {},
    manifest: manifest === undefined || manifest === null ? null : {
      schemaVersion: manifest.schemaVersion,
      bundleId: manifest.bundleId,
      redactionState: manifest.redactionState,
      entriesDigest: manifest.entriesDigest,
      entryCount: Array.isArray(manifest.entries) ? manifest.entries.length : 0,
    },
    verify: verify === undefined || verify === null ? null : {
      ok: verify.ok === true,
      checked: verify.checked ?? 0,
      failures: verify.failures ?? [],
    },
  };
}

/**
 * Fixed, honest v1 limitations. Each line reflects an already-documented
 * product boundary (see README "Judge status", "Network / DNS
 * limitation", "Signing is not implemented", and the domain-coverage note
 * above) — this list does not claim anything the harness does not
 * actually do.
 */
export function buildLimitations(report) {
  const usesLiveJev = buildJevSummary(report).usesLiveJev;
  const limitations = [
    "Assessment only: this product observes, tests, scores, and reports. It does not block production requests.",
    usesLiveJev
      ? "Jev live scoring was used for this run."
      : "Jev live scoring was disabled for this run; all judge results come from the deterministic StubJudge fixture, not a live model call.",
    "Evidence bundle signing is not implemented yet — integrity relies on sha256 checksums and the entriesDigest binding, not a cryptographic signature.",
    "The REST adapter narrows but does not eliminate DNS-rebinding risk: addresses are re-validated before every request attempt, but Node's fetch can still re-resolve between validation and connection.",
    "Redaction is defense in depth, not a guarantee: pattern matching cannot catch every secret format or a novel encoding of one.",
    "The Fairness domain has no initial test plugin in this harness version, so it always reads \"not yet evaluated\" rather than a score.",
  ];
  return limitations;
}

/** Compose the full view model consumed by the UI. */
export function buildViewModel(report, manifest, verify) {
  return {
    schemaVersion: RISK_VERDICT_POLICY_VERSION,
    report,
    topBar: {
      runId: report?.runId ?? null,
      createdAt: report?.createdAt ?? null,
      harnessVersion: report?.harnessVersion ?? null,
      reportSchemaVersion: report?.reportSchemaVersion ?? null,
      verified: verify?.ok === true,
    },
    risk: {
      score: report?.riskScore ?? null,
      policyVersion: report?.riskScorePolicyVersion ?? null,
      verdict: riskVerdict(report?.riskScore),
    },
    jev: buildJevSummary(report),
    domains: buildDomainSummaries(report),
    findings: buildFindingsView(report),
    recommendations: buildRecommendationCards(report),
    integrity: buildIntegritySummary(report, manifest, verify),
    limitations: buildLimitations(report),
    counts: report?.counts ?? null,
  };
}
