/**
 * Deterministic recommendation mapping — versioned independently of the
 * risk score and the report assembler. Turns existing typed findings and
 * review tasks into an array of recommendations; it invents no new
 * judgment beyond this fixed, documented precedence:
 *
 *   1. any hard-rule failure in the case -> block_release
 *   2. else a finding with a pending review -> human_review_required
 *   3. else a finding alone (judge-only, no review) -> monitor
 *   4. else a pending review without a finding (e.g. rule_error,
 *      ambiguous_case) -> human_review_required
 *   5. otherwise -> no_action
 *
 * A run-level recommendation reports the single worst action across all
 * cases (block_release > human_review_required > monitor > no_action).
 */

import type { CaseOutcome } from "../pipeline/assess.ts";
import type { Recommendation, RecommendationAction } from "../contracts/report-types.ts";
import type { Severity } from "../contracts/types.ts";

export const RECOMMENDATION_POLICY_VERSION = "1.0.0";

const ACTION_RANK: Record<RecommendationAction, number> = {
  block_release: 3,
  human_review_required: 2,
  monitor: 1,
  no_action: 0,
};

const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

function caseAction(outcome: CaseOutcome): RecommendationAction {
  const hardFail = outcome.ruleResults.some((r) => r.outcome === "fail");
  if (hardFail) return "block_release";
  if (outcome.finding !== undefined) {
    return outcome.review !== undefined ? "human_review_required" : "monitor";
  }
  if (outcome.review !== undefined) return "human_review_required";
  return "no_action";
}

export function buildRecommendations(cases: CaseOutcome[], runId: string): Recommendation[] {
  const recommendations: Recommendation[] = [];
  let worstAction: RecommendationAction = "no_action";
  let worstSeverity: Severity | "none" = "none";

  for (const outcome of cases) {
    const action = caseAction(outcome);
    if (ACTION_RANK[action] > ACTION_RANK[worstAction]) worstAction = action;
    const severity: Severity | "none" = outcome.finding?.severity ?? "none";
    if (severity !== "none" && (worstSeverity === "none" || SEVERITY_RANK[severity] > SEVERITY_RANK[worstSeverity])) {
      worstSeverity = severity;
    }
    if (action === "no_action") continue;

    recommendations.push({
      recommendationId: `rec_${outcome.caseId}`,
      policyVersion: RECOMMENDATION_POLICY_VERSION,
      scope: "case",
      caseId: outcome.caseId,
      action,
      severity,
      reasonCodes: [...new Set([...outcome.ruleResults.filter((r) => r.outcome === "fail").map((r) => r.reasonCode), ...(outcome.judgeResult?.reasonCodes ?? [])])],
      evidenceRefs: [
        ...new Set([...outcome.ruleResults.flatMap((r) => r.evidenceRefs), ...(outcome.finding?.evidenceRefs ?? []), ...(outcome.judgeResult?.evidenceRefs ?? [])]),
      ],
    });
  }

  recommendations.unshift({
    recommendationId: `rec_run_${runId}`,
    policyVersion: RECOMMENDATION_POLICY_VERSION,
    scope: "run",
    action: worstAction,
    severity: worstSeverity,
    reasonCodes: [],
    evidenceRefs: [],
  });

  return recommendations;
}
