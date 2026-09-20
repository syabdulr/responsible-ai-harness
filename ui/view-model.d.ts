/**
 * Ambient type declarations for the plain-JS `view-model.js` runtime
 * module. `view-model.js` ships unmodified to the browser (no build
 * step), so it stays plain ES module JS; this sibling `.d.ts` is what
 * gives `tests/report-ui-view-model.test.ts` (and any other TS consumer)
 * full type safety over it, per TypeScript's standard JS+.d.ts pairing.
 */

import type { EvidenceBundleManifest, FindingCategory, JudgeLabel, RuleResult, Severity } from "../src/contracts/types.ts";
import type { RecommendationAction, ReportV1 } from "../src/contracts/report-types.ts";
import type { VerifyResult } from "../src/evidence/bundle.ts";

export declare const RISK_VERDICT_POLICY_VERSION: string;
export declare const DOMAIN_MAP_VERSION: string;

export type RiskTone = "unknown" | "critical" | "high" | "medium" | "low";

export interface RiskVerdict {
  tone: RiskTone;
  label: string;
  detail: string;
}

export declare function riskVerdict(riskScore: number | undefined): RiskVerdict;

export type SeverityTone = "critical" | "high" | "medium" | "low" | "none";

export declare function severityTone(severity: Severity | undefined): SeverityTone;

export interface Domain {
  id: string;
  label: string;
  categories: FindingCategory[];
  description: string;
}

export declare const DOMAINS: readonly Domain[];

export declare function categoryLabel(category: FindingCategory): string;

export type DomainStatus = "not_evaluated" | "no_cases" | "clean" | "findings";

export interface DomainSummary {
  id: string;
  label: string;
  description: string;
  inScope: boolean;
  totalCases: number;
  totalFindings: number;
  worstSeverity: Severity | "none";
  worstSeverityTone: SeverityTone;
  reviewCount: number;
  status: DomainStatus;
}

export declare function buildDomainSummaries(report: ReportV1 | undefined): DomainSummary[];

export interface FindingRow {
  caseId: string;
  category: FindingCategory;
  categoryLabel: string;
  domainId: string;
  domainLabel: string;
  hasFinding: boolean;
  severity: Severity | "none";
  severityTone: SeverityTone;
  affectedControl: string | null;
  questionIds: string[];
  evidenceCount: number;
  confidencePct: number | null;
  judgeLabel: JudgeLabel | "error" | null;
  judgeId: string | null;
  reviewState: string;
  reviewStatus: "pending" | "resolved" | null;
  reasonCodes: string[];
  ruleResults: RuleResult[];
  evidenceRefs: string[];
  reproductionSteps: string[];
}

export declare function buildFindingsView(report: ReportV1 | undefined): FindingRow[];

export interface JevSummary {
  judgeIds: string[];
  usesLiveJev: boolean;
  totalJudged: number;
  totalErrored: number;
  byLabel: Record<JudgeLabel, number>;
  avgConfidencePct: number | null;
  humanReviewCount: number;
}

export declare function buildJevSummary(report: ReportV1 | undefined): JevSummary;

export interface RecommendationCard {
  recommendationId: string;
  policyVersion: string;
  scope: "run" | "case";
  caseId?: string;
  action: RecommendationAction;
  severity: Severity | "none";
  reasonCodes: string[];
  evidenceRefs: string[];
}

export declare function buildRecommendationCards(report: ReportV1 | undefined): RecommendationCard[];

export interface IntegrityManifestSummary {
  schemaVersion: string;
  bundleId: string;
  redactionState: string;
  entriesDigest: string;
  entryCount: number;
}

export interface IntegrityVerifySummary {
  ok: boolean;
  checked: number;
  failures: string[];
}

export interface IntegritySummary {
  reportSchemaVersion: string | null;
  reportSha256: string | null;
  harnessVersion: string | null;
  toolVersions: Record<string, string>;
  manifest: IntegrityManifestSummary | null;
  verify: IntegrityVerifySummary | null;
}

export declare function buildIntegritySummary(
  report: ReportV1 | undefined,
  manifest: EvidenceBundleManifest | undefined,
  verify: VerifyResult | undefined,
): IntegritySummary;

export declare function buildLimitations(report: ReportV1 | undefined): string[];

export interface ViewModel {
  schemaVersion: string;
  report: ReportV1 | undefined;
  topBar: {
    runId: string | null;
    createdAt: string | null;
    harnessVersion: string | null;
    reportSchemaVersion: string | null;
    verified: boolean;
  };
  risk: {
    score: number | null;
    policyVersion: string | null;
    verdict: RiskVerdict;
  };
  jev: JevSummary;
  domains: DomainSummary[];
  findings: FindingRow[];
  recommendations: RecommendationCard[];
  integrity: IntegritySummary;
  limitations: string[];
  counts: ReportV1["counts"] | null;
}

export declare function buildViewModel(
  report: ReportV1 | undefined,
  manifest: EvidenceBundleManifest | undefined,
  verify: VerifyResult | undefined,
): ViewModel;
