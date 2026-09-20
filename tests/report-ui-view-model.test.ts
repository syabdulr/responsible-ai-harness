import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runDemoPipeline } from "../scripts/lib/demo-bundle.ts";
import {
  DOMAINS,
  buildDomainSummaries,
  buildFindingsView,
  buildIntegritySummary,
  buildJevSummary,
  buildLimitations,
  buildRecommendationCards,
  buildViewModel,
  riskVerdict,
  severityTone,
} from "../ui/view-model.js";
import type { ReportV1 } from "../src/contracts/report-types.ts";

/**
 * These tests run the SAME pipeline the CLI demo and the report-UI dev
 * server use (scripts/lib/demo-bundle.ts) to produce a real report.json
 * through the harness's existing contract, then assert on the pure
 * ui/view-model.js mapping over that real data — no hand-duplicated
 * scoring or recommendation logic.
 */
async function demoReport(): Promise<{ report: ReportV1; manifest: Awaited<ReturnType<typeof runDemoPipeline>>["manifest"]; verify: Awaited<ReturnType<typeof runDemoPipeline>>["verify"] }> {
  const outDir = mkdtempSync(join(tmpdir(), "rai-ui-vm-"));
  const result = await runDemoPipeline({ outDir });
  return { report: result.report, manifest: result.manifest, verify: result.verify };
}

describe("view-model over a real demo report", () => {
  it("produces a view model with one row per case and a domain per known category", async () => {
    const { report, manifest, verify } = await demoReport();
    const vm = buildViewModel(report, manifest, verify);

    expect(vm.findings).toHaveLength(report.cases.length);
    expect(vm.domains).toHaveLength(DOMAINS.length);
    expect(vm.topBar.runId).toBe(report.runId);
    expect(vm.integrity.reportSha256).toBe(report.integrity.reportSha256);
    expect(vm.integrity.verify?.ok).toBe(true);
  });

  it("demo run's known hard-rule failures surface as critical/high severity findings", async () => {
    const { report } = await demoReport();
    const findings = buildFindingsView(report);
    const canary = findings.find((f) => f.caseId === "case_canary_leak");
    expect(canary?.hasFinding).toBe(true);
    expect(canary?.severity).toBe("critical");
    expect(canary?.severityTone).toBe("critical");

    const injection = findings.find((f) => f.caseId === "case_injection_doc");
    expect(injection?.domainId).toBe("security");
    expect(injection?.hasFinding).toBe(true);
  });

  it("maps every case's category into exactly one of the five domains it groups", async () => {
    const { report } = await demoReport();
    const summaries = buildDomainSummaries(report);
    const totalCasesAcrossDomains = summaries.reduce((sum, d) => sum + d.totalCases, 0);
    // Every demo case has a category in {prompt_injection, secret_pii_leakage,
    // unsafe_tool_use, policy_bypass}, all of which map to a domain, so the
    // per-domain counts must exactly partition all cases.
    expect(totalCasesAcrossDomains).toBe(report.cases.length);
    const fairness = summaries.find((d) => d.id === "fairness");
    expect(fairness?.status).toBe("not_evaluated");
    expect(fairness?.totalCases).toBe(0);
  });

  it("run-level recommendation is pinned first, and case-level cards are worst-action-first", async () => {
    const { report } = await demoReport();
    const cards = buildRecommendationCards(report);
    expect(cards[0]?.scope).toBe("run");
    // block_release must never appear after a lower-ranked action.
    const actionRank: Record<string, number> = { block_release: 3, human_review_required: 2, monitor: 1, no_action: 0 };
    const caseCards = cards.filter((c) => c.scope === "case");
    let prevRank = Number.POSITIVE_INFINITY;
    for (const card of caseCards) {
      const rank = actionRank[card.action] ?? 0;
      expect(rank).toBeLessThanOrEqual(prevRank);
      prevRank = rank;
    }
  });

  it("Jev summary reflects the demo run's actual StubJudge label distribution", async () => {
    const { report } = await demoReport();
    const jev = buildJevSummary(report);
    expect(jev.usesLiveJev).toBe(false);
    expect(jev.judgeIds).toEqual(["stub-judge"]);
    expect(jev.totalJudged).toBe(report.cases.length);
    expect(jev.byLabel.pass + jev.byLabel.fail + jev.byLabel.uncertain).toBe(report.cases.length);
    expect(jev.humanReviewCount).toBe(report.counts.totalReviews);
  });

  it("limitations correctly report StubJudge (not live Jev) for this run", async () => {
    const { report } = await demoReport();
    const limitations = buildLimitations(report);
    expect(limitations.some((l) => l.includes("StubJudge"))).toBe(true);
  });

  it("integrity summary is null-safe when manifest/verify are absent", async () => {
    const { report } = await demoReport();
    const integrity = buildIntegritySummary(report, undefined, undefined);
    expect(integrity.manifest).toBeNull();
    expect(integrity.verify).toBeNull();
    expect(integrity.reportSha256).toBe(report.integrity.reportSha256);
  });
});

describe("riskVerdict — deterministic bands", () => {
  it("bands scores into low/medium/high/critical, inclusive at the boundary", () => {
    expect(riskVerdict(0).tone).toBe("low");
    expect(riskVerdict(0.19).tone).toBe("low");
    expect(riskVerdict(0.2).tone).toBe("medium");
    expect(riskVerdict(0.49).tone).toBe("medium");
    expect(riskVerdict(0.5).tone).toBe("high");
    expect(riskVerdict(0.79).tone).toBe("high");
    expect(riskVerdict(0.8).tone).toBe("critical");
    expect(riskVerdict(1).tone).toBe("critical");
  });

  it("fails closed to 'unknown' rather than crashing on a missing/non-numeric score", () => {
    expect(riskVerdict(undefined).tone).toBe("unknown");
    expect(riskVerdict(Number.NaN).tone).toBe("unknown");
    expect(riskVerdict("0.9" as unknown as number).tone).toBe("unknown");
  });
});

describe("severityTone", () => {
  it("reserves the critical tone strictly for critical severity", () => {
    expect(severityTone("critical")).toBe("critical");
    expect(severityTone("high")).toBe("high");
    expect(severityTone("medium")).toBe("medium");
    expect(severityTone("low")).toBe("low");
    expect(severityTone(undefined)).toBe("none");
  });
});

describe("empty report edge case", () => {
  const emptyReport: ReportV1 = {
    reportSchemaVersion: "1.0.0",
    runId: "run_empty",
    createdAt: "2026-01-01T00:00:00.000Z",
    harnessVersion: "0.1.0",
    toolVersions: {},
    riskScorePolicyVersion: "1.0.0",
    riskScore: 0,
    counts: {
      bySeverity: { low: 0, medium: 0, high: 0, critical: 0 },
      byCategory: { prompt_injection: 0, secret_pii_leakage: 0, unsafe_tool_use: 0, policy_bypass: 0, harness_error: 0 },
      totalCases: 0,
      totalFindings: 0,
      totalReviews: 0,
    },
    cases: [],
    recommendations: [
      { recommendationId: "rec_run_empty", policyVersion: "1.0.0", scope: "run", action: "no_action", severity: "none", reasonCodes: [], evidenceRefs: [] },
    ],
    integrity: { algorithm: "sha256", reportSha256: "0".repeat(64) },
  };

  it("does not crash and reports zero everywhere", () => {
    const vm = buildViewModel(emptyReport, undefined, undefined);
    expect(vm.findings).toHaveLength(0);
    expect(vm.domains.every((d) => d.totalCases === 0)).toBe(true);
    expect(vm.jev.totalJudged).toBe(0);
    expect(vm.jev.avgConfidencePct).toBeNull();
    expect(vm.risk.verdict.tone).toBe("low");
    expect(vm.recommendations).toHaveLength(1);
  });
});
