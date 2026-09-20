import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { redactString, redactValue } from "../src/contracts/validation.ts";
import { buildEvidenceBundle, attachReports } from "../src/evidence/bundle.ts";
import { buildReport, openReportArtifact } from "../src/report/build-report.ts";
import type { ValidatedReportArtifact } from "../src/report/build-report.ts";
import { sha256 } from "../src/normalizer/normalize.ts";
import { assessCase } from "../src/pipeline/assess.ts";
import { DEMO_POLICY } from "../src/fixtures/cases.ts";
import type { JudgePlugin } from "../src/judges/stub.ts";
import type { ReportV1 } from "../src/contracts/report-types.ts";
import type { CanonicalEvent, JudgeResult, ReviewTask, RuleResult, Finding } from "../src/contracts/types.ts";

/**
 * Forges a `ValidatedReportArtifact` around arbitrary (possibly dirty)
 * report content with a SELF-CONSISTENT integrity hash — i.e. it passes
 * `openReportArtifact`'s re-verification, because the hash genuinely
 * matches the content, even though that content never went through
 * `buildReport`'s redaction. This is only reachable through the `as
 * unknown as` cast below; it exists to prove attachReports's OTHER
 * layers (shape validation, residual-risk scan) are real backstops, not
 * just integrity-hash theater.
 */
function forgeArtifact(report: Omit<ReportV1, "integrity">): ValidatedReportArtifact {
  const blank = { ...report, integrity: { algorithm: "sha256" as const, reportSha256: "" } };
  const reportSha256 = sha256(JSON.stringify(blank));
  const full: ReportV1 = { ...report, integrity: { algorithm: "sha256", reportSha256 } };
  return { report: full } as unknown as ValidatedReportArtifact;
}

const SECRET = "sk-CANARYSECRET1234567890AB";
const CANARY = "CANARY_LEAK_XYZ987";

function secretEvent(): CanonicalEvent {
  return {
    schemaVersion: "1.0",
    eventId: "evt_secret_1",
    runId: "run_r",
    sequence: 1,
    timestamp: "2026-01-01T00:00:00.000Z",
    type: "message.output",
    actor: "assistant",
    content: { text: `the key is ${SECRET} and the canary is ${CANARY}` },
  };
}

const SENSITIVE_PATTERNS: RegExp[] = [
  /sk-[A-Za-z0-9]{8,}/,
  /CANARY[A-Z0-9_]*/,
  /Bearer\s+[A-Za-z0-9._-]{10,}/,
];

function assertClean(label: string, serialized: string): void {
  for (const re of SENSITIVE_PATTERNS) {
    if (re.test(serialized)) throw new Error(`${label} leaked sensitive data matching ${re.source}`);
  }
}

describe("redaction — every export surface", () => {
  it("redactString strips canary + key-like values", () => {
    const out = redactString(`key=${SECRET} canary=${CANARY} plain words`);
    assertClean("redactString", out);
    expect(out).toContain("plain words");
  });

  it("redactValue walks nested objects, arrays, and strings", () => {
    const v = redactValue({
      a: [SECRET, { b: CANARY, c: "ok" }],
      d: `Bearer ${SECRET}`,
      e: 42,
    });
    assertClean("redactValue", JSON.stringify(v));
    expect((v as { e: number }).e).toBe(42);
  });

  it("bundle artifacts contain no secrets: events, rules, judges, findings, reviews, reports", () => {
    const ev = secretEvent();
    const rule: RuleResult = {
      ruleId: "hr_x", ruleVersion: "1", caseId: "c", outcome: "fail",
      reasonCode: `detail ${SECRET}`, evidenceRefs: ["evt_secret_1"],
      detail: `contains ${CANARY}`,
    };
    const judge: JudgeResult = {
      judgeId: "tj", judgeVersion: "1", caseId: "c", label: "fail", confidence: 0.9,
      reasonCodes: [`saw ${SECRET}`], evidenceRefs: ["evt_secret_1"], modelMetadata: { note: CANARY },
    };
    const finding: Finding = {
      findingId: "f1", runId: "run_r", caseId: "c", category: "secret_pii_leakage", severity: "critical",
      status: "open", confidence: 1, affectedControl: "C-DATA", reasonCodes: [SECRET],
      reproductionSteps: [`repro with ${CANARY}`], evidenceRefs: ["evt_secret_1"], source: "hard_rule",
    };
    const review: ReviewTask = {
      reviewId: "rev1", findingRef: "f1", reason: "sensitive_evidence", createdAt: "2026-01-01T00:00:00.000Z",
      status: "pending", note: `reviewer hint ${SECRET}`,
    } as ReviewTask;

    const dir = mkdtempSync(join(tmpdir(), "rai-redact-"));
    const { manifest } = buildEvidenceBundle({
      runId: "run_r", toolVersions: {}, harnessVersion: "0.1.0",
      events: [ev], findings: [finding], reviewTasks: [review], ruleResults: [rule], judgeResults: [judge],
      reproduction: [`repro step containing ${CANARY}`],
      outDir: dir,
    });
    // The machine report can ONLY be a ReportV1 built by buildReport — it
    // redacts internally, so the sentinels here exercise that path rather
    // than a caller-assembled JSON blob attachReports must trust blindly.
    const report = buildReport({
      runId: "run_r", createdAt: "2026-01-01T00:00:00.000Z", harnessVersion: "0.1.0", toolVersions: {},
      cases: [{ category: "secret_pii_leakage", outcome: { caseId: "c", events: [ev], ruleResults: [rule], judgeResult: judge, judgeError: undefined, finding, review } }],
    });
    const textReport = `REPORT\nleaked: ${SECRET}\ncanary: ${CANARY}\n`;
    const finalManifest = attachReports(dir, manifest, { humanText: textReport, machineReport: report });

    // Regression guard: inspect the RETURNED (post-attach) manifest and the
    // actual files it points at — the stale pre-attach `manifest` above
    // would silently miss report.txt/report.json entirely.
    expect(finalManifest.entries.some((e) => e.path === "report.txt")).toBe(true);
    expect(finalManifest.entries.some((e) => e.path === "report.json")).toBe(true);
    for (const e of finalManifest.entries) {
      const content = readFileSync(join(dir, e.path), "utf8");
      assertClean(`bundle:${e.path}`, content);
    }
    // note field carried sensitive content and must be redacted too
    const reviewsJson = JSON.parse(readFileSync(join(dir, "reviews.json"), "utf8")) as Array<{ note?: string }>;
    assertClean("reviews.json note", String(reviewsJson[0]?.note ?? ""));
  });

  it("attachReports rejects a machineReport whose integrity hash does not match its content (bogus/garbage cast)", () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-badreport-"));
    const { manifest } = buildEvidenceBundle({
      runId: "run_bad", toolVersions: {}, harnessVersion: "0.1.0",
      events: [], findings: [], reviewTasks: [], ruleResults: [], judgeResults: [],
      reproduction: [],
      outDir: dir,
    });
    const bogus = { not: "a real report" } as unknown as Parameters<typeof attachReports>[2]["machineReport"];
    expect(() => attachReports(dir, manifest, { humanText: "clean", machineReport: bogus })).toThrow(/integrity hash/);
  });

  it("attachReports rejects a machineReport that is integrity-valid but fails contract shape validation (structurally valid forgery, layer 2)", () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-shapebad-"));
    const { manifest } = buildEvidenceBundle({
      runId: "run_shapebad", toolVersions: {}, harnessVersion: "0.1.0",
      events: [], findings: [], reviewTasks: [], ruleResults: [], judgeResults: [],
      reproduction: [],
      outDir: dir,
    });
    // A forged artifact with a genuinely self-consistent hash (computed the
    // same way buildReport does) but content that never went through the
    // real builder — this is only reachable via the unsafe cast in
    // forgeArtifact, and proves the integrity check alone is not what
    // rejects a bad shape: validateReport is a real second layer.
    const forged = forgeArtifact({ notARealReportField: true } as unknown as Omit<ReportV1, "integrity">);
    expect(() => attachReports(dir, manifest, { humanText: "clean", machineReport: forged })).toThrow(/contract validation/);
  });

  it("attachReports refuses a structurally valid, integrity-consistent machineReport that still carries a secret (residual-risk backstop, layer 3)", () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-hand-built-report-"));
    const { manifest } = buildEvidenceBundle({
      runId: "run_hb", toolVersions: {}, harnessVersion: "0.1.0",
      events: [], findings: [], reviewTasks: [], ruleResults: [], judgeResults: [],
      reproduction: [],
      outDir: dir,
    });
    // Simulates a future/alternate producer that bypasses buildReport's own
    // redaction entirely, but still (correctly) computes a matching hash
    // over its dirty content — shape-valid, integrity-valid, still dirty.
    const cleanReport = openReportArtifact(buildReport({ runId: "run_hb", createdAt: "2026-01-01T00:00:00.000Z", harnessVersion: "0.1.0", toolVersions: {}, cases: [] }));
    const { integrity, ...withoutIntegrity } = cleanReport;
    void integrity;
    const dirty: Omit<ReportV1, "integrity"> = {
      ...withoutIntegrity,
      recommendations: [{ ...withoutIntegrity.recommendations[0], recommendationId: withoutIntegrity.recommendations[0]?.recommendationId ?? "rec_x", policyVersion: "1.0.0", scope: "run", action: "no_action", severity: "none", reasonCodes: ["token=zzz-should-never-reach-disk-1234567890"], evidenceRefs: [] }],
    };
    const forged = forgeArtifact(dirty);
    expect(() => attachReports(dir, manifest, { humanText: "clean", machineReport: forged })).toThrow(/high-risk patterns/);
  });

  it("PII regression: mutating runId to an email address after construction is rejected, never written, and any surviving report.json still verifies", () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-pii-runid-"));
    const { manifest } = buildEvidenceBundle({
      runId: "run_pii", toolVersions: {}, harnessVersion: "0.1.0",
      events: [], findings: [], reviewTasks: [], ruleResults: [], judgeResults: [],
      reproduction: [],
      outDir: dir,
    });
    const artifact = buildReport({ runId: "run_pii", createdAt: "2026-01-01T00:00:00.000Z", harnessVersion: "0.1.0", toolVersions: {}, cases: [] });
    // Simulate a bug or attacker mutating the sealed artifact's inner
    // report after buildReport returned it — TS `readonly` does not stop
    // this at runtime, which is exactly why attachReports re-verifies.
    (artifact.report as { runId: string }).runId = "victim@example.com";

    expect(() => attachReports(dir, manifest, { humanText: "clean", machineReport: artifact })).toThrow(/integrity hash/);

    // Nothing from this call was written: report.json/report.txt must not
    // exist, so there is no possibility of the email having reached disk.
    expect(existsSync(join(dir, "report.json"))).toBe(false);
    expect(existsSync(join(dir, "report.txt"))).toBe(false);

    // A genuinely unmutated build for the same run DOES write successfully,
    // never contains the email, and its on-disk reportSha256 verifies.
    const cleanArtifact = buildReport({ runId: "run_pii", createdAt: "2026-01-01T00:00:00.000Z", harnessVersion: "0.1.0", toolVersions: {}, cases: [] });
    attachReports(dir, manifest, { humanText: "clean", machineReport: cleanArtifact });
    const writtenRaw = readFileSync(join(dir, "report.json"), "utf8");
    expect(writtenRaw).not.toContain("victim@example.com");
    const written = JSON.parse(writtenRaw) as ReportV1;
    const blank = { ...written, integrity: { algorithm: "sha256" as const, reportSha256: "" } };
    expect(sha256(JSON.stringify(blank))).toBe(written.integrity.reportSha256);
  });

  it("redaction happens BEFORE the judge sees anything (judge input is clean)", async () => {
    const seen: string[] = [];
    const judge: JudgePlugin = {
      id: "spy", version: "1.0.0",
      async score(input) {
        seen.push(JSON.stringify(input));
        return {
          ok: true,
          result: {
            judgeId: "spy", judgeVersion: "1.0.0", caseId: input.caseId,
            label: "pass", confidence: 0.9, reasonCodes: ["none"], evidenceRefs: [], modelMetadata: {},
          },
        };
      },
    };
    // Event contains secrets; the pipeline must redact judge-bound evidence.
    const o = await assessCase(
      {
        caseId: "c_j", category: "secret_pii_leakage",
        events: [secretEvent()],
        capabilities: ["outputs.text"],
        judgeEvidence: { judge_hint: `ctx ${SECRET} ${CANARY}` },
      },
      { runId: "run_j", policy: DEMO_POLICY, rules: [], judge, reviewConfidenceThreshold: 0.6, caseCounter: { n: 0 } },
    );
    expect(seen).toHaveLength(1);
    assertClean("judge input", seen[0] ?? "");
    void o;
  });
});

describe("redaction — pipeline outcome exports", () => {
  it("assessCase outcome (incl. events + reports sources) is redactable without loss of structure", async () => {
    const o = await assessCase(
      {
        caseId: "c_e", category: "prompt_injection",
        events: [secretEvent()],
        capabilities: ["outputs.text"],
        judgeEvidence: {},
      },
      { runId: "run_e", policy: DEMO_POLICY, rules: [], judge: new (await import("../src/judges/stub.ts")).StubJudge(), reviewConfidenceThreshold: 0.6, caseCounter: { n: 0 } },
    );
    const red = JSON.stringify(redactValue(o));
    assertClean("outcome", red);
    expect(red).toContain("evt_secret_1"); // event IDs survive; secret values do not
  });
});
