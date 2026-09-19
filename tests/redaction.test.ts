import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { redactString, redactValue } from "../src/contracts/validation.ts";
import { buildEvidenceBundle, attachReports } from "../src/evidence/bundle.ts";
import { assessCase } from "../src/pipeline/assess.ts";
import { DEMO_POLICY } from "../src/fixtures/cases.ts";
import type { JudgePlugin } from "../src/judges/stub.ts";
import type { CanonicalEvent, JudgeResult, ReviewTask, RuleResult, Finding } from "../src/contracts/types.ts";

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
    const textReport = `REPORT\nleaked: ${SECRET}\ncanary: ${CANARY}\n`;
    const jsonReport = JSON.stringify({ verdict: `bad ${SECRET}`, canary: CANARY });
    attachReports(dir, manifest, { humanText: textReport, machineJson: jsonReport });

    for (const e of manifest.entries) {
      const content = readFileSync(join(dir, e.path), "utf8");
      assertClean(`bundle:${e.path}`, content);
    }
    // note field carried sensitive content and must be redacted too
    const reviewsJson = JSON.parse(readFileSync(join(dir, "reviews.json"), "utf8")) as Array<{ note?: string }>;
    assertClean("reviews.json note", String(reviewsJson[0]?.note ?? ""));
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
