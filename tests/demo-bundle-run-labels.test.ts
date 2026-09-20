import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runDemoPipeline } from "../scripts/lib/demo-bundle.ts";
import { DEMO_CASES } from "../src/fixtures/cases.ts";
import { JevJudge } from "../src/judges/jev.ts";
import { buildJevEvidence } from "../src/judges/evidence-mapper.ts";
import { CATEGORY_QUESTION_IDS } from "../src/judges/jev-questions.ts";
import { FakeJevClient, fakeResult, noulAnswers } from "./support/fake-jev-client.ts";

/**
 * Regression tests for the logging bug where an offline run's [2] probe
 * line and a hardcoded "StubJudge second" string in [3] made a real,
 * verified LIVE run's console output claim "Jev live mode disabled" and
 * "StubJudge second" even though four real Jev calls occurred. These tests
 * pin down the truthful run-summary line ([8]) so that regression is
 * structurally impossible to reintroduce silently.
 */

function findSummaryLine(lines: string[]): string {
  const line = lines.find((l) => l.startsWith("[8] run summary"));
  if (line === undefined) throw new Error("no [8] run summary line found in logs");
  return line;
}

describe("runDemoPipeline log output truthfully identifies the run's actual judge and mode", () => {
  it("an offline (default StubJudge) run's summary never claims live Jev, and names stub-judge + deterministic", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "rai-log-offline-"));
    const lines: string[] = [];
    await runDemoPipeline({ outDir, log: (l) => lines.push(l) });

    const summary = findSummaryLine(lines);
    expect(summary).toContain('judge: "stub-judge"');
    expect(summary).toContain("mode: deterministic");
    expect(summary).not.toMatch(/mode:\s*live/i);
    expect(summary).not.toContain('judge: "jev"');

    const full = lines.join("\n");
    // The old bug: a hardcoded string claiming StubJudge scored, regardless
    // of which judge actually ran. That hardcoded phrase must never appear
    // now that the label is derived from the real judge.
    expect(full).not.toMatch(/StubJudge second/);
  });

  it("a live-shaped (real JevJudge, liveMode:true, fake transport) run's summary never claims StubJudge or an offline/deterministic mode", async () => {
    const script = DEMO_CASES.map((c) => ({
      kind: "result" as const,
      result: fakeResult(noulAnswers(Object.fromEntries(CATEGORY_QUESTION_IDS[c.category].map((id) => [id, 0.05])))),
    }));
    const client = new FakeJevClient(script);
    const judge = new JevJudge({ secretRef: "jev/test", liveMode: true, timeoutMs: 5000 }, { resolve: () => "test-fake-key-never-real" }, () => client);

    const outDir = mkdtempSync(join(tmpdir(), "rai-log-live-"));
    const lines: string[] = [];
    await runDemoPipeline({
      outDir,
      log: (l) => lines.push(l),
      judge,
      buildJudgeEvidence: (c, events) => buildJevEvidence(c.caseId, c.category, events),
    });

    const summary = findSummaryLine(lines);
    expect(summary).toContain('judge: "jev"');
    expect(summary).toContain("mode: live");
    expect(summary).not.toMatch(/mode:\s*(deterministic|offline)/i);
    expect(summary).not.toContain("stub-judge");

    const full = lines.join("\n");
    expect(full).not.toMatch(/StubJudge second/);
    // The internal self-check ([2]) is allowed to exist and to describe
    // itself as an offline probe — it must not be mistakable for this
    // run's own judge/mode, which is why it's asserted only on the [8]
    // summary line above. It must still never claim this line IS the run.
    expect(lines.some((l) => l.startsWith("[2]"))).toBe(true);
  });

  it("JudgePlugin.mode is truthful: StubJudge is deterministic, JevJudge reflects its own liveMode config", async () => {
    const { StubJudge } = await import("../src/judges/stub.ts");
    expect(new StubJudge().mode).toBe("deterministic");
    const offlineJev = new JevJudge({ secretRef: "x", liveMode: false, timeoutMs: 1000 }, undefined, undefined);
    expect(offlineJev.mode).toBe("offline");
    const liveJev = new JevJudge({ secretRef: "x", liveMode: true, timeoutMs: 1000 }, undefined, undefined);
    expect(liveJev.mode).toBe("live");
  });
});
