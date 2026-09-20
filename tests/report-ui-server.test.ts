import { describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runDemoPipeline } from "../scripts/lib/demo-bundle.ts";
import { DEMO_CASES } from "../src/fixtures/cases.ts";
import { JevJudge } from "../src/judges/jev.ts";
import { buildJevEvidence } from "../src/judges/evidence-mapper.ts";
import { CATEGORY_QUESTION_IDS } from "../src/judges/jev-questions.ts";
import { FakeJevClient, fakeResult, noulAnswers } from "./support/fake-jev-client.ts";
import { safeResolve, tryPublishLiveData } from "../scripts/lib/report-ui-server.ts";

async function buildFakeLiveBundle(outDir: string): Promise<void> {
  const script = DEMO_CASES.map((c) => ({
    kind: "result" as const,
    result: fakeResult(noulAnswers(Object.fromEntries(CATEGORY_QUESTION_IDS[c.category].map((id) => [id, 0.05])))),
  }));
  const client = new FakeJevClient(script);
  const judge = new JevJudge({ secretRef: "x", liveMode: true, timeoutMs: 5000 }, { resolve: () => "fake" }, () => client);
  await runDemoPipeline({ outDir, judge, buildJudgeEvidence: (c, events) => buildJevEvidence(c.caseId, c.category, events) });
}

describe("tryPublishLiveData — the UI's sole trust boundary for a live bundle", () => {
  it("reports unavailable when the bundle directory doesn't exist", async () => {
    const missingDir = join(mkdtempSync(join(tmpdir(), "rai-noexist-")), "nope");
    const dataLiveDir = mkdtempSync(join(tmpdir(), "rai-datalive-"));
    const result = await tryPublishLiveData(missingDir, dataLiveDir);
    expect(result.available).toBe(false);
    expect(result.reason).toMatch(/no live run found/);
  });

  it("publishes a curated subset only after bundle checksums AND report integrity both re-verify", async () => {
    const bundleDir = mkdtempSync(join(tmpdir(), "rai-livebundle-"));
    await buildFakeLiveBundle(bundleDir);
    const dataLiveDir = mkdtempSync(join(tmpdir(), "rai-datalive-ok-"));

    const result = await tryPublishLiveData(bundleDir, dataLiveDir);
    expect(result.available).toBe(true);
    expect(existsSync(join(dataLiveDir, "report.json"))).toBe(true);
    expect(existsSync(join(dataLiveDir, "bundle-manifest.json"))).toBe(true);
    expect(existsSync(join(dataLiveDir, "verify.json"))).toBe(true);

    const publishedReport = JSON.parse(readFileSync(join(dataLiveDir, "report.json"), "utf8")) as { cases: unknown[] };
    expect(publishedReport.cases).toHaveLength(4);
  });

  it("refuses a bundle whose report.json was tampered after generation (checksum mismatch)", async () => {
    const bundleDir = mkdtempSync(join(tmpdir(), "rai-livebundle-tamper-"));
    await buildFakeLiveBundle(bundleDir);
    // Mutate report.json in place — its sha256 in manifest.json no longer matches.
    const reportPath = join(bundleDir, "report.json");
    const report = JSON.parse(readFileSync(reportPath, "utf8")) as { riskScore: number };
    report.riskScore = 0;
    writeFileSync(reportPath, JSON.stringify(report, null, 2));

    const dataLiveDir = mkdtempSync(join(tmpdir(), "rai-datalive-tamper-"));
    const result = await tryPublishLiveData(bundleDir, dataLiveDir);
    expect(result.available).toBe(false);
    expect(result.reason).toMatch(/checksum mismatch|bundle re-verification failed/);
    expect(existsSync(join(dataLiveDir, "report.json"))).toBe(false);
  });

  it("refuses a report whose embedded integrity hash was forged to match tampered content", async () => {
    // Recompute a self-consistent (but still wrong-relative-to-the-bundle-checksum)
    // report so this exercises the SECOND independent check: even a report.json
    // edited AND re-checksummed into manifest.json would still need its own
    // internal reportSha256 to match — simulate that gap directly by writing a
    // manifest whose checksum matches the edited bytes, but leaving the
    // report's embedded integrity hash stale.
    const bundleDir = mkdtempSync(join(tmpdir(), "rai-livebundle-forge-"));
    await buildFakeLiveBundle(bundleDir);
    const reportPath = join(bundleDir, "report.json");
    const manifestPath = join(bundleDir, "manifest.json");
    const report = JSON.parse(readFileSync(reportPath, "utf8")) as { riskScore: number; integrity: { reportSha256: string } };
    report.riskScore = 0; // content changes, integrity.reportSha256 left stale
    const newBytes = JSON.stringify(report, null, 2);
    writeFileSync(reportPath, newBytes);

    const { createHash } = await import("node:crypto");
    const newHash = createHash("sha256").update(newBytes).digest("hex");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { entries: { path: string; sha256: string; bytes: number }[]; entriesDigest: string };
    const entry = manifest.entries.find((e) => e.path === "report.json");
    if (entry === undefined) throw new Error("test setup: report.json entry missing from manifest");
    entry.sha256 = newHash;
    entry.bytes = Buffer.byteLength(newBytes);
    const { sha256 } = await import("../src/normalizer/normalize.ts");
    manifest.entriesDigest = sha256(JSON.stringify(manifest.entries));
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    const dataLiveDir = mkdtempSync(join(tmpdir(), "rai-datalive-forge-"));
    const result = await tryPublishLiveData(bundleDir, dataLiveDir);
    // Bundle checksums now "pass" (attacker kept them consistent), but the
    // report's OWN embedded integrity hash is still stale — this is exactly
    // the second, independent check that must catch it.
    expect(result.available).toBe(false);
    expect(result.reason).toMatch(/integrity hash/);
    expect(existsSync(join(dataLiveDir, "report.json"))).toBe(false);
  });

  it("never overwrites a previously published good copy with a failed run's content", async () => {
    const dataLiveDir = mkdtempSync(join(tmpdir(), "rai-datalive-preserve-"));
    mkdirSync(dataLiveDir, { recursive: true });
    writeFileSync(join(dataLiveDir, "report.json"), JSON.stringify({ marker: "previous-good-run" }));

    const badDir = mkdtempSync(join(tmpdir(), "rai-livebundle-bad-"));
    const result = await tryPublishLiveData(badDir, dataLiveDir);
    expect(result.available).toBe(false);

    const stillThere = JSON.parse(readFileSync(join(dataLiveDir, "report.json"), "utf8")) as { marker: string };
    expect(stillThere.marker).toBe("previous-good-run");
  });
});

describe("safeResolve — path traversal and data-live gating", () => {
  const uiDir = "/repo/ui";
  const dataLiveDir = "/repo/ui/data-live";

  it("resolves the root to index.html", () => {
    const r = safeResolve(uiDir, dataLiveDir, "/");
    expect(r?.path).toBe("/repo/ui/index.html");
    expect(r?.isDataLive).toBe(false);
  });

  it("flags a request under data-live/ as isDataLive", () => {
    const r = safeResolve(uiDir, dataLiveDir, "/data-live/report.json");
    expect(r?.isDataLive).toBe(true);
  });

  it("rejects a traversal attempt that would escape ui/", () => {
    const r = safeResolve(uiDir, dataLiveDir, "/../package.json");
    expect(r).toBeUndefined();
  });

  it("rejects an encoded traversal attempt", () => {
    const r = safeResolve(uiDir, dataLiveDir, "/..%2f..%2fpackage.json");
    expect(r).toBeUndefined();
  });
});
