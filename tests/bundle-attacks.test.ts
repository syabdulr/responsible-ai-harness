import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildEvidenceBundle, attachReports, verifyBundle } from "../src/evidence/bundle.ts";
import { buildReport } from "../src/report/build-report.ts";
import type { CanonicalEvent, EvidenceBundleManifest } from "../src/contracts/types.ts";

function emptyReport() {
  return buildReport({ runId: "run_b", createdAt: "2026-01-01T00:00:00.000Z", harnessVersion: "0.1.0", toolVersions: {}, cases: [] });
}

function ev(): CanonicalEvent {
  return {
    schemaVersion: "1.0",
    eventId: "evt_b1",
    runId: "run_b",
    sequence: 1,
    timestamp: "2026-01-01T00:00:00.000Z",
    type: "message.output",
    actor: "assistant",
    content: { text: "clean" },
  };
}

function build(dir: string): { manifest: EvidenceBundleManifest } {
  return buildEvidenceBundle({
    runId: "run_b", toolVersions: {}, harnessVersion: "0.1.0",
    events: [ev()], findings: [], reviewTasks: [], ruleResults: [], judgeResults: [],
    reproduction: ["npm ci", "npm run demo"],
    outDir: dir,
  });
}

function readManifest(dir: string): EvidenceBundleManifest {
  return JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")) as EvidenceBundleManifest;
}

function writeManifest(dir: string, m: EvidenceBundleManifest): void {
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(m, null, 2));
}

describe("bundle integrity attacks", () => {
  it("verifies a pristine bundle", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-int-"));
    build(dir);
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(true);
    expect(v.checked).toBeGreaterThan(3);
  });

  it("detects a tampered artifact (checksum mismatch)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-tam-"));
    build(dir);
    writeFileSync(join(dir, "events.jsonl"), JSON.stringify({ ...ev(), content: { text: "TAMPERED" } }) + "\n");
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toMatch(/events\.jsonl: checksum mismatch/);
  });

  it("detects byte-count mismatch with a valid checksum updated", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-byte-"));
    build(dir);
    const m = readManifest(dir);
    // Flip a declared byte count without changing the file.
    const entry = m.entries.find((e) => e.path === "events.jsonl");
    if (entry === undefined) throw new Error("missing entry");
    entry.bytes = entry.bytes + 1;
    writeManifest(dir, m);
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toMatch(/byte count/);
  });

  it("detects entriesDigest mismatch (manifest entries list tampered)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-dig-"));
    build(dir);
    const m = readManifest(dir);
    // Add a phantom entry — entries changed but digest not recomputed.
    m.entries.push({ path: "phantom.json", sha256: "0".repeat(64), bytes: 1 });
    writeManifest(dir, m);
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toMatch(/entriesDigest mismatch/);
  });

  it("detects duplicate paths in the manifest", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-dup-"));
    build(dir);
    const m = readManifest(dir);
    const run = m.entries.find((e) => e.path === "run.json");
    if (run === undefined) throw new Error("missing run entry");
    m.entries.push({ ...run });
    m.entriesDigest = await digestOf(m.entries);
    writeManifest(dir, m);
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(false);
    // Caught at the schema layer (first gate); verifyBundle adds a second check.
    expect(v.failures.join(" ")).toMatch(/duplicate path/);
  });

  it("rejects path traversal (..) even with a correct digest", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-trav-"));
    build(dir);
    // Drop a file OUTSIDE the bundle dir for the manifest to point at.
    const outside = mkdtempSync(join(tmpdir(), "rai-outside-"));
    writeFileSync(join(outside, "stolen.txt"), "secret");
    const m = readManifest(dir);
    m.entries.push({ path: "../../stolen.txt", sha256: await digestOfFile(join(outside, "stolen.txt")), bytes: 6 });
    m.entriesDigest = await digestOf(m.entries);
    writeManifest(dir, m);
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(false);
    // Traversal is rejected at the schema layer even when the digest is honest.
    expect(v.failures.join(" ")).toMatch(/traversal|path escapes/);
  });

  it("rejects absolute paths in the manifest", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-abs-"));
    build(dir);
    const outside = mkdtempSync(join(tmpdir(), "rai-outside2-"));
    writeFileSync(join(outside, "etc-passwd"), "root:x:0:0");
    const m = readManifest(dir);
    m.entries.push({ path: join(outside, "etc-passwd"), sha256: await digestOfFile(join(outside, "etc-passwd")), bytes: 10 });
    m.entriesDigest = await digestOf(m.entries);
    writeManifest(dir, m);
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toMatch(/path escapes bundle dir/);
  });

  it("rejects a malformed manifest (bad JSON)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-mal-"));
    build(dir);
    writeFileSync(join(dir, "manifest.json"), "{ not json");
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(false);
    expect(v.failures[0]).toMatch(/manifest\.json/);
  });

  it("rejects a manifest failing schema validation", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-sch-"));
    build(dir);
    const m = readManifest(dir);
    delete (m as Partial<EvidenceBundleManifest>).entriesDigest;
    writeManifest(dir, { ...m, schemaVersion: "9.9" } as unknown as EvidenceBundleManifest);
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(false);
  });

  it("detects a tampered attached report (report.txt / report.json)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-rep-"));
    const { manifest } = build(dir);
    attachReports(dir, manifest, { humanText: "REPORT clean", machineReport: emptyReport() });
    writeFileSync(join(dir, "report.txt"), "REPORT fabricated findings: all pass");
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toMatch(/report\.txt/);
  });

  it("detects a tampered attached report.json (integrity + checksum both catch it)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-repjson-"));
    const { manifest } = build(dir);
    const finalManifest = attachReports(dir, manifest, { humanText: "REPORT clean", machineReport: emptyReport() });
    expect(finalManifest.entries.some((e) => e.path === "report.json")).toBe(true);
    const tamperedReport = JSON.parse(readFileSync(join(dir, "report.json"), "utf8")) as { riskScore: number };
    tamperedReport.riskScore = 0.999;
    writeFileSync(join(dir, "report.json"), JSON.stringify(tamperedReport, null, 2));
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toMatch(/report\.json: checksum mismatch/);
  });

  it("detects a deleted artifact referenced by the manifest", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rai-del-"));
    build(dir);
    const { rmSync } = await import("node:fs");
    rmSync(join(dir, "findings.json"));
    const v = await verifyBundle(dir);
    expect(v.ok).toBe(false);
    expect(v.failures.join(" ")).toMatch(/findings\.json: unreadable/);
  });
});

async function digestOf(entries: unknown): Promise<string> {
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(JSON.stringify(entries)).digest("hex");
}

async function digestOfFile(p: string): Promise<string> {
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(readFileSync(p)).digest("hex");
}

// keep mkdirSync referenced for future fixtures
void mkdirSync;
