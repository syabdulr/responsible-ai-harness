/**
 * Evidence bundle: offline-verifiable, checksummed, fully redacted.
 *
 * Everything exported here is redacted BEFORE writing: events, rule
 * results, judge results, findings, review tasks, and both reports.
 * The manifest records every artifact (including reports) with
 * sha256 + byte counts; verifyBundle re-validates the manifest schema,
 * entriesDigest, duplicate paths, path containment, and per-entry
 * checksums before trusting anything.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type {
  CanonicalEvent,
  EvidenceBundleManifest,
  Finding,
  JudgeResult,
  ReviewTask,
  RuleResult,
} from "../contracts/types.ts";
import { findResidualRiskIndicators, redactString, redactValue, validateBundleManifest, parseJson } from "../contracts/validation.ts";
import { validateReport } from "../contracts/report-validation.ts";
import { openReportArtifact } from "../report/build-report.ts";
import type { ValidatedReportArtifact } from "../report/build-report.ts";
import { sha256 } from "../normalizer/normalize.ts";

export interface BundleInput {
  runId: string;
  toolVersions: Record<string, string>;
  harnessVersion: string;
  events: CanonicalEvent[];
  findings: Finding[];
  reviewTasks: ReviewTask[];
  ruleResults: RuleResult[];
  judgeResults: JudgeResult[];
  /** Self-contained reproduction instructions (redacted like everything else). */
  reproduction: string[];
  outDir: string;
}

/** Build an offline-verifiable evidence bundle with checksums + lineage. */
export function buildEvidenceBundle(input: BundleInput): { manifest: EvidenceBundleManifest; dir: string } {
  mkdirSync(join(input.outDir, "cases"), { recursive: true });
  const entries: Array<{ path: string; sha256: string; bytes: number }> = [];

  const addArtifact = (rel: string, data: unknown): void => {
    const json = JSON.stringify(redactValue(data), null, 2);
    writeFileSync(join(input.outDir, rel), json);
    entries.push({ path: rel, sha256: sha256(json), bytes: Buffer.byteLength(json) });
  };

  addArtifact("run.json", { runId: input.runId, toolVersions: input.toolVersions, harnessVersion: input.harnessVersion, createdAt: new Date().toISOString() });
  // Actual JSONL for events (newline-delimited JSON objects).
  const jsonl = input.events.map((e) => JSON.stringify(redactValue(e))).join("\n") + "\n";
  writeFileSync(join(input.outDir, "events.jsonl"), jsonl);
  entries.push({ path: "events.jsonl", sha256: sha256(jsonl), bytes: Buffer.byteLength(jsonl) });

  addArtifact("rule-results.json", input.ruleResults);
  addArtifact("judge-results.json", input.judgeResults);
  addArtifact("findings.json", input.findings);
  addArtifact("reviews.json", input.reviewTasks);
  addArtifact("reproduction.json", input.reproduction);

  const manifest: EvidenceBundleManifest = {
    schemaVersion: "1.0",
    bundleId: `bundle_${input.runId}`,
    runId: input.runId,
    createdAt: new Date().toISOString(),
    toolVersions: input.toolVersions,
    harnessVersion: input.harnessVersion,
    entries,
    redactionState: "redacted",
    entriesDigest: sha256(JSON.stringify(entries)),
  };
  writeFileSync(join(input.outDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(
    join(input.outDir, "checksums.txt"),
    entries.map((e) => `${e.sha256}  ${e.path}`).join("\n") + "\n",
  );
  return { manifest, dir: input.outDir };
}

/**
 * Attach the human and machine reports to the bundle manifest + checksums.
 *
 * `machineReport` can ONLY be a `ValidatedReportArtifact` — the sealed,
 * branded wrapper `buildReport` returns (see its doc comment) — never a
 * plain `ReportV1` a caller could assemble or mutate by hand. Getting a
 * value of that type without going through `buildReport` requires a
 * visible `as unknown as` cast; this function does not rely on that
 * alone, though. It re-verifies the artifact's integrity hash itself
 * (`openReportArtifact` throws if the hash no longer matches the
 * report's content — the exact case of a report mutated, accidentally or
 * not, after `buildReport` returned it), then re-validates the contract
 * shape (`validateReport`) and runs a residual-risk scan (the same
 * paranoid second pass `JevJudge` runs before a live call) before
 * anything is written. Any of these three checks failing throws rather
 * than writing unverified or stale content to disk. `humanText`/
 * `reproductionText` have no equivalent typed contract, so they are
 * redacted again here (idempotent defense in depth) regardless of what
 * the caller already did.
 */
export function attachReports(
  outDir: string,
  manifest: EvidenceBundleManifest,
  reports: { humanText: string; machineReport: ValidatedReportArtifact; reproductionText?: string },
): EvidenceBundleManifest {
  // Throws on a stale/mismatched hash — e.g. the report was mutated after
  // buildReport sealed it, or the "artifact" was forged via an unsafe cast
  // with a hash that doesn't match its own content.
  const report = openReportArtifact(reports.machineReport);

  const reportCheck = validateReport(report);
  if (!reportCheck.ok) {
    throw new Error(`attachReports: machineReport failed contract validation: ${reportCheck.error}`);
  }
  // Scan everything except `integrity`: its `reportSha256` is legitimately
  // a 64-char hex digest, which is exactly the shape
  // `residual_high_entropy_hex` exists to catch elsewhere.
  const { integrity, ...scannable } = reportCheck.value;
  void integrity;
  const residual = findResidualRiskIndicators(scannable);
  if (residual.length > 0) {
    throw new Error(`attachReports: machineReport still matches high-risk patterns after redaction (${residual.join(", ")}); refusing to write it`);
  }

  const humanPath = "report.txt";
  const machinePath = "report.json";
  const humanText = redactString(reports.humanText);
  const machineJson = `${JSON.stringify(reportCheck.value, null, 2)}\n`;
  writeFileSync(join(outDir, humanPath), humanText, "utf8");
  writeFileSync(join(outDir, machinePath), machineJson, "utf8");
  const newEntries = [
    ...manifest.entries,
    { path: humanPath, sha256: sha256(humanText), bytes: Buffer.byteLength(humanText) },
    { path: machinePath, sha256: sha256(machineJson), bytes: Buffer.byteLength(machineJson) },
  ];
  if (reports.reproductionText !== undefined) {
    const reproductionText = redactString(reports.reproductionText);
    writeFileSync(join(outDir, "reproduction.txt"), reproductionText, "utf8");
    newEntries.push({ path: "reproduction.txt", sha256: sha256(reproductionText), bytes: Buffer.byteLength(reproductionText) });
  }
  const updated: EvidenceBundleManifest = {
    ...manifest,
    entries: newEntries,
    entriesDigest: sha256(JSON.stringify(newEntries)),
  };
  writeFileSync(join(outDir, "manifest.json"), `${JSON.stringify(updated, null, 2)}\n`);
  writeFileSync(
    join(outDir, "checksums.txt"),
    newEntries.map((e) => `${e.sha256}  ${e.path}`).join("\n") + "\n",
  );
  return updated;
}

export interface VerifyResult {
  ok: boolean;
  checked: number;
  failures: string[];
}

/** Verify a bundle offline: manifest schema, digest, paths, checksums. */
export async function verifyBundle(dir: string): Promise<VerifyResult> {
  const { readFileSync } = await import("node:fs");
  const failures: string[] = [];

  const raw = readFileSync(join(dir, "manifest.json"), "utf8");
  const parsed = parseJson(raw);
  if (!parsed.ok) return { ok: false, checked: 0, failures: [`manifest.json: ${parsed.error}`] };
  const mv = validateBundleManifest(parsed.value);
  if (!mv.ok) return { ok: false, checked: 0, failures: [`manifest.json: ${mv.error}`] };
  const manifest = mv.value;

  // entriesDigest binds the entries list itself.
  const recomputedDigest = sha256(JSON.stringify(manifest.entries));
  if (recomputedDigest !== manifest.entriesDigest) {
    failures.push(`entriesDigest mismatch: manifest claims ${manifest.entriesDigest}, recomputed ${recomputedDigest}`);
  }

  const seen = new Set<string>();
  let checked = 0;
  for (const e of manifest.entries) {
    if (seen.has(e.path)) failures.push(`duplicate path: ${e.path}`);
    seen.add(e.path);
    // Path containment: no absolute paths, no "..", stays inside dir.
    if (e.path.startsWith("/") || e.path.split("/").includes("..")) {
      failures.push(`path escapes bundle dir: ${e.path}`);
      continue;
    }
    let data: Buffer;
    try {
      data = readFileSync(join(dir, e.path));
    } catch {
      failures.push(`${e.path}: unreadable`);
      continue;
    }
    checked += 1;
    if (data.byteLength !== e.bytes) failures.push(`${e.path}: byte count ${data.byteLength} != manifest ${e.bytes}`);
    const digest = sha256(data);
    if (digest !== e.sha256) failures.push(`${e.path}: checksum mismatch (expected ${e.sha256}, got ${digest})`);
  }
  return { ok: failures.length === 0, checked, failures };
}
