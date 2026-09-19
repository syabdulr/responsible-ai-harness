import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { EvidenceBundleManifest, Finding, ReviewTask } from "../contracts/types.ts";
import { redactValue } from "../contracts/validation.ts";
import { sha256 } from "../normalizer/normalize.ts";

export interface BundleInput {
  runId: string;
  toolVersions: Record<string, string>;
  harnessVersion: string;
  events: unknown[];
  findings: Finding[];
  reviewTasks: ReviewTask[];
  ruleResults: unknown[];
  judgeResults: unknown[];
  outDir: string;
}

/** Build an offline-verifiable evidence bundle with checksums + lineage. */
export function buildEvidenceBundle(input: BundleInput): { manifest: EvidenceBundleManifest; dir: string } {
  mkdirSync(join(input.outDir, "cases"), { recursive: true });
  const entries: { path: string; sha256: string; bytes: number }[] = [];

  const addArtifact = (rel: string, data: unknown): void => {
    const json = JSON.stringify(data, null, 2);
    writeFileSync(join(input.outDir, rel), json);
    entries.push({ path: rel, sha256: sha256(json), bytes: Buffer.byteLength(json) });
  };

  addArtifact("run.json", { runId: input.runId, toolVersions: input.toolVersions, harnessVersion: input.harnessVersion, createdAt: new Date().toISOString() });
  addArtifact("events.jsonl.redacted.json", redactValue(input.events));
  addArtifact("rule-results.json", input.ruleResults);
  addArtifact("judge-results.json", input.judgeResults);
  addArtifact("findings.json", redactValue(input.findings));
  addArtifact("reviews.json", input.reviewTasks);

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

/** Verify a bundle offline: recompute every checksum from disk. */
export async function verifyBundle(dir: string): Promise<{ ok: boolean; checked: number; failures: string[] }> {
  // read manifest.json — parse; recompute each entry hash
  const { readFileSync } = await import("node:fs");
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8")) as EvidenceBundleManifest;
  const failures: string[] = [];
  let checked = 0;
  for (const e of manifest.entries) {
    const data = readFileSync(join(dir, e.path));
    const digest = sha256(data);
    checked += 1;
    if (digest !== e.sha256) failures.push(`${e.path}: expected ${e.sha256}, got ${digest}`);
  }
  return { ok: failures.length === 0, checked, failures };
}
