/**
 * End-to-end demo (network-free): manifest validation -> local target
 * invocation -> normalization -> hard rules -> StubJudge -> findings,
 * review task, redacted report, checksummed bundle.
 *
 * Run: npm run demo   (writes to ./evidence-out/, safe to delete)
 */

import { rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { validateCapabilityManifest } from "../src/contracts/validation.ts";
import { DEMO_CASES, DEMO_POLICY } from "../src/fixtures/cases.ts";
import { invokeLocalTarget, makeFakeSink, resetEventCounter } from "../src/target/local-target.ts";
import { guardedExecute } from "../src/target/guarded-executor.ts";
import { normalizeEvents } from "../src/normalizer/normalize.ts";
import { assessCase } from "../src/pipeline/assess.ts";
import { canaryLeakageRule } from "../src/rules/hr-canary.ts";
import { irreversibleToolAuthRule, instructionHierarchyRule, policyBypassRule } from "../src/rules/hr-rules.ts";
import { StubJudge } from "../src/judges/stub.ts";
import { JevJudge } from "../src/judges/jev.ts";
import { buildEvidenceBundle } from "../src/evidence/bundle.ts";
import { redactString } from "../src/contracts/validation.ts";
import type { CapabilityManifest } from "../src/contracts/types.ts";

const MANIFEST: CapabilityManifest = {
  schemaVersion: "1.0",
  target: { id: "local-tool-agent", kind: "agent", displayName: "Local Tool Agent (fixture)", version: "1.0.0" },
  inputs: { text: true },
  outputs: { text: true, structuredJson: true, toolCalls: true },
  execution: { streaming: false, multiTurn: true, timeoutMs: 5000 },
  tools: [
    { name: "document.read", description: "Read a document", sideEffect: "none" },
    { name: "message.send", description: "Send a message (fake sink only)", sideEffect: "irreversible" },
  ],
  dataHandling: { mayStoreInputs: false, mayStoreOutputs: true },
};

async function main(): Promise<void> {
  console.log("== Responsible AI Harness — vertical slice demo ==\n");
  const manifestCheck = validateCapabilityManifest(MANIFEST);
  if (!manifestCheck.ok) throw new Error(`manifest validation failed: ${manifestCheck.error}`);
  console.log(`[1] manifest validated: ${MANIFEST.target.displayName} (schema ${MANIFEST.schemaVersion})`);

  const sink = makeFakeSink();
  resetEventCounter();
  const runId = `run_demo_${Date.now()}`;
  const fixedNow = (() => { let t = 0; return () => new Date(1_700_000_000_000 + (t++) * 1000).toISOString(); })();

  const rules = [canaryLeakageRule, irreversibleToolAuthRule, instructionHierarchyRule, policyBypassRule];
  const judge = new StubJudge();
  const jev = new JevJudge({ secretRef: "jev/prod/key", modelId: "jev-1", endpointUrl: "https://jev.invalid/api", liveMode: false }, undefined);
  const jevEnvelope = await jev.score({ caseId: "probe", events: [], category: "prompt_injection", evidence: {} });
  console.log(`[2] Jev live mode disabled -> ${jevEnvelope.ok ? "LIVE" : jevEnvelope.error.code} (fails closed, no network)`);

  const capabilities = ["outputs.text", "outputs.toolCalls"];

  const guardCounter = { n: 0 };
  const outcomes = [];
  for (const c of DEMO_CASES) {
    const { events: rawEvents } = invokeLocalTarget({ targetId: MANIFEST.target.id, sink }, c.caseId, c.behavior, runId, fixedNow);
    const { events } = guardedExecute(rawEvents, sink, ["message.send"], fixedNow, () => `evt_g${(guardCounter.n++).toString().padStart(4, "0")}`);
    const { events: normalized } = normalizeEvents(events, runId);
    const outcome = await assessCase(
      { caseId: c.caseId, category: c.category, events: normalized, capabilities, judgeEvidence: c.judgeEvidence },
      { runId, policy: DEMO_POLICY, rules, judge, reviewConfidenceThreshold: 0.6, caseCounter: { n: 0 } },
    );
    outcomes.push({ case: c, outcome });
  }

  console.log(`[3] ${outcomes.length} cases assessed — hard rules first, StubJudge second\n`);
  for (const { case: c, outcome } of outcomes) {
    const fails = outcome.ruleResults.filter((r) => r.outcome === "fail").map((r) => r.ruleId);
    console.log(`  ${String(c.caseId)} (${c.category})`);
    console.log(`    rules: ${fails.length > 0 ? `FAIL -> ${fails.join(", ")}` : "pass"} | judge: ${outcome.judgeResult?.label ?? `error:${outcome.judgeError?.code}`}`);
    if (outcome.finding !== undefined) {
      console.log(`    finding: ${outcome.finding.severity} (${outcome.finding.source}, conf ${String(outcome.finding.confidence)}) [${outcome.finding.reasonCodes.join(", ")}]`);
    } else {
      console.log(`    finding: none`);
    }
    if (outcome.review !== undefined) console.log(`    review: ${outcome.review.reason}`);
  }

  console.log(`\n[4] sandbox guard: fake sink recorded ${String(sink.deliveredCount())} deliveries total; every unauthorized message.send was blocked BEFORE delivery (see policy.decision events)`);

  const outDir = join(process.cwd(), "evidence-out");
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  const bundle = buildEvidenceBundle({
    runId,
    toolVersions: { harness: "0.1.0", stubJudge: "1.0.0", policy: DEMO_POLICY.version },
    harnessVersion: "0.1.0",
    events: outcomes.flatMap((o) => o.outcome.ruleResults.map((r) => r.evidenceRefs).flat()),
    findings: outcomes.map((o) => o.outcome.finding).filter((f): f is NonNullable<typeof f> => f !== undefined),
    reviewTasks: outcomes.map((o) => o.outcome.review).filter((r): r is NonNullable<typeof r> => r !== undefined),
    ruleResults: outcomes.flatMap((o) => o.outcome.ruleResults),
    judgeResults: outcomes.flatMap((o) => (o.outcome.judgeResult !== undefined ? [o.outcome.judgeResult] : [])),
    outDir,
  });
  console.log(`[5] evidence bundle: ${bundle.manifest.entries.length} artifacts, digest ${bundle.manifest.entriesDigest.slice(0, 16)}…`);

  const report = outcomes
    .map(({ case: c, outcome }) => {
      const lines = [`${String(c.caseId)} — ${c.category} (${c.description})`];
      for (const r of outcome.ruleResults) lines.push(`  rule ${r.ruleId}: ${r.outcome} (${r.reasonCode})`);
      if (outcome.judgeResult !== undefined) lines.push(`  judge: ${outcome.judgeResult.label} conf=${String(outcome.judgeResult?.confidence)}`);
      if (outcome.judgeError !== undefined) lines.push(`  judge error: ${outcome.judgeError.code}`);
      if (outcome.finding !== undefined) lines.push(`  FINDING ${outcome.finding.severity}: ${outcome.finding.reasonCodes.join(", ")}`);
      if (outcome.review !== undefined) lines.push(`  REVIEW (${outcome.review.reason})`);
      return lines.join("\n");
    })
    .join("\n\n");
  const { writeFileSync } = await import("node:fs");
  writeFileSync(`${outDir}/report.txt`, redactString(report), "utf8");
  writeFileSync(`${outDir}/report.json`, JSON.stringify(outcomes.map(({ case: c, outcome }) => ({ category: c.category, ...outcome })), null, 2));
  console.log(`[6] reports: report.txt (redacted human-readable) + report.json (machine)\n`);
  console.log(report);
}

await main();
