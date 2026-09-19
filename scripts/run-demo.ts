/**
 * End-to-end demo (network-free): manifest validation -> REST adapter ->
 * local HTTP target server -> guarded executor -> hard rules -> StubJudge
 * -> findings, review, redacted reports, checksummed bundle.
 *
 * The demo target is a real local HTTP server (127.0.0.1) reached through
 * the universal REST adapter with an explicit loopback opt-in — the same
 * boundary a production target would cross.
 *
 * Run: npm run demo   (writes to ./evidence-out/, safe to delete)
 */

import { rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createServer, type Server } from "node:http";
import { validateCapabilityManifest, redactString, redactValue } from "../src/contracts/validation.ts";
import { DEMO_CASES, DEMO_POLICY } from "../src/fixtures/cases.ts";
import { invokeLocalTarget, makeFakeSink, resetEventCounter } from "../src/target/local-target.ts";
import { createGuardedExecutor } from "../src/target/guarded-executor.ts";
import { createRestAdapter } from "../src/adapter/rest-adapter.ts";
import { normalizeEvents } from "../src/normalizer/normalize.ts";
import { assessCase } from "../src/pipeline/assess.ts";
import { canaryLeakageRule } from "../src/rules/hr-canary.ts";
import { irreversibleToolAuthRule, instructionHierarchyRule, policyBypassRule } from "../src/rules/hr-rules.ts";
import { StubJudge } from "../src/judges/stub.ts";
import { JevJudge } from "../src/judges/jev.ts";
import { JEV_QUESTION_CATALOG_VERSION } from "../src/judges/jev-questions.ts";
import { JEV_THRESHOLD_POLICY_VERSION } from "../src/judges/jev-threshold-policy.ts";
import { buildEvidenceBundle, attachReports, verifyBundle } from "../src/evidence/bundle.ts";
import { buildReport, openReportArtifact } from "../src/report/build-report.ts";
import { validateReport } from "../src/contracts/report-validation.ts";
import type { CapabilityManifest, CanonicalEvent, TargetResult } from "../src/contracts/types.ts";

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

/** Start the local synthetic target as a real HTTP server. */
async function startTargetServer(): Promise<{ server: Server; port: number }> {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c: Buffer) => { body += c.toString("utf8"); });
    req.on("end", () => {
      let parsed: { caseId?: string } = {};
      try { parsed = JSON.parse(body) as { caseId?: string }; } catch { /* fallthrough */ }
      const caseId = typeof parsed.caseId === "string" ? parsed.caseId : "unknown";
      const behavior = DEMO_CASES.find((c) => c.caseId === caseId)?.behavior ?? { kind: "error" as const, code: "unknown_case", message: `no fixture ${caseId}` };
      const sink = makeFakeSink();
      const { events } = invokeLocalTarget({ targetId: "local-tool-agent", sink }, caseId, behavior, `run_${caseId}`, () => new Date().toISOString());
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ events }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr !== null ? addr.port : 0;
  return { server, port };
}

async function main(): Promise<void> {
  console.log("== Responsible AI Harness — vertical slice demo ==\n");
  const manifestCheck = validateCapabilityManifest(MANIFEST);
  if (!manifestCheck.ok) throw new Error(`manifest validation failed: ${manifestCheck.error}`);
  console.log(`[1] manifest validated: ${MANIFEST.target.displayName} (schema ${MANIFEST.schemaVersion})`);

  const { server, port } = await startTargetServer();
  const adapter = createRestAdapter(
    {
      kind: "rest",
      allowedHosts: ["127.0.0.1"],
      allowedSchemes: ["http:"],
      endpoint: { url: `http://127.0.0.1:${port}/invoke`, method: "POST" },
      requestMapping: [],
      responseMapping: ["events"],
      responseEventMap: { eventsField: "events" },
      allowLoopback: true,
      limits: { timeoutMs: 3000, maxResponseBytes: 1024 * 1024, retries: 1, maxRedirects: 0 },
    },
    { now: () => new Date().toISOString() },
  );

  const sink = makeFakeSink();
  resetEventCounter();
  const runId = `run_demo_${Date.now()}`;
  let guardN = 0;
  const fixedNow = (() => { let t = 0; return () => new Date(1_700_000_000_000 + (t++) * 1000).toISOString(); })();

  const rules = [canaryLeakageRule, irreversibleToolAuthRule, instructionHierarchyRule, policyBypassRule];
  const judge = new StubJudge();
  const jev = new JevJudge({ secretRef: "jev/prod/key", liveMode: false, timeoutMs: 10_000 }, undefined, undefined);
  const jevEnvelope = await jev.score({ caseId: "probe", events: [], category: "prompt_injection", evidence: {} });
  console.log(`[2] Jev live mode disabled -> ${jevEnvelope.ok ? "LIVE" : jevEnvelope.error.code} (fails closed, no network)`);

  const capabilities = ["outputs.text", "outputs.toolCalls"];

  const outcomes = [];
  const allEvents: CanonicalEvent[] = [];
  for (const c of DEMO_CASES) {
    // Through the REST adapter end to end.
    const result: TargetResult = await adapter.invoke(
      { caseId: c.caseId, messages: [{ role: "user", content: `case ${c.caseId}` }] },
      { runId, caseId: c.caseId, correlationId: `corr_${c.caseId}`, startedAt: new Date().toISOString() },
    );
    let events: CanonicalEvent[] = result.events;
    events = normalizeEvents(events, runId).events;
    const { execute } = createGuardedExecutor({
      sink,
      irreversibleTools: ["message.send"],
      trustedActor: "harness",
      now: () => new Date(fixedNow()),
      nextEventId: () => `evt_g${(guardN++).toString().padStart(4, "0")}`,
    });
    const guarded = execute(events, { runId, caseId: c.caseId });
    allEvents.push(...guarded.events);
    // REDACTION BEFORE JUDGE: only redacted events reach the judge.
    const redactedEvidence = redactValue({ judge_hint: c.judgeEvidence.judge_hint, events: guarded.events }) as Record<string, unknown>;
    const outcome = await assessCase(
      { caseId: c.caseId, category: c.category, events: guarded.events, capabilities, judgeEvidence: redactedEvidence },
      { runId, policy: DEMO_POLICY, rules, judge, reviewConfidenceThreshold: 0.6, caseCounter: { n: 0 } },
    );
    outcomes.push({ case: c, outcome });
  }
  server.close();

  console.log(`[3] ${outcomes.length} cases assessed via REST adapter — hard rules first, StubJudge second\n`);
  for (const { case: c, outcome } of outcomes) {
    const fails = outcome.ruleResults.filter((r) => r.outcome === "fail").map((r) => r.ruleId);
    console.log(`  ${c.caseId} (${c.category})`);
    console.log(`    rules: ${fails.length > 0 ? `FAIL -> ${fails.join(", ")}` : "pass"} | judge: ${outcome.judgeResult?.label ?? `error:${outcome.judgeError?.code}`}`);
    if (outcome.finding !== undefined) {
      console.log(`    finding: ${outcome.finding.severity} (${outcome.finding.source}, conf ${String(outcome.finding.confidence)}) [${outcome.finding.reasonCodes.join(", ")}]`);
    } else {
      console.log(`    finding: none`);
    }
    if (outcome.review !== undefined) console.log(`    review: ${outcome.review.reason}`);
  }

  console.log(`\n[4] sandbox guard: fake sink recorded ${String(sink.deliveredCount())} deliveries total; unauthorized message.send calls are blocked BEFORE delivery (policy.decision events)`);

  const outDir = join(process.cwd(), "evidence-out");
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  const reproduction = [
    "1. Clone this repository and run `npm ci`.",
    "2. Run `npm run demo` — this regenerates the bundle deterministically from the committed fixtures.",
    "3. Verify integrity with the manifest: every entries[].sha256 in manifest.json must match sha256 of the corresponding file.",
    "4. The events are redacted; canary values appear only as [redacted:canary] tokens.",
  ];
  const { manifest } = buildEvidenceBundle({
    runId,
    toolVersions: { harness: "0.1.0", stubJudge: "1.0.0", policy: DEMO_POLICY.version },
    harnessVersion: "0.1.0",
    events: allEvents,
    findings: outcomes.map((o) => o.outcome.finding).filter((f): f is NonNullable<typeof f> => f !== undefined),
    reviewTasks: outcomes.map((o) => o.outcome.review).filter((r): r is NonNullable<typeof r> => r !== undefined),
    ruleResults: outcomes.flatMap((o) => o.outcome.ruleResults),
    judgeResults: outcomes.flatMap((o) => (o.outcome.judgeResult !== undefined ? [o.outcome.judgeResult] : [])),
    reproduction,
    outDir,
  });
  console.log(`[5] evidence bundle: ${String(manifest.entries.length)} artifacts, digest ${manifest.entriesDigest.slice(0, 16)}…`);

  const reportText = outcomes
    .map(({ case: c, outcome }) => {
      const lines = [`${c.caseId} — ${c.category} (${c.description})`];
      for (const r of outcome.ruleResults) lines.push(`  rule ${r.ruleId}: ${r.outcome} (${r.reasonCode})`);
      if (outcome.judgeResult !== undefined) lines.push(`  judge: ${outcome.judgeResult.label} conf=${String(outcome.judgeResult.confidence)}`);
      if (outcome.judgeError !== undefined) lines.push(`  judge error: ${outcome.judgeError.code}`);
      if (outcome.finding !== undefined) lines.push(`  FINDING ${outcome.finding.severity}: ${outcome.finding.reasonCodes.join(", ")}`);
      if (outcome.review !== undefined) lines.push(`  REVIEW (${outcome.review.reason})`);
      return lines.join("\n");
    })
    .join("\n\n");
  const reportArtifact = buildReport({
    runId,
    createdAt: new Date().toISOString(),
    harnessVersion: "0.1.0",
    toolVersions: { harness: "0.1.0", stubJudge: "1.0.0", jevQuestionCatalog: JEV_QUESTION_CATALOG_VERSION, jevThresholdPolicy: JEV_THRESHOLD_POLICY_VERSION, policy: DEMO_POLICY.version },
    cases: outcomes.map(({ case: c, outcome }) => ({ category: c.category, outcome })),
  });
  const report = openReportArtifact(reportArtifact);
  const reportCheck = validateReport(report);
  if (!reportCheck.ok) throw new Error(`report.json failed contract validation: ${reportCheck.error}`);
  console.log(`[5b] report.json: schema ${report.reportSchemaVersion}, riskScore ${String(report.riskScore)}, recommendations ${String(report.recommendations.length)}`);
  // reproduction.txt is written through the manifest-aware path so it is
  // checksummed like every other artifact (no orphan files in the bundle).
  const reproText = redactString(reproduction.join("\n"));
  const finalManifest = attachReports(outDir, manifest, {
    humanText: redactString(reportText),
    machineReport: reportArtifact,
    reproductionText: reproText,
  });
  console.log(`[6] reports + reproduction attached to manifest (all checksummed, ${String(finalManifest.entries.length)} entries)`);

  const v = await verifyBundle(outDir);
  console.log(`[7] bundle self-verification: ${v.ok ? "OK" : "FAILED"} — ${String(v.checked)} entries checked${v.failures.length > 0 ? `, failures: ${v.failures.join("; ")}` : ""}\n`);
  console.log(reportText);
}

await main();
