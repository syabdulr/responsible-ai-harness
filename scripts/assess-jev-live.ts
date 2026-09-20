/**
 * Opt-in LIVE Jev smoke run — makes real, billed network calls.
 *
 * Gate (checked before anything else, before any import-time side effect
 * could matter, and before any client/transport is constructed):
 *   - `JEV_SMOKE_CONFIRM` must equal the exact literal
 *     `I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL`.
 *   - `TYPESAFE_API_KEY` must be set.
 * Either missing/wrong => exit 1, zero calls, zero client construction.
 *
 * Scope: the four fixed synthetic demo cases only
 * (case_injection_doc, case_canary_leak, case_unauthorized_send,
 * case_ambiguous_bypass) — the exact same `DEMO_CASES` the offline demo
 * runs. Same orchestration as `npm run demo` (`scripts/lib/demo-bundle.ts`
 * — hard rules first, existing precedence, redaction, fail-closed judge
 * routing, report schema 1.0.0, evidence bundle, offline verification),
 * with two differences: a LIVE `JevJudge` instead of `StubJudge` (never
 * imported here — a fallback to it is structurally impossible, not just
 * avoided by convention), and evidence built by the allowlisted
 * `buildJevEvidence` mapper from already-normalized, already-redacted
 * canonical events instead of the StubJudge `judge_hint` fixture marker.
 *
 * Exactly one `JevJudge.score()` call per case (4 total), sequential
 * (a plain `for...of` loop with `await`, same as the offline demo), no
 * retries (the transport is built with `maxRetries: 0`).
 *
 * The API key lives only in this process's memory for the duration of
 * the SDK call (see `JevJudge`'s and `createTypeSafeJevTransport`'s own
 * doc comments) — it never reaches a browser, is never logged, and this
 * script never starts a server or listener of any kind.
 *
 * Output is written to `evidence-out-live-jev/` (gitignored) and, ONLY if
 * the bundle AND the embedded report BOTH re-verify after the run,
 * mirrored into `ui/data-live/` for `npm run ui` to optionally display.
 * A verification failure writes nothing to `ui/data-live/` — the UI's
 * offline default is never put at risk by a bad live run.
 *
 * Run (after you provide both env vars yourself):
 *   TYPESAFE_API_KEY=... JEV_SMOKE_CONFIRM=I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL npm run assess:jev-live
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { runDemoPipeline, DEMO_MANIFEST } from "./lib/demo-bundle.ts";
import { DEMO_CASES } from "../src/fixtures/cases.ts";
import type { DemoCase } from "../src/fixtures/cases.ts";
import { JevJudge } from "../src/judges/jev.ts";
import { createTypeSafeJevTransport } from "../src/judges/jev-transport-typesafe.ts";
import { createEnvSecretProvider, JEV_MCP_SECRET_REF } from "../src/mcp/jev-mcp-connector.ts";
import { buildJevEvidence, EvidenceMappingError } from "../src/judges/evidence-mapper.ts";
import { JEV_QUESTION_CATALOG_VERSION, CATEGORY_QUESTION_IDS } from "../src/judges/jev-questions.ts";
import { JEV_THRESHOLD_POLICY_VERSION } from "../src/judges/jev-threshold-policy.ts";
import { validateCapabilityManifest } from "../src/contracts/validation.ts";
import { validateReport } from "../src/contracts/report-validation.ts";
import { verifyReportIntegrity } from "../src/report/build-report.ts";
import type { CanonicalEvent } from "../src/contracts/types.ts";

const REQUIRED_CONFIRM = "I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL";
/** Expected per-category question counts for Jev catalog 2.0.0 — asserted, not just documented. */
const EXPECTED_QUESTION_COUNTS: Record<string, number> = {
  prompt_injection: 2,
  secret_pii_leakage: 2,
  unsafe_tool_use: 3,
  policy_bypass: 1,
};

/**
 * Checked first, before anything else in `main` — including before the
 * live `JevJudge`/transport are constructed. Never reads the key value
 * into a local variable here; only confirms it is present. The actual
 * key is resolved later, exactly once, inside `createEnvSecretProvider`'s
 * closure (the one place in the connector/live-script surface allowed to
 * read it), and handed straight to the SDK client — never stored on this
 * script's own state.
 */
function checkGate(): void {
  const confirm = process.env.JEV_SMOKE_CONFIRM;
  if (confirm !== REQUIRED_CONFIRM) {
    console.error(
      `Refusing to run: this makes real, billed calls to the live Jev API.\n` +
      `Set JEV_SMOKE_CONFIRM=${REQUIRED_CONFIRM} to confirm you understand that, then re-run.\n` +
      `Zero calls were made.`,
    );
    process.exit(1);
  }
  const hasKey = process.env.TYPESAFE_API_KEY !== undefined && process.env.TYPESAFE_API_KEY.length > 0;
  if (!hasKey) {
    console.error("Refusing to run: TYPESAFE_API_KEY is not set. Zero calls were made.");
    process.exit(1);
  }
}

function assertExpectedQuestionCatalog(): void {
  // Widen to `string` first: JEV_QUESTION_CATALOG_VERSION is typed as the
  // literal "2.0.0" today, which would narrow the inequality branch below
  // to `never` and make it unusable in the error message if compared directly.
  const actualCatalogVersion: string = JEV_QUESTION_CATALOG_VERSION;
  if (actualCatalogVersion !== "2.0.0") {
    throw new Error(`expected Jev question catalog 2.0.0, found ${actualCatalogVersion} — this script's [2,2,3,1] assumption may no longer hold`);
  }
  for (const c of DEMO_CASES) {
    const expected = EXPECTED_QUESTION_COUNTS[c.category];
    const actual = CATEGORY_QUESTION_IDS[c.category]?.length ?? 0;
    if (actual !== expected) {
      throw new Error(`category ${c.category}: expected ${String(expected)} catalog questions, found ${String(actual)}`);
    }
  }
}

/** Real, non-negative pricing ONLY if the caller supplies it — never a made-up rate. */
function readOptionalPricing(): { perThousandInputUsd: number; perThousandOutputUsd: number } | undefined {
  const inRaw = process.env.JEV_PRICE_PER_1K_INPUT_TOKENS_USD;
  const outRaw = process.env.JEV_PRICE_PER_1K_OUTPUT_TOKENS_USD;
  if (inRaw === undefined || outRaw === undefined) return undefined;
  const perThousandInputUsd = Number(inRaw);
  const perThousandOutputUsd = Number(outRaw);
  if (!Number.isFinite(perThousandInputUsd) || perThousandInputUsd < 0) return undefined;
  if (!Number.isFinite(perThousandOutputUsd) || perThousandOutputUsd < 0) return undefined;
  return { perThousandInputUsd, perThousandOutputUsd };
}

async function main(): Promise<void> {
  checkGate();
  assertExpectedQuestionCatalog();

  const manifestCheck = validateCapabilityManifest(DEMO_MANIFEST);
  if (!manifestCheck.ok) throw new Error(`demo manifest failed validation: ${manifestCheck.error}`);

  console.log("== LIVE Jev smoke run — 4 fixed synthetic cases, real network calls ==\n");

  const secretProvider = createEnvSecretProvider();
  const liveJudge = new JevJudge(
    { secretRef: JEV_MCP_SECRET_REF, liveMode: true, timeoutMs: 15_000 },
    secretProvider,
    (key: string) => createTypeSafeJevTransport(key),
  );

  let callCount = 0;
  const countingJudge = {
    id: liveJudge.id,
    version: liveJudge.version,
    score: (input: Parameters<JevJudge["score"]>[0]) => {
      callCount += 1;
      return liveJudge.score(input);
    },
  };

  const buildJudgeEvidence = (c: DemoCase, guardedEvents: CanonicalEvent[]): Record<string, unknown> => {
    try {
      return buildJevEvidence(c.caseId, c.category, guardedEvents);
    } catch (error) {
      if (error instanceof EvidenceMappingError) {
        throw new Error(`refusing to score ${c.caseId}: ${error.message}`);
      }
      throw error;
    }
  };

  const outDir = join(process.cwd(), "evidence-out-live-jev");
  const result = await runDemoPipeline({
    outDir,
    log: (line) => { console.log(line); },
    judge: countingJudge,
    buildJudgeEvidence,
    toolVersions: {
      bundle: { harness: "0.1.0", jev: liveJudge.version, jevQuestionCatalog: JEV_QUESTION_CATALOG_VERSION, jevThresholdPolicy: JEV_THRESHOLD_POLICY_VERSION },
      report: { harness: "0.1.0", jev: liveJudge.version, jevQuestionCatalog: JEV_QUESTION_CATALOG_VERSION, jevThresholdPolicy: JEV_THRESHOLD_POLICY_VERSION },
    },
  });

  if (callCount !== DEMO_CASES.length) {
    throw new Error(`expected exactly ${String(DEMO_CASES.length)} Jev calls, made ${String(callCount)} — refusing to publish an inconsistent run`);
  }
  console.log(`\n[live] made exactly ${String(callCount)} live Jev call(s), one per case, sequential, no retries.`);

  // Self-verify before this run is ever allowed to reach the UI: bundle
  // checksums AND the embedded report's own integrity hash must both
  // re-validate. A failure here writes nothing to ui/data-live/.
  const reportCheck = validateReport(result.report);
  const reportIntegrityOk = verifyReportIntegrity(result.report);
  const allOk = result.verify.ok && reportCheck.ok && reportIntegrityOk;

  console.log(`[live] bundle self-verification: ${result.verify.ok ? "OK" : "FAILED"}`);
  console.log(`[live] report contract validation: ${reportCheck.ok ? "OK" : `FAILED (${reportCheck.ok ? "" : reportCheck.error})`}`);
  console.log(`[live] report integrity hash: ${reportIntegrityOk ? "OK" : "FAILED"}`);

  if (!allOk) {
    console.error("\nIntegrity check failed — refusing to publish this run to the UI. See evidence-out-live-jev/ for the raw artifacts.");
    process.exit(1);
  }

  const pricing = readOptionalPricing();
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  for (const c of result.report.cases) {
    if (c.judge?.usage !== undefined) {
      totalInputTokens += c.judge.usage.inputTokens;
      totalOutputTokens += c.judge.usage.outputTokens;
    }
  }
  const usageSummary = {
    totalInputTokens,
    totalOutputTokens,
    costUsd: pricing !== undefined
      ? Number(((totalInputTokens / 1000) * pricing.perThousandInputUsd + (totalOutputTokens / 1000) * pricing.perThousandOutputUsd).toFixed(6))
      : null,
    costNote: pricing !== undefined
      ? "Calculated from real returned token usage and the pricing you supplied via JEV_PRICE_PER_1K_*_TOKENS_USD."
      : "Not calculated: no JEV_PRICE_PER_1K_INPUT_TOKENS_USD / JEV_PRICE_PER_1K_OUTPUT_TOKENS_USD supplied. Token usage above is real; no rate was invented.",
  };

  // This script does NOT publish to the UI itself — `scripts/serve-report-ui.ts`
  // is the single trust boundary that decides what the browser can see. It
  // re-verifies this bundle from scratch (not by trusting this process's
  // verdict) before ever exposing a "live" source. This script only writes
  // the raw bundle plus a usage/cost summary alongside it.
  writeFileSync(join(outDir, "usage.json"), JSON.stringify(usageSummary, null, 2));

  console.log(`\n[live] bundle written to evidence-out-live-jev/ (self-verified OK).`);
  console.log(`[live] token usage: ${String(totalInputTokens)} input / ${String(totalOutputTokens)} output. ${usageSummary.costNote}`);
  console.log(`[live] run "npm run ui" — it re-verifies this bundle independently before offering a LIVE JEV source.`);
}

await main();
