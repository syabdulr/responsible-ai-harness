/**
 * Opt-in, one-call smoke test for the Jev MCP connector. NOT wired into
 * `npm test`, `npm run check`, or any CI gate — like `smoke-jev.ts`, it
 * exists so a human can deliberately verify the connector's real
 * end-to-end wiring after code review, outside automated gates.
 *
 * This calls `evaluateResponsibleAiCase` directly (in-process) against
 * the production transport, rather than spawning a separate stdio
 * process — that keeps this a genuine "one call" test of the same code
 * path `mcp-jev-connector-serve.ts` runs, without adding process-spawn
 * mechanics that would exist only for this smoke test.
 *
 * Guardrails: identical to `smoke-jev.ts` — refuses without the exact
 * confirmation literal, makes exactly one bounded call (enforced by
 * `JevJudge`/`createTypeSafeJevTransport`), and never logs the key or the
 * evidence sent.
 *
 * Run: JEV_SMOKE_CONFIRM=I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL \
 *      TYPESAFE_API_KEY=... npm run smoke:jev-mcp
 */

import { EvaluateCaseInputSchema, createEnvSecretProvider, evaluateResponsibleAiCase } from "../src/mcp/jev-mcp-connector.ts";
import { JevJudge } from "../src/judges/jev.ts";
import { createTypeSafeJevTransport } from "../src/judges/jev-transport-typesafe.ts";

const CONFIRM_VALUE = "I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL";
const SECRET_REF = "env:TYPESAFE_API_KEY";

async function main(): Promise<void> {
  if (process.env.JEV_SMOKE_CONFIRM !== CONFIRM_VALUE) {
    console.error(
      [
        "Refusing to run: this makes one real network call to the live Jev API through the MCP connector's tool logic.",
        `Set JEV_SMOKE_CONFIRM=${CONFIRM_VALUE} and TYPESAFE_API_KEY to proceed.`,
        "This script is opt-in only and is never run by npm test or npm run check.",
      ].join("\n"),
    );
    process.exitCode = 1;
    return;
  }

  const jev = new JevJudge({ secretRef: SECRET_REF, liveMode: true, timeoutMs: 15_000 }, createEnvSecretProvider(), (apiKey) => createTypeSafeJevTransport(apiKey));
  const input = EvaluateCaseInputSchema.parse({
    caseId: "smoke_test",
    category: "prompt_injection",
    evidence: { note: "Smoke test: a harmless request containing no injected instructions." },
  });

  const result = await evaluateResponsibleAiCase(input, jev);
  if (result.ok) {
    console.log(`OK — label=${result.label} confidence=${String(result.confidence)} model=${String(result.modelMetadata.jev_model ?? "unknown")}`);
  } else {
    console.error(`FAILED — ${result.code}: ${result.message}`);
    process.exitCode = 1;
  }
}

await main();
