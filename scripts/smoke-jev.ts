/**
 * Opt-in, one-call Jev smoke test. NOT wired into `npm test`, `npm run
 * check`, or any CI gate — it exists so a human can deliberately verify
 * live connectivity after code review, outside automated gates.
 *
 * Guardrails:
 * - Refuses to run unless `JEV_SMOKE_CONFIRM` matches the exact literal
 *   below, so `npm run smoke:jev` alone never fires a real call.
 * - Makes exactly one bounded `systemOne` call (see `jev-transport-typesafe.ts`:
 *   `retry: { maxRetries: 0 }` at both the client and the call).
 * - Never logs, prints, or persists the API key. The key is read once
 *   from `TYPESAFE_API_KEY` inside the secret provider closure below and
 *   handed straight to the production transport factory; this script
 *   never assigns it to a variable that outlives that call.
 * - Prints only the resulting label, confidence, and model id — never the
 *   evidence sent, never request/response bodies.
 *
 * Run: JEV_SMOKE_CONFIRM=I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL \
 *      TYPESAFE_API_KEY=... npm run smoke:jev
 */

import { JevJudge } from "../src/judges/jev.ts";
import type { RuntimeSecretProvider } from "../src/judges/jev.ts";
import { createTypeSafeJevTransport } from "../src/judges/jev-transport-typesafe.ts";

const CONFIRM_VALUE = "I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL";
const SECRET_REF = "env:TYPESAFE_API_KEY";

async function main(): Promise<void> {
  if (process.env.JEV_SMOKE_CONFIRM !== CONFIRM_VALUE) {
    console.error(
      [
        "Refusing to run: this makes one real network call to the live Jev API.",
        `Set JEV_SMOKE_CONFIRM=${CONFIRM_VALUE} and TYPESAFE_API_KEY to proceed.`,
        "This script is opt-in only and is never run by npm test or npm run check.",
      ].join("\n"),
    );
    process.exitCode = 1;
    return;
  }

  const secretProvider: RuntimeSecretProvider = {
    resolve(secretRef: string): string | undefined {
      if (secretRef !== SECRET_REF) return undefined;
      const value = process.env.TYPESAFE_API_KEY;
      return value !== undefined && value.length > 0 ? value : undefined;
    },
  };

  const jev = new JevJudge({ secretRef: SECRET_REF, liveMode: true, timeoutMs: 15_000 }, secretProvider, (apiKey) => createTypeSafeJevTransport(apiKey));

  const envelope = await jev.score({
    caseId: "smoke_test",
    events: [],
    category: "prompt_injection",
    evidence: { note: "Smoke test: a harmless request containing no injected instructions." },
  });

  if (envelope.ok) {
    console.log(`OK — label=${envelope.result.label} confidence=${String(envelope.result.confidence)} model=${String(envelope.result.modelMetadata.jev_model ?? "unknown")}`);
  } else {
    console.error(`FAILED — ${envelope.error.code}: ${envelope.error.message}`);
    process.exitCode = 1;
  }
}

await main();
