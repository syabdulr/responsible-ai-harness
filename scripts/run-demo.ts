/**
 * End-to-end demo (network-free): manifest validation -> REST adapter ->
 * local HTTP target server -> guarded executor -> hard rules -> StubJudge
 * -> findings, review, redacted reports, checksummed bundle.
 *
 * The actual pipeline lives in `scripts/lib/demo-bundle.ts` and is shared
 * with `scripts/serve-report-ui.ts` — this file is just the CLI presenter.
 *
 * Run: npm run demo   (writes to ./evidence-out/, safe to delete)
 */

import { join } from "node:path";
import { runDemoPipeline } from "./lib/demo-bundle.ts";

async function main(): Promise<void> {
  console.log("== Responsible AI Harness — vertical slice demo ==\n");
  const outDir = join(process.cwd(), "evidence-out");
  const result = await runDemoPipeline({ outDir, log: (line) => { console.log(line); } });
  console.log(result.reportText);
}

await main();
