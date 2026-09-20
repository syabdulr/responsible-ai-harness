/**
 * Local dev server for the responsive report UI.
 *
 * 1. Runs the SAME demo pipeline `npm run demo` uses (scripts/lib/demo-bundle.ts)
 *    to produce a real, contract-validated report.json + evidence bundle from
 *    the committed fixtures — nothing in the UI is hand-typed sample data.
 * 2. Copies the artifacts the UI needs into ui/data/ (gitignored, regenerated
 *    on every server start): report.json, bundle-manifest.json,
 *    target-manifest.json, verify.json.
 * 3. Serves ONLY the ui/ directory over plain HTTP on 127.0.0.1, with an
 *    explicit allowlisted set of extensions (default deny everything else,
 *    same posture as the REST adapter's host allowlist) — no directory
 *    listing, no path traversal, no access to the rest of the repo.
 *
 * Run: npm run ui   (then open the printed http://127.0.0.1:<port> URL)
 */

import { createServer } from "node:http";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, normalize, resolve } from "node:path";
import { runDemoPipeline, DEMO_MANIFEST } from "./lib/demo-bundle.ts";
import { validateCapabilityManifest } from "../src/contracts/validation.ts";

const PORT = Number(process.env.PORT ?? 4790);
const HOST = "127.0.0.1";

const UI_DIR = resolve(new URL("../ui", import.meta.url).pathname);
const DATA_DIR = join(UI_DIR, "data");

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

async function generateUiData(): Promise<{ runId: string; verified: boolean }> {
  const manifestCheck = validateCapabilityManifest(DEMO_MANIFEST);
  if (!manifestCheck.ok) throw new Error(`demo manifest failed validation: ${manifestCheck.error}`);

  const outDir = join(process.cwd(), "evidence-out");
  const result = await runDemoPipeline({ outDir });

  mkdirSync(DATA_DIR, { recursive: true });
  writeFileSync(join(DATA_DIR, "report.json"), JSON.stringify(result.report, null, 2));
  writeFileSync(join(DATA_DIR, "bundle-manifest.json"), JSON.stringify(result.manifest, null, 2));
  writeFileSync(join(DATA_DIR, "target-manifest.json"), JSON.stringify(manifestCheck.value, null, 2));
  writeFileSync(join(DATA_DIR, "verify.json"), JSON.stringify({ ok: result.verify.ok, checked: result.verify.checked, failures: result.verify.failures }, null, 2));

  return { runId: result.runId, verified: result.verify.ok };
}

function safeResolve(urlPath: string): string | undefined {
  const decoded = decodeURIComponent(urlPath.split("?")[0] ?? "/");
  const relative = decoded === "/" ? "/index.html" : decoded;
  const target = normalize(join(UI_DIR, relative));
  if (!target.startsWith(UI_DIR)) return undefined; // path traversal rejected
  return target;
}

function startServer(): void {
  const server = createServer((req, res) => {
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { "content-type": "text/plain" });
      res.end("method not allowed");
      return;
    }
    const filePath = safeResolve(req.url ?? "/");
    if (filePath === undefined) {
      res.writeHead(400, { "content-type": "text/plain" });
      res.end("bad request");
      return;
    }
    const ext = filePath.slice(filePath.lastIndexOf("."));
    const contentType = CONTENT_TYPES[ext];
    if (contentType === undefined) {
      // Default-deny: only the allowlisted extensions above are servable.
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
      return;
    }
    let body: Buffer;
    try {
      body = readFileSync(filePath);
    } catch {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
      return;
    }
    res.writeHead(200, { "content-type": contentType, "cache-control": "no-store" });
    res.end(req.method === "HEAD" ? undefined : body);
  });

  server.listen(PORT, HOST, () => {
    console.log(`\nResponsible AI Harness — report UI`);
    console.log(`  serving:  ${UI_DIR}`);
    console.log(`  url:      http://${HOST}:${String(PORT)}/\n`);
    console.log(`Press Ctrl+C to stop.`);
  });
}

async function main(): Promise<void> {
  console.log("Generating a fresh demo report through the existing pipeline…");
  const { runId, verified } = await generateUiData();
  console.log(`Report ready: ${runId} (bundle self-verification: ${verified ? "OK" : "FAILED"})`);
  startServer();
}

await main();
