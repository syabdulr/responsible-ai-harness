/**
 * Local dev server for the responsive report UI.
 *
 * 1. Runs the SAME demo pipeline `npm run demo` uses (scripts/lib/demo-bundle.ts)
 *    to produce a real, contract-validated report.json + evidence bundle from
 *    the committed fixtures — nothing in the offline UI is hand-typed sample
 *    data. Written to ui/data/ (offline, always available — this is the
 *    default view).
 * 2. If `evidence-out-live-jev/` exists (produced by the opt-in
 *    `npm run assess:jev-live`), this server is the SOLE trust boundary
 *    that decides whether a "live" source is ever exposed to the browser:
 *    `tryPublishLiveData` (scripts/lib/report-ui-server.ts) re-verifies the
 *    bundle checksums AND the embedded report's own integrity hash from
 *    scratch on every startup — it never trusts a verdict written by
 *    assess-jev-live.ts, only what it re-derives itself from the files on
 *    disk right now. Only on a full pass is a curated subset copied into
 *    ui/data-live/ and listed in ui/data/sources.json; otherwise no live
 *    source is listed and /data-live/* is not servable at all, even if
 *    files happen to exist there from a previous run.
 * 3. Serves ONLY the ui/ directory over plain HTTP on 127.0.0.1, with an
 *    explicit allowlisted set of extensions (default deny everything else,
 *    same posture as the REST adapter's host allowlist) — no directory
 *    listing, no path traversal, no access to the rest of the repo.
 *
 * Run: npm run ui   (then open the printed http://127.0.0.1:<port> URL)
 */

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { CONTENT_TYPES, generateOfflineData, safeResolve, tryPublishLiveData, writeSourcesManifest } from "./lib/report-ui-server.ts";

const PORT = Number(process.env.PORT ?? 4790);
const HOST = "127.0.0.1";

const UI_DIR = resolve(new URL("../ui", import.meta.url).pathname);
const DATA_DIR = join(UI_DIR, "data");
const DATA_LIVE_DIR = join(UI_DIR, "data-live");
const LIVE_BUNDLE_DIR = join(process.cwd(), "evidence-out-live-jev");

function startServer(liveAvailable: boolean): void {
  const server = createServer((req, res) => {
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { "content-type": "text/plain" });
      res.end("method not allowed");
      return;
    }
    const resolved = safeResolve(UI_DIR, DATA_LIVE_DIR, req.url ?? "/");
    if (resolved === undefined) {
      res.writeHead(400, { "content-type": "text/plain" });
      res.end("bad request");
      return;
    }
    // Belt-and-suspenders: even if files physically exist under
    // ui/data-live/, they are only servable when this run's startup
    // re-verification actually passed.
    if (resolved.isDataLive && !liveAvailable) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
      return;
    }
    const ext = resolved.path.slice(resolved.path.lastIndexOf("."));
    const contentType = CONTENT_TYPES[ext];
    if (contentType === undefined) {
      // Default-deny: only the allowlisted extensions above are servable.
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
      return;
    }
    let body: Buffer;
    try {
      body = readFileSync(resolved.path);
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
    console.log(`  url:      http://${HOST}:${String(PORT)}/`);
    console.log(`  sources:  offline (default)${liveAvailable ? ", live (verified)" : ""}\n`);
    console.log(`Press Ctrl+C to stop.`);
  });
}

async function main(): Promise<void> {
  console.log("Generating a fresh offline demo report through the existing pipeline…");
  const { runId, verified } = await generateOfflineData(DATA_DIR, join(process.cwd(), "evidence-out"));
  console.log(`Offline report ready: ${runId} (bundle self-verification: ${verified ? "OK" : "FAILED"})`);

  console.log("Checking for a live Jev bundle (evidence-out-live-jev/)…");
  const live = await tryPublishLiveData(LIVE_BUNDLE_DIR, DATA_LIVE_DIR);
  console.log(live.available ? "Live Jev bundle found and re-verified OK — will be offered in the UI." : `Live Jev source not offered: ${live.reason ?? "unavailable"}.`);

  writeSourcesManifest(DATA_DIR, live.available);
  startServer(live.available);
}

await main();
