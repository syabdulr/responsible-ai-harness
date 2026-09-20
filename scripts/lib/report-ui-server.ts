/**
 * Testable core of the report-UI dev server: offline data generation, and
 * the live-bundle re-verification/publish gate. `scripts/serve-report-ui.ts`
 * is a thin CLI wrapper around these functions plus the actual HTTP
 * listener — split out so the integrity gate (the security-critical part)
 * can be unit-tested in-process without spawning a real server.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, normalize } from "node:path";
import { runDemoPipeline, DEMO_MANIFEST } from "./demo-bundle.ts";
import { validateCapabilityManifest, parseJson } from "../../src/contracts/validation.ts";
import { validateReport } from "../../src/contracts/report-validation.ts";
import { verifyReportIntegrity } from "../../src/report/build-report.ts";
import { verifyBundle } from "../../src/evidence/bundle.ts";

export const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

export async function generateOfflineData(dataDir: string, outDir: string): Promise<{ runId: string; verified: boolean }> {
  const manifestCheck = validateCapabilityManifest(DEMO_MANIFEST);
  if (!manifestCheck.ok) throw new Error(`demo manifest failed validation: ${manifestCheck.error}`);

  const result = await runDemoPipeline({ outDir });

  mkdirSync(dataDir, { recursive: true });
  writeFileSync(join(dataDir, "report.json"), JSON.stringify(result.report, null, 2));
  writeFileSync(join(dataDir, "bundle-manifest.json"), JSON.stringify(result.manifest, null, 2));
  writeFileSync(join(dataDir, "target-manifest.json"), JSON.stringify(manifestCheck.value, null, 2));
  writeFileSync(join(dataDir, "verify.json"), JSON.stringify({ ok: result.verify.ok, checked: result.verify.checked, failures: result.verify.failures }, null, 2));

  return { runId: result.runId, verified: result.verify.ok };
}

export interface PublishResult {
  available: boolean;
  reason?: string;
}

/**
 * Re-verify a live bundle directory from scratch — checksums AND the
 * embedded report's own integrity hash — and ONLY on a full pass, copy a
 * curated subset into `dataLiveDir`. This function IS the trust decision
 * for the live source; nothing written by the producer of `liveBundleDir`
 * (assess-jev-live.ts) is taken on faith — every check re-reads the files
 * on disk right now.
 */
export async function tryPublishLiveData(liveBundleDir: string, dataLiveDir: string): Promise<PublishResult> {
  if (!existsSync(join(liveBundleDir, "manifest.json"))) {
    return { available: false, reason: "no live run found (bundle directory absent)" };
  }

  const verify = await verifyBundle(liveBundleDir);
  if (!verify.ok) {
    return { available: false, reason: `bundle re-verification failed: ${verify.failures.join("; ")}` };
  }

  let reportRaw: string;
  try {
    reportRaw = readFileSync(join(liveBundleDir, "report.json"), "utf8");
  } catch {
    return { available: false, reason: "report.json unreadable in the live bundle" };
  }
  const parsed = parseJson(reportRaw);
  if (!parsed.ok) return { available: false, reason: `report.json: ${parsed.error}` };
  const reportCheck = validateReport(parsed.value);
  if (!reportCheck.ok) return { available: false, reason: `report.json failed contract validation: ${reportCheck.error}` };
  if (!verifyReportIntegrity(reportCheck.value)) {
    return { available: false, reason: "report.json integrity hash does not match its content" };
  }

  let manifestRaw: string;
  let targetManifestRaw: string | undefined;
  try {
    manifestRaw = readFileSync(join(liveBundleDir, "manifest.json"), "utf8");
  } catch {
    return { available: false, reason: "manifest.json unreadable in the live bundle" };
  }
  try {
    targetManifestRaw = readFileSync(join(liveBundleDir, "target-manifest.json"), "utf8");
  } catch {
    targetManifestRaw = undefined;
  }

  mkdirSync(dataLiveDir, { recursive: true });
  writeFileSync(join(dataLiveDir, "report.json"), reportRaw);
  writeFileSync(join(dataLiveDir, "bundle-manifest.json"), manifestRaw);
  if (targetManifestRaw !== undefined) writeFileSync(join(dataLiveDir, "target-manifest.json"), targetManifestRaw);
  writeFileSync(join(dataLiveDir, "verify.json"), JSON.stringify({ ok: true, checked: verify.checked, failures: [] }, null, 2));
  if (existsSync(join(liveBundleDir, "usage.json"))) {
    writeFileSync(join(dataLiveDir, "usage.json"), readFileSync(join(liveBundleDir, "usage.json")));
  }

  return { available: true };
}

export function writeSourcesManifest(dataDir: string, liveAvailable: boolean): void {
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(
    join(dataDir, "sources.json"),
    JSON.stringify(
      {
        sources: [
          { id: "offline", label: "Offline (StubJudge)", available: true },
          ...(liveAvailable ? [{ id: "live", label: "Live Jev", available: true }] : []),
        ],
      },
      null,
      2,
    ),
  );
}

/**
 * Resolve a request path to a file under `uiDir`, rejecting path
 * traversal. `dataLiveBase` is reported back so the caller can gate it
 * separately (only servable when the live source actually verified).
 */
export function safeResolve(uiDir: string, dataLiveDir: string, urlPath: string): { path: string; isDataLive: boolean } | undefined {
  const decoded = decodeURIComponent(urlPath.split("?")[0] ?? "/");
  const relative = decoded === "/" ? "/index.html" : decoded;
  const target = normalize(join(uiDir, relative));
  if (!target.startsWith(uiDir)) return undefined; // path traversal rejected
  return { path: target, isDataLive: target.startsWith(dataLiveDir) };
}
