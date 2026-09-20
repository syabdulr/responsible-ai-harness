import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

/**
 * These spawn the REAL script as a subprocess with a deliberately missing
 * or wrong gate value. Safe to actually execute: `checkGate()` runs
 * before anything Jev-related is constructed, so a failing gate makes
 * zero network calls and never touches TYPESAFE_API_KEY meaningfully.
 * Never run with a valid confirmation + a real key in this test file.
 */

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const outDir = join(repoRoot, "evidence-out-live-jev");
const CORRECT_CONFIRM = "I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL";

function runScript(overrides: Record<string, string>) {
  rmSync(outDir, { recursive: true, force: true });
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.TYPESAFE_API_KEY;
  delete env.JEV_SMOKE_CONFIRM;
  delete env.JEV_PRICE_PER_1K_INPUT_TOKENS_USD;
  delete env.JEV_PRICE_PER_1K_OUTPUT_TOKENS_USD;
  Object.assign(env, overrides);
  const result = spawnSync("npx", ["tsx", "scripts/assess-jev-live.ts"], {
    cwd: repoRoot,
    env,
    encoding: "utf8",
    timeout: 30_000,
  });
  return result;
}

describe("assess-jev-live.ts — gate refuses before any call, zero network", () => {
  it("refuses with both env vars missing and creates no bundle directory", () => {
    const r = runScript({});
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/Zero calls were made/);
    expect(existsSync(outDir)).toBe(false);
  }, 35_000);

  it("refuses when JEV_SMOKE_CONFIRM is present but not the exact required string", () => {
    const r = runScript({ JEV_SMOKE_CONFIRM: "yes I confirm", TYPESAFE_API_KEY: "fake-not-real" });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/JEV_SMOKE_CONFIRM=I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL/);
    expect(existsSync(outDir)).toBe(false);
  }, 35_000);

  it("refuses when confirmation is exactly correct but TYPESAFE_API_KEY is missing", () => {
    const r = runScript({ JEV_SMOKE_CONFIRM: CORRECT_CONFIRM });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/TYPESAFE_API_KEY is not set/);
    expect(existsSync(outDir)).toBe(false);
  }, 35_000);

  it("refuses when TYPESAFE_API_KEY is an empty string", () => {
    const r = runScript({ JEV_SMOKE_CONFIRM: CORRECT_CONFIRM, TYPESAFE_API_KEY: "" });
    expect(r.status).toBe(1);
    expect(existsSync(outDir)).toBe(false);
  }, 35_000);
});
