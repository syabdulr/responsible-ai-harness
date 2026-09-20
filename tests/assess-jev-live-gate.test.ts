import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * These spawn the REAL script as a subprocess with a deliberately missing
 * or wrong gate value. Safe to actually execute: `checkGate()` runs
 * before anything Jev-related is constructed, so a failing gate makes
 * zero network calls and never touches TYPESAFE_API_KEY meaningfully.
 * Never run with a valid confirmation + a real key in this test file.
 *
 * IMPORTANT: each spawn runs with `cwd` set to a fresh temp directory, not
 * the real repo root. `assess-jev-live.ts` writes to
 * `join(process.cwd(), "evidence-out-live-jev")`, so this keeps every
 * created/deleted bundle directory confined to the temp dir. An earlier
 * version of this file used the real repo root as `cwd` and `rmSync`'d the
 * real `evidence-out-live-jev/` before every spawn — which silently
 * destroyed a genuine, previously-verified live bundle the very first time
 * `npm test` ran after one existed. Never repeat that: always use a scratch
 * `cwd`, never the repo root, for anything that writes to or deletes
 * `evidence-out-live-jev/`.
 */

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const scriptPath = join(repoRoot, "scripts", "assess-jev-live.ts");
const CORRECT_CONFIRM = "I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL";

function runScript(overrides: Record<string, string>) {
  const scratchCwd = mkdtempSync(join(tmpdir(), "rai-gate-test-"));
  const outDir = join(scratchCwd, "evidence-out-live-jev");
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.TYPESAFE_API_KEY;
  delete env.JEV_SMOKE_CONFIRM;
  delete env.JEV_PRICE_PER_1K_INPUT_TOKENS_USD;
  delete env.JEV_PRICE_PER_1K_OUTPUT_TOKENS_USD;
  // Deterministic regardless of what (if anything) is stored in this
  // machine's real macOS Keychain: these gate tests assert "no key
  // resolves", which must not depend on developer machine state.
  env.JEV_SKIP_KEYCHAIN = "1";
  Object.assign(env, overrides);
  const result = spawnSync("npx", ["tsx", scriptPath], {
    cwd: scratchCwd,
    env,
    encoding: "utf8",
    timeout: 30_000,
  });
  return { result, outDir };
}

describe("assess-jev-live.ts — gate refuses before any call, zero network", () => {
  it("refuses with both env vars missing and creates no bundle directory", () => {
    const { result: r, outDir } = runScript({});
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/Zero calls were made/);
    expect(existsSync(outDir)).toBe(false);
  }, 35_000);

  it("refuses when JEV_SMOKE_CONFIRM is present but not the exact required string", () => {
    const { result: r, outDir } = runScript({ JEV_SMOKE_CONFIRM: "yes I confirm", TYPESAFE_API_KEY: "fake-not-real" });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/JEV_SMOKE_CONFIRM=I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL/);
    expect(existsSync(outDir)).toBe(false);
  }, 35_000);

  it("refuses when confirmation is exactly correct but no key resolves (env unset, Keychain skipped)", () => {
    const { result: r, outDir } = runScript({ JEV_SMOKE_CONFIRM: CORRECT_CONFIRM });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/no Jev API key available/);
    expect(r.stderr).toMatch(/jev:secret:set/);
    expect(existsSync(outDir)).toBe(false);
  }, 35_000);

  it("refuses when TYPESAFE_API_KEY is an empty string and Keychain is skipped", () => {
    const { result: r, outDir } = runScript({ JEV_SMOKE_CONFIRM: CORRECT_CONFIRM, TYPESAFE_API_KEY: "" });
    expect(r.status).toBe(1);
    expect(existsSync(outDir)).toBe(false);
  }, 35_000);

  it("still refuses (fails closed) even if JEV_SKIP_KEYCHAIN is unset, as long as TYPESAFE_API_KEY is absent and this test machine has no real Keychain entry for this service", () => {
    // Explicitly re-enables the real Keychain lookup path (does not set
    // JEV_SKIP_KEYCHAIN) to prove the gate still fails closed rather than
    // silently passing through some other channel. This assumes the CI/dev
    // machine has never run `npm run jev:secret:set`; it makes zero network
    // calls either way, since checkGate() exits before any client is built.
    const scratchCwd = mkdtempSync(join(tmpdir(), "rai-gate-test-"));
    const outDir = join(scratchCwd, "evidence-out-live-jev");
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.TYPESAFE_API_KEY;
    delete env.JEV_SKIP_KEYCHAIN;
    env.JEV_SMOKE_CONFIRM = CORRECT_CONFIRM;
    const r = spawnSync("npx", ["tsx", scriptPath], { cwd: scratchCwd, env, encoding: "utf8", timeout: 30_000 });
    if (r.status === 0) {
      throw new Error(
        "This test machine has a real key stored in macOS Keychain for service responsible-ai-harness-jev — " +
        "refusing to treat that as a test failure, but this test cannot safely assert fail-closed behavior here. " +
        "Run `npm run jev:secret:remove` or re-run with this test skipped.",
      );
    }
    expect(r.status).toBe(1);
    expect(existsSync(outDir)).toBe(false);
  }, 35_000);
});
