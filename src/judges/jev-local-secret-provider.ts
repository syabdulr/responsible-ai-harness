/**
 * Local (developer-machine) Jev API key resolution for `assess-jev-live.ts`.
 *
 * Precedence, checked in this order, first hit wins:
 *   1. `TYPESAFE_API_KEY` env var, if explicitly set and non-empty — this
 *      keeps CI and non-macOS machines working exactly as before, with no
 *      Keychain dependency at all.
 *   2. On macOS only: the macOS Keychain, service `responsible-ai-harness-jev`,
 *      account equal to the current OS username (`os.userInfo().username`).
 *      Read via the system `security` CLI's `find-generic-password -w`,
 *      which prints the stored secret to its own stdout; this module
 *      captures that output in memory and returns it, and never writes it
 *      anywhere else.
 *
 * If neither source resolves, `resolve()` returns `undefined` — the caller
 * (`assess-jev-live.ts`'s gate, and `JevJudge.score()` itself) both already
 * fail closed on that, so no live call is ever attempted without a key.
 *
 * This module never logs, prints, or persists the resolved value. It is
 * held only in a local variable for the duration of one `resolve()` call
 * and handed straight back to the caller (which itself only forwards it
 * into the SDK client constructor — see `jev.ts` / `jev-transport-typesafe.ts`).
 *
 * Setting up or rotating the stored Keychain value is done by
 * `scripts/jev-secret.ts` (`npm run jev:secret:set` / `:remove` / `:status`),
 * which never reads the key into its own process either — it shells out to
 * `security add-generic-password ... -w` with `-w` as the LAST argument and
 * no value, which makes `security` itself prompt on the terminal and store
 * the typed value directly. That script's process never receives the key.
 */

import { spawnSync } from "node:child_process";
import { userInfo } from "node:os";
import type { RuntimeSecretProvider } from "./jev.ts";

/** Opaque reference only — never a key value (same convention as `JEV_MCP_SECRET_REF`). */
export const JEV_LOCAL_SECRET_REF = "local:jev-live-key";

export const JEV_KEYCHAIN_SERVICE = "responsible-ai-harness-jev";

/** Injectable for tests — never exercises a real Keychain or spawns a real process when overridden. */
export type KeychainReader = (service: string, account: string) => string | undefined;

/**
 * Real macOS Keychain reader. Returns `undefined` (never throws) on any
 * non-macOS platform, a missing item, or any CLI failure — all of which
 * fail closed to "no secret available", never to a fabricated value.
 */
export function readMacKeychain(service: string, account: string): string | undefined {
  if (process.platform !== "darwin") return undefined;
  let result;
  try {
    result = spawnSync("security", ["find-generic-password", "-a", account, "-s", service, "-w"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return undefined;
  }
  if (result.status !== 0) return undefined;
  const value = result.stdout.replace(/\r?\n+$/, "");
  return value.length > 0 ? value : undefined;
}

export interface LocalSecretProviderOptions {
  /** Override for tests: replaces the real macOS Keychain lookup. Zero network/process spawn when supplied. */
  keychainReader?: KeychainReader;
  /** Override for tests: replaces `process.env`. */
  env?: NodeJS.ProcessEnv;
}

/**
 * Builds the `RuntimeSecretProvider` for `assess-jev-live.ts`: env var
 * first, macOS Keychain fallback. Only resolves for `JEV_LOCAL_SECRET_REF`
 * — any other ref returns `undefined`, matching `createEnvSecretProvider`'s
 * convention in the MCP connector.
 */
export function createLocalSecretProvider(options: LocalSecretProviderOptions = {}): RuntimeSecretProvider {
  const keychainReader = options.keychainReader ?? readMacKeychain;
  const env = options.env ?? process.env;
  return {
    resolve(secretRef: string): string | undefined {
      if (secretRef !== JEV_LOCAL_SECRET_REF) return undefined;
      const envValue = env.TYPESAFE_API_KEY;
      if (envValue !== undefined && envValue.length > 0) return envValue;
      // Test/CI escape hatch only: makes gate behavior deterministic and
      // independent of whatever happens to be stored in this machine's
      // real Keychain. Never bypasses the confirmation gate or fabricates
      // a key — it only ever removes a secret *source*.
      if (env.JEV_SKIP_KEYCHAIN === "1") return undefined;
      return keychainReader(JEV_KEYCHAIN_SERVICE, userInfo().username);
    },
  };
}
