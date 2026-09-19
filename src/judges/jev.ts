import { createHash } from "node:crypto";
import type { JudgeEnvelope } from "../contracts/types.ts";
import type { JudgePlugin } from "./stub.ts";

/**
 * Jev judge adapter — LIVE MODE DISABLED BY DEFAULT, FAILS CLOSED.
 *
 * - No key is ever requested, read, printed, stored, or committed here.
 * - The adapter holds only an opaque `secretRef` string naming a runtime
 *   secret provider entry; resolution happens outside this module.
 * - When live mode is off (default) or the provider is unavailable, the
 *   adapter returns an error envelope, which the pipeline converts to
 *   `uncertain` — never a pass.
 */

export interface JevConfig {
  /** Opaque reference only. Never a key value. */
  secretRef: string;
  modelId: string;
  endpointUrl: string;
  /** Live mode must be explicitly enabled at runtime. Default: false. */
  liveMode: boolean;
}

export interface RuntimeSecretProvider {
  /** Returns undefined when the referenced secret is unavailable. */
  resolve(secretRef: string): string | undefined;
}

export class JevJudge implements JudgePlugin {
  readonly id = "jev";
  readonly version = "1.0.0";
  constructor(
    private readonly config: JevConfig,
    private readonly secretProvider: RuntimeSecretProvider | undefined,
  ) {}

  async score(input: { caseId: string; events: unknown[]; category: string; evidence: unknown }): Promise<JudgeEnvelope> {
    if (!this.config.liveMode) {
      return { ok: false, error: { code: "jev_live_mode_disabled", message: `Jev live mode disabled; case ${input.caseId} not scored (no network calls)`, timeout: false } };
    }
    const key = this.secretProvider?.resolve(this.config.secretRef);
    if (key === undefined) {
      return { ok: false, error: { code: "jev_secret_unavailable", message: "runtime secret provider did not resolve the opaque reference — failing closed", timeout: false } };
    }
    // Live call deliberately not implemented in this slice: any future
    // implementation must keep prompts versioned and evidence redacted.
    return { ok: false, error: { code: "jev_not_implemented", message: "live Jev scoring is reserved for a later milestone", timeout: false } };
  }
}

/** Deterministic content hashing shared by evidence and lineage. */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}
