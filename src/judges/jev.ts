import type { EntryType } from "@typesafe-ai/sdk";
import type { JudgeEnvelope, FindingCategory } from "../contracts/types.ts";
import type { JudgePlugin } from "./stub.ts";
import { CATEGORY_QUESTION_IDS, JEV_QUESTION_CATALOG_VERSION, questionsForCategory } from "./jev-questions.ts";
import { JEV_THRESHOLD_POLICY_VERSION, evaluateThresholdPolicy } from "./jev-threshold-policy.ts";
import { JEV_TRANSPORT_VERSION, JevTransportError } from "./jev-transport.ts";
import type { JevClient } from "./jev-transport.ts";
import { findResidualRiskIndicators, isRecord, redactValue } from "../contracts/validation.ts";

/**
 * Jev judge adapter — LIVE MODE DISABLED BY DEFAULT, FAILS CLOSED.
 *
 * Jev is a structured decision model: it answers versioned, atomic Noul
 * questions (`jev-questions.ts`) with a probability each, never prose.
 * This module maps those probabilities to a `JudgeResult` deterministically
 * (`jev-threshold-policy.ts`) and makes exactly one bounded call per
 * `score()` through an injected `JevClient` (`jev-transport.ts`). It never
 * imports `@typesafe-ai/sdk` itself and never falls back to `StubJudge` —
 * that substitution is the caller's choice (see `scripts/run-demo.ts`).
 *
 * Secret handling: `secretRef` is an opaque name only. The resolved key
 * value is handed straight to `clientFactory` and is never assigned to a
 * field on this class, never logged, never included in `JevConfig`,
 * `JudgeResult`, evidence, reports, prompts, fixtures, or test code, and is
 * never read from or written to this repository. It necessarily exists in
 * process memory for the duration of the SDK call — that is unavoidable
 * for any in-process SDK — but nothing in this codebase reads, prints, or
 * persists it outside that call.
 *
 * Outbound data boundary: the pipeline already redacts evidence before
 * calling any judge (see `pipeline/assess.ts`), but this is the last line
 * before data leaves the process, so `score()` redacts again and then
 * runs a second, paranoid `findResidualRiskIndicators` pass — defense in
 * depth, not a guarantee (see `validation.ts`'s doc comment on both).
 * A live call is refused (fails closed to `uncertain`) if anything
 * high-risk survives. The wire payload is also an allowlisted, fixed
 * shape (`{category, caseId, evidence}`) rather than a free-form dump of
 * `input.events` — only whatever the caller explicitly put in `evidence`
 * is ever sent.
 */

export interface JevConfig {
  /** Opaque reference only. Never a key value. */
  secretRef: string;
  /** Live mode must be explicitly enabled at runtime. Default: false. */
  liveMode: boolean;
  /** Per-attempt timeout in milliseconds for the single bounded call. */
  timeoutMs: number;
  /** Model override; omitted lets the transport use the SDK default (`jev-latest`). */
  model?: string;
}

export interface RuntimeSecretProvider {
  /** Returns undefined when the referenced secret is unavailable. */
  resolve(secretRef: string): string | undefined;
}

/** Builds a `JevClient` from a resolved API key. Never called unless live mode is on and a secret resolved. */
export type JevClientFactory = (apiKey: string) => JevClient;

export class JevJudge implements JudgePlugin {
  readonly id = "jev";
  readonly version = "2.0.0";
  constructor(
    private readonly config: JevConfig,
    private readonly secretProvider: RuntimeSecretProvider | undefined,
    private readonly clientFactory: JevClientFactory | undefined,
  ) {}

  /** Truthful mode label for logging/UI only (see `JudgePlugin.mode`) — never consulted by scoring. */
  get mode(): "live" | "offline" {
    return this.config.liveMode ? "live" : "offline";
  }

  async score(input: { caseId: string; events: unknown[]; category: string; evidence: unknown }): Promise<JudgeEnvelope> {
    if (!this.config.liveMode) {
      return { ok: false, error: { code: "jev_live_mode_disabled", message: `Jev live mode disabled; case ${input.caseId} not scored (no network calls)`, timeout: false } };
    }
    const apiKey = this.secretProvider?.resolve(this.config.secretRef);
    if (apiKey === undefined) {
      return { ok: false, error: { code: "jev_secret_unavailable", message: "runtime secret provider did not resolve the opaque reference — failing closed", timeout: false } };
    }
    if (this.clientFactory === undefined) {
      return { ok: false, error: { code: "jev_transport_unavailable", message: "live mode is on but no client factory was injected — failing closed", timeout: false } };
    }

    const category = input.category as FindingCategory;
    const questionIds: readonly string[] = CATEGORY_QUESTION_IDS[category] ?? [];
    if (questionIds.length === 0) {
      return { ok: false, error: { code: "jev_no_questions_for_category", message: `no Jev question catalog entry for category "${input.category}"`, timeout: false } };
    }

    let client: JevClient;
    try {
      client = this.clientFactory(apiKey);
    } catch {
      return { ok: false, error: { code: "jev_client_construction_failed", message: "failed to construct the Jev transport client", timeout: false } };
    }

    // Allowlisted, fixed-shape payload — never a free-form dump of
    // input.events. `evidence` is whatever the caller curated; wrap
    // non-record evidence so the wire shape stays a fixed record either way.
    const evidenceRecord: Record<string, unknown> = isRecord(input.evidence) ? input.evidence : { value: input.evidence };
    const allowlistedState = { category, caseId: input.caseId, evidence: evidenceRecord };
    // Redact again (defense in depth) and refuse to send if anything
    // high-risk still survives — see the class doc comment.
    const redactedState = redactValue(allowlistedState) as typeof allowlistedState;
    const residual = findResidualRiskIndicators(redactedState);
    if (residual.length > 0) {
      return { ok: false, error: { code: "jev_residual_risk_detected", message: "redacted evidence still matches high-risk patterns; refusing to send to Jev", timeout: false } };
    }
    const state = redactedState as unknown as EntryType;

    let transportResult;
    try {
      transportResult = await client.systemOne(
        { state, questions: questionsForCategory(category), ...(this.config.model !== undefined ? { model: this.config.model } : {}) },
        { timeoutMs: this.config.timeoutMs },
      );
    } catch (error) {
      if (error instanceof JevTransportError) {
        return { ok: false, error: { code: error.code, message: error.message, timeout: error.timeout } };
      }
      return { ok: false, error: { code: "jev_transport_unknown_error", message: "the Jev transport failed in an unrecognized way", timeout: false } };
    }

    const verdict = evaluateThresholdPolicy(transportResult.answers, questionIds);
    if (verdict.kind === "malformed") {
      return { ok: false, error: { code: verdict.code, message: verdict.message, timeout: false } };
    }

    const modelMetadata: Record<string, string | number> = {
      jev_question_catalog_version: JEV_QUESTION_CATALOG_VERSION,
      jev_threshold_policy_version: JEV_THRESHOLD_POLICY_VERSION,
      jev_transport_version: JEV_TRANSPORT_VERSION,
      jev_model: transportResult.model,
      jev_usage_input_tokens: transportResult.usage.inputTokens,
      jev_usage_output_tokens: transportResult.usage.outputTokens,
      jev_latency_ms: transportResult.latencyMs,
      jev_aggregate_violation_probability: verdict.aggregateProbability,
    };
    for (const pq of verdict.perQuestion) {
      modelMetadata[`jev_q_${pq.questionId}_probability`] = pq.probability;
    }

    return {
      ok: true,
      result: {
        judgeId: this.id,
        judgeVersion: this.version,
        caseId: input.caseId,
        label: verdict.label,
        confidence: verdict.confidence,
        reasonCodes: verdict.reasonCodes,
        evidenceRefs: [`${input.caseId}/judged`, ...verdict.perQuestion.map((pq) => `${input.caseId}/jev/${pq.questionId}`)],
        modelMetadata,
      },
    };
  }
}
