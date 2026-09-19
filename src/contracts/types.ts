/**
 * Canonical contract types (schema family v1).
 *
 * Every type exported here is the single source of truth for the harness
 * data model. Runtime validators live in `validation.ts`; they validate
 * untrusted input against these shapes and fail closed on malformed data
 * or unsupported schema versions.
 */

/** Supported schema family. Bump on breaking changes; validators reject others. */
export const SCHEMA_VERSION = "1.0" as const;
export type SchemaVersion = "1.0";
/** Schema versions this build understands. Anything else fails validation. */
export const SUPPORTED_SCHEMA_VERSIONS: readonly string[] = ["1.0"];

/* ------------------------------------------------------------------ */
/* Capability manifest                                                 */
/* ------------------------------------------------------------------ */

export type TargetKind = "model" | "agent" | "trace";

export interface CapabilityManifest {
  schemaVersion: SchemaVersion;
  target: {
    id: string;
    kind: TargetKind;
    displayName: string;
    version?: string;
  };
  inputs: {
    text: boolean;
    images?: boolean;
    files?: boolean;
  };
  outputs: {
    text: boolean;
    structuredJson?: boolean;
    toolCalls?: boolean;
  };
  execution: {
    streaming: boolean;
    multiTurn: boolean;
    maxContextTokens?: number;
    timeoutMs: number;
  };
  tools?: {
    name: string;
    description?: string;
    sideEffect: "none" | "reversible" | "irreversible";
  }[];
  dataHandling: {
    mayStoreInputs: boolean;
    mayStoreOutputs: boolean;
    declaredRegions?: string[];
  };
}

/* ------------------------------------------------------------------ */
/* Canonical request / target result                                   */
/* ------------------------------------------------------------------ */

export type ChatRole = "system" | "user" | "assistant" | "tool";

export interface ToolDefinition {
  name: string;
  description?: string;
  parameters?: Record<string, unknown>;
  sideEffect: "none" | "reversible" | "irreversible";
}

export interface CanonicalRequest {
  caseId: string;
  messages: { role: ChatRole; content: unknown }[];
  tools?: ToolDefinition[];
  metadata?: Record<string, string | number | boolean>;
}

export interface RunContext {
  runId: string;
  caseId: string;
  correlationId: string;
  startedAt: string;
  /** Opaque references only — never inline secret values. */
  secretRefs?: Record<string, string>;
}

export type TargetResultStatus = "completed" | "timeout" | "error";

export interface TargetResult {
  status: TargetResultStatus;
  startedAt: string;
  endedAt: string;
  rawArtifactRef: string;
  events: CanonicalEvent[];
  usage?: {
    inputTokens?: number;
    outputTokens?: number;
    costUsd?: number;
  };
  error?: {
    code: string;
    message: string;
    retryable: boolean;
  };
}

/* ------------------------------------------------------------------ */
/* Canonical events                                                    */
/* ------------------------------------------------------------------ */

export type CanonicalEventType =
  | "message.input"
  | "message.output"
  | "tool.call"
  | "tool.result"
  | "policy.decision"
  | "system.error"
  | "metadata.snapshot";

export type EventActor = "user" | "assistant" | "system" | "tool" | "harness";

export interface CanonicalEvent {
  schemaVersion: SchemaVersion;
  eventId: string;
  runId: string;
  sequence: number;
  timestamp: string;
  type: CanonicalEventType;
  actor: EventActor;
  /** Untrusted data. Never evaluated or executed. */
  content: Record<string, unknown>;
  labels?: Record<string, string>;
}

/* ------------------------------------------------------------------ */
/* Rules and judges                                                    */
/* ------------------------------------------------------------------ */

export interface PolicySnapshot {
  policyId: string;
  version: string;
  /** Policy rules as declarative data — never executed. */
  controls: {
    controlId: string;
    description: string;
    /** Regular-expression sources, compiled by the rule engine, not eval'd. */
    pattern?: string;
    flags?: string;
    forbid?: boolean;
  }[];
}

export type RuleOutcome = "pass" | "fail" | "not_applicable" | "error";

export interface RuleResult {
  ruleId: string;
  ruleVersion: string;
  caseId: string;
  outcome: RuleOutcome;
  reasonCode: string;
  evidenceRefs: string[];
  detail?: string;
}

export type JudgeLabel = "pass" | "fail" | "uncertain";

export interface JudgeResult {
  judgeId: string;
  judgeVersion: string;
  caseId: string;
  label: JudgeLabel;
  confidence: number;
  reasonCodes: string[];
  evidenceRefs: string[];
  modelMetadata: Record<string, string | number>;
}

/* ------------------------------------------------------------------ */
/* Findings and review                                                 */
/* ------------------------------------------------------------------ */

export type FindingCategory =
  | "prompt_injection"
  | "secret_pii_leakage"
  | "unsafe_tool_use"
  | "policy_bypass"
  | "harness_error";

export type Severity = "low" | "medium" | "high" | "critical";
export type FindingStatus = "open" | "confirmed" | "dismissed" | "in_review";

export interface Finding {
  findingId: string;
  runId: string;
  caseId: string;
  category: FindingCategory;
  severity: Severity;
  status: FindingStatus;
  /** 0..1. Hard-rule findings carry 1.0; judge findings carry judge confidence. */
  confidence: number;
  affectedControl: string;
  reasonCodes: string[];
  reproductionSteps: string[];
  evidenceRefs: string[];
  /** Which decision layer produced this finding. */
  source: "hard_rule" | "judge" | "both";
}

export type ReviewReason =
  | "low_confidence"
  | "rule_judge_conflict"
  | "sensitive_evidence"
  | "judge_error"
  | "judge_timeout"
  | "ambiguous_case"
  | "release_decision";

export interface ReviewTask {
  reviewId: string;
  findingRef: string;
  reason: ReviewReason;
  createdAt: string;
  status: "pending" | "resolved";
  decision?: {
    resolution: "confirm" | "dismiss";
    decidedBy: string;
    decidedAt: string;
    note?: string;
  };
}

/* ------------------------------------------------------------------ */
/* Evidence bundle manifest                                            */
/* ------------------------------------------------------------------ */

export interface BundleEntry {
  path: string;
  sha256: string;
  bytes: number;
}

export interface EvidenceBundleManifest {
  schemaVersion: SchemaVersion;
  bundleId: string;
  runId: string;
  createdAt: string;
  toolVersions: Record<string, string>;
  harnessVersion: string;
  entries: BundleEntry[];
  redactionState: "redacted" | "raw_separate";
  /** sha256 of the canonical JSON of entries, binding the bundle together. */
  entriesDigest: string;
}

export type JudgeEnvelope = {
  ok: true;
  result: JudgeResult;
} | {
  ok: false;
  /** Judge failures become `uncertain`, never a pass. */
  error: { code: string; message: string; timeout: boolean };
};
