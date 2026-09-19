/**
 * Runtime validators for untrusted contract payloads.
 *
 * Every validator returns a typed result instead of throwing: malformed
 * data, unknown fields that violate policy, and unsupported schema
 * versions all fail closed as explicit errors. No dynamic evaluation,
 * no remote fetching, no prototype-pollution vector (objects created
 * with null prototype where content is stored as untrusted data).
 */

import {
  SUPPORTED_SCHEMA_VERSIONS,
  type CanonicalEvent,
  type CanonicalEventType,
  type CapabilityManifest,
  type EvidenceBundleManifest,
  type Finding,
  type JudgeResult,
  type ReviewTask,
  type RuleResult,
  type TargetResult,
} from "./types.ts";

export type Valid<T> = { ok: true; value: T } | { ok: false; error: string };

const ok = <T>(value: T): Valid<T> => ({ ok: true, value });
const err = (error: string): Valid<never> => ({ ok: false, error });

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Safe JSON parse — never throws on malformed input. */
export function parseJson(text: string): Valid<unknown> {
  try {
    return ok(JSON.parse(text) as unknown);
  } catch {
    return err(`malformed JSON: unable to parse`);
  }
}

function requireString(v: unknown, field: string): Valid<string> {
  if (typeof v !== "string" || v.length === 0) return err(`${field} must be a non-empty string`);
  return ok(v);
}

function requireSchemaVersion(v: unknown, field: string): Valid<string> {
  const sv = requireString(v, field);
  if (!sv.ok) return sv;
  if (!SUPPORTED_SCHEMA_VERSIONS.includes(sv.value)) {
    return err(`${field}: unsupported schema version "${sv.value}" (supported: ${SUPPORTED_SCHEMA_VERSIONS.join(", ")})`);
  }
  return sv;
}

function requireNumber(v: unknown, field: string, min?: number, max?: number): Valid<number> {
  if (typeof v !== "number" || !Number.isFinite(v)) return err(`${field} must be a finite number`);
  if (min !== undefined && v < min) return err(`${field} must be >= ${min}`);
  if (max !== undefined && v > max) return err(`${field} must be <= ${max}`);
  return ok(v);
}

function requireBoolean(v: unknown, field: string): Valid<boolean> {
  if (typeof v !== "boolean") return err(`${field} must be a boolean`);
  return ok(v);
}

function requireArray(v: unknown, field: string): Valid<unknown[]> {
  if (!Array.isArray(v)) return err(`${field} must be an array`);
  return ok(v);
}

const EVENT_TYPES: readonly CanonicalEventType[] = [
  "message.input",
  "message.output",
  "tool.call",
  "tool.result",
  "policy.decision",
  "system.error",
  "metadata.snapshot",
];

const ACTORS: readonly string[] = ["user", "assistant", "system", "tool", "harness"];

export function validateCapabilityManifest(input: unknown): Valid<CapabilityManifest> {
  if (!isRecord(input)) return err("manifest: not an object");
  const sv = requireSchemaVersion(input.schemaVersion, "manifest.schemaVersion");
  if (!sv.ok) return sv;
  const target = input.target;
  if (!isRecord(target)) return err("manifest.target: not an object");
  const id = requireString(target.id, "manifest.target.id");
  if (!id.ok) return id;
  const displayName = requireString(target.displayName, "manifest.target.displayName");
  if (!displayName.ok) return displayName;
  if (target.kind !== "model" && target.kind !== "agent" && target.kind !== "trace") {
    return err(`manifest.target.kind: must be model|agent|trace, got "${String(target.kind)}"`);
  }
  const inputs = input.inputs;
  if (!isRecord(inputs)) return err("manifest.inputs: not an object");
  const outputs = input.outputs;
  if (!isRecord(outputs)) return err("manifest.outputs: not an object");
  const execution = input.execution;
  if (!isRecord(execution)) return err("manifest.execution: not an object");
  const timeoutMs = requireNumber(execution.timeoutMs, "manifest.execution.timeoutMs", 1);
  if (!timeoutMs.ok) return timeoutMs;
  if (input.tools !== undefined) {
    const tools = requireArray(input.tools, "manifest.tools");
    if (!tools.ok) return tools;
    for (const [i, t] of tools.value.entries()) {
      if (!isRecord(t)) return err(`manifest.tools[${i}]: not an object`);
      const name = requireString(t.name, `manifest.tools[${i}].name`);
      if (!name.ok) return name;
      if (t.sideEffect !== "none" && t.sideEffect !== "reversible" && t.sideEffect !== "irreversible") {
        return err(`manifest.tools[${i}].sideEffect: invalid`);
      }
    }
  }
  const dataHandling = input.dataHandling;
  if (!isRecord(dataHandling)) return err("manifest.dataHandling: not an object");
  const mayStoreInputs = requireBoolean(dataHandling.mayStoreInputs, "manifest.dataHandling.mayStoreInputs");
  if (!mayStoreInputs.ok) return mayStoreInputs;
  return ok(input as unknown as CapabilityManifest);
}

export function validateCanonicalEvent(input: unknown): Valid<CanonicalEvent> {
  if (!isRecord(input)) return err("event: not an object");
  const sv = requireSchemaVersion(input.schemaVersion, "event.schemaVersion");
  if (!sv.ok) return sv;
  const eventId = requireString(input.eventId, "event.eventId");
  if (!eventId.ok) return eventId;
  const runId = requireString(input.runId, "event.runId");
  if (!runId.ok) return runId;
  const seq = requireNumber(input.sequence, "event.sequence", 0);
  if (!seq.ok) return seq;
  const ts = requireString(input.timestamp, "event.timestamp");
  if (!ts.ok) return ts;
  if (!EVENT_TYPES.includes(input.type as CanonicalEventType)) {
    return err(`event.type: unknown event type "${String(input.type)}"`);
  }
  if (!ACTORS.includes(String(input.actor))) {
    return err(`event.actor: unknown actor "${String(input.actor)}"`);
  }
  if (!isRecord(input.content)) return err("event.content: must be an object");
  return ok(input as unknown as CanonicalEvent);
}

export function validateTargetResult(input: unknown): Valid<TargetResult> {
  if (!isRecord(input)) return err("target result: not an object");
  if (input.status !== "completed" && input.status !== "timeout" && input.status !== "error") {
    return err(`target result.status: invalid`);
  }
  const rawArtifactRef = requireString(input.rawArtifactRef, "target result.rawArtifactRef");
  if (!rawArtifactRef.ok) return rawArtifactRef;
  const events = requireArray(input.events, "target result.events");
  if (!events.ok) return events;
  for (const [i, e] of events.value.entries()) {
    const ev = validateCanonicalEvent(e);
    if (!ev.ok) return err(`target result.events[${i}]: ${ev.error}`);
  }
  return ok(input as unknown as TargetResult);
}

export function validateRuleResult(input: unknown): Valid<RuleResult> {
  if (!isRecord(input)) return err("rule result: not an object");
  for (const f of ["ruleId", "ruleVersion", "caseId", "reasonCode"] as const) {
    const s = requireString(input[f], `rule result.${f}`);
    if (!s.ok) return s;
  }
  if (input.outcome !== "pass" && input.outcome !== "fail" && input.outcome !== "not_applicable" && input.outcome !== "error") {
    return err("rule result.outcome: invalid");
  }
  const refs = requireArray(input.evidenceRefs, "rule result.evidenceRefs");
  if (!refs.ok) return refs;
  return ok(input as unknown as RuleResult);
}

export function validateJudgeResult(input: unknown): Valid<JudgeResult> {
  if (!isRecord(input)) return err("judge result: not an object");
  for (const f of ["judgeId", "judgeVersion", "caseId"] as const) {
    const s = requireString(input[f], `judge result.${f}`);
    if (!s.ok) return s;
  }
  if (input.label !== "pass" && input.label !== "fail" && input.label !== "uncertain") {
    return err("judge result.label: invalid");
  }
  const conf = requireNumber(input.confidence, "judge result.confidence", 0, 1);
  if (!conf.ok) return conf;
  return ok(input as unknown as JudgeResult);
}

export function validateFinding(input: unknown): Valid<Finding> {
  if (!isRecord(input)) return err("finding: not an object");
  for (const f of ["findingId", "runId", "caseId", "affectedControl"] as const) {
    const s = requireString(input[f], `finding.${f}`);
    if (!s.ok) return s;
  }
  const CATS = ["prompt_injection", "secret_pii_leakage", "unsafe_tool_use", "policy_bypass", "harness_error"];
  if (!CATS.includes(String(input.category))) return err("finding.category: invalid");
  const SEVS = ["low", "medium", "high", "critical"];
  if (!SEVS.includes(String(input.severity))) return err("finding.severity: invalid");
  const STATS = ["open", "confirmed", "dismissed", "in_review"];
  if (!STATS.includes(String(input.status))) return err("finding.status: invalid");
  if (input.source !== "hard_rule" && input.source !== "judge" && input.source !== "both") {
    return err("finding.source: invalid");
  }
  const conf = requireNumber(input.confidence, "finding.confidence", 0, 1);
  if (!conf.ok) return conf;
  return ok(input as unknown as Finding);
}

export function validateReviewTask(input: unknown): Valid<ReviewTask> {
  if (!isRecord(input)) return err("review task: not an object");
  const reviewId = requireString(input.reviewId, "review task.reviewId");
  if (!reviewId.ok) return reviewId;
  const findingRef = requireString(input.findingRef, "review task.findingRef");
  if (!findingRef.ok) return findingRef;
  const REASONS = ["low_confidence", "rule_judge_conflict", "sensitive_evidence", "judge_error", "judge_timeout", "ambiguous_case", "release_decision"];
  if (!REASONS.includes(String(input.reason))) return err("review task.reason: invalid");
  if (input.status !== "pending" && input.status !== "resolved") return err("review task.status: invalid");
  return ok(input as unknown as ReviewTask);
}

export function validateBundleManifest(input: unknown): Valid<EvidenceBundleManifest> {
  if (!isRecord(input)) return err("bundle manifest: not an object");
  const sv = requireSchemaVersion(input.schemaVersion, "bundle manifest.schemaVersion");
  if (!sv.ok) return sv;
  const bundleId = requireString(input.bundleId, "bundle manifest.bundleId");
  if (!bundleId.ok) return bundleId;
  const entries = requireArray(input.entries, "bundle manifest.entries");
  if (!entries.ok) return entries;
  for (const [i, e] of entries.value.entries()) {
    if (!isRecord(e)) return err(`bundle manifest.entries[${i}]: not an object`);
    const path = requireString(e.path, `bundle manifest.entries[${i}].path`);
    if (!path.ok) return path;
    if (typeof e.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(e.sha256)) {
      return err(`bundle manifest.entries[${i}].sha256: not a sha256 hex digest`);
    }
  }
  return ok(input as unknown as EvidenceBundleManifest);
}

/**
 * Redaction: recursively remove values matching secret/canary patterns.
 * Used before judge calls, logging, and human-readable exports.
 */
const REDACTION_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "credit_card", re: /\b(?:\d[ -]?){13,16}\b/g },
  { name: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: "email", re: /\b[\w.+-]+@[\w-]+\.[\w.]+\b/g },
  { name: "api_key", re: /\b(?:sk-|ghp_|AKIA)[A-Za-z0-9_-]{10,}\b/g },
  { name: "canary", re: /\bCANARY[A-Z0-9_]*\b/g },
];

export function redactString(s: string, applied: string[] = []): string {
  let out = s;
  for (const p of REDACTION_PATTERNS) {
    if (p.re.test(s)) {
      p.re.lastIndex = 0;
      applied.push(p.name);
      out = out.replace(p.re, `[redacted:${p.name}]`);
    }
    p.re.lastIndex = 0;
  }
  return out;
}

/** Redact all string leaves in a JSON-compatible structure. */
export function redactValue(value: unknown, applied: string[] = []): unknown {
  if (typeof value === "string") return redactString(value, applied);
  if (Array.isArray(value)) return value.map((v) => redactValue(v, applied));
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactValue(v, applied);
    return out;
  }
  return value;
}
