/**
 * Allowlisted Jev evidence mapper — builds evidence FROM already-
 * normalized, already-guarded, already-redacted canonical events, never
 * from an arbitrary prompt and never from the StubJudge's `judge_hint`
 * fixture marker.
 *
 * Output is validated against the exact same closed, bounded zod shapes
 * (`jev-evidence-shapes.ts`) the MCP connector enforces on externally
 * supplied input — this module is just a different producer of the same
 * contract. A case whose events don't contain what its category's
 * question catalog needs throws rather than sending a best-effort guess:
 * fail closed on a mapping gap, never send partial or fabricated evidence.
 *
 * Authorization state is read ONLY from the harness's own
 * `policy.decision` events (actor "harness", source "guarded-executor")
 * — the same trust boundary `hr_irreversible_tool_auth` enforces. A
 * target-supplied tool.result claiming "delivered" is never treated as
 * proof of authorization.
 */

import type { CanonicalEvent, FindingCategory } from "../contracts/types.ts";
import {
  EXCERPT_MAX,
  PolicyBypassEvidence,
  PromptInjectionEvidence,
  SecretPiiLeakageEvidence,
  UnsafeToolUseEvidence,
} from "./jev-evidence-shapes.ts";

export class EvidenceMappingError extends Error {
  constructor(
    public readonly caseId: string,
    public readonly category: FindingCategory,
    message: string,
  ) {
    super(`evidence mapping failed for ${caseId} (${category}): ${message}`);
    this.name = "EvidenceMappingError";
  }
}

function truncate(s: string): string {
  return s.length > EXCERPT_MAX ? s.slice(0, EXCERPT_MAX) : s;
}

function textOf(content: Record<string, unknown>): string | undefined {
  if (typeof content.text === "string") return content.text;
  if (typeof content.output === "string") return content.output;
  return undefined;
}

function findEvent(events: CanonicalEvent[], predicate: (e: CanonicalEvent) => boolean): CanonicalEvent | undefined {
  return events.find(predicate);
}

function mapPromptInjection(caseId: string, events: CanonicalEvent[]): PromptInjectionEvidence {
  const docResult = findEvent(events, (e) => e.type === "tool.result" && e.content.tool_name === "document.read");
  const output = docResult !== undefined ? textOf(docResult.content) : undefined;
  if (output === undefined) {
    throw new EvidenceMappingError(caseId, "prompt_injection", "no document.read tool.result with textual output found");
  }
  const response = findEvent(events, (e) => e.type === "message.output");
  const responseText = response !== undefined ? textOf(response.content) : undefined;
  if (responseText === undefined) {
    throw new EvidenceMappingError(caseId, "prompt_injection", "no message.output event with textual content found");
  }
  return PromptInjectionEvidence.parse({
    untrustedContentExcerpt: truncate(output),
    assistantResponseExcerpt: truncate(responseText),
  });
}

function mapSecretPiiLeakage(caseId: string, events: CanonicalEvent[]): SecretPiiLeakageEvidence {
  const output = findEvent(events, (e) => e.type === "message.output");
  const outputText = output !== undefined ? textOf(output.content) : undefined;
  if (outputText === undefined) {
    throw new EvidenceMappingError(caseId, "secret_pii_leakage", "no message.output event with textual content found");
  }
  const toolCall = findEvent(events, (e) => e.type === "tool.call");
  const toolResult = findEvent(events, (e) => e.type === "tool.result");
  const evidence: Record<string, unknown> = { assistantOutputExcerpt: truncate(outputText) };
  if (toolCall !== undefined) {
    const args = JSON.stringify(toolCall.content.arguments ?? {});
    evidence.toolArgumentsExcerpt = truncate(args);
  }
  if (toolResult !== undefined) {
    const out = textOf(toolResult.content);
    if (out !== undefined) evidence.toolResultExcerpt = truncate(out);
  }
  return SecretPiiLeakageEvidence.parse(evidence);
}

function mapUnsafeToolUse(caseId: string, events: CanonicalEvent[]): UnsafeToolUseEvidence {
  const toolCall = findEvent(events, (e) => e.type === "tool.call");
  if (toolCall === undefined) {
    throw new EvidenceMappingError(caseId, "unsafe_tool_use", "no tool.call event found");
  }
  const toolName = typeof toolCall.content.tool_name === "string" ? toolCall.content.tool_name : undefined;
  if (toolName === undefined) {
    throw new EvidenceMappingError(caseId, "unsafe_tool_use", "tool.call event has no string tool_name");
  }
  const args = (toolCall.content.arguments ?? {}) as Record<string, unknown>;
  const recipientRaw = args.to ?? args.recipient ?? args.target;
  const recipient = typeof recipientRaw === "string" && recipientRaw.length > 0 ? recipientRaw : undefined;

  // Authorization comes ONLY from the harness's own policy.decision event
  // bound to this exact tool.call — never from a target-supplied claim.
  const decision = findEvent(
    events,
    (e) => e.type === "policy.decision" && e.actor === "harness" && e.content.source === "guarded-executor" && e.content.toolCallId === toolCall.eventId,
  );
  const authorizationGranted = decision?.content.authorized === true;

  const evidence: Record<string, unknown> = {
    toolName: truncate(toolName).slice(0, 100),
    confirmationObtained: false,
    authorizationGranted,
  };
  if (recipient !== undefined) evidence.recipient = truncate(recipient).slice(0, 200);
  return UnsafeToolUseEvidence.parse(evidence);
}

function mapPolicyBypass(caseId: string, events: CanonicalEvent[]): PolicyBypassEvidence {
  const output = findEvent(events, (e) => e.type === "message.output");
  if (output === undefined) {
    throw new EvidenceMappingError(caseId, "policy_bypass", "no message.output event found");
  }
  const requestText = typeof output.content.request_text === "string" ? output.content.request_text : undefined;
  const responseText = textOf(output.content);
  if (requestText === undefined || responseText === undefined) {
    throw new EvidenceMappingError(caseId, "policy_bypass", "message.output event is missing request_text or response text");
  }
  return PolicyBypassEvidence.parse({
    userRequestExcerpt: truncate(requestText),
    assistantResponseExcerpt: truncate(responseText),
  });
}

/**
 * Build the fixed, allowlisted evidence object for one case's category
 * from its already-normalized, already-guarded canonical events. The
 * caller is still expected to redact the result again before it crosses
 * the judge boundary (the same "redact, then redact again" discipline
 * `pipeline/assess.ts` and `JevJudge.score` already apply everywhere
 * else) — this function's job is shape and provenance, not redaction.
 */
export function buildJevEvidence(caseId: string, category: FindingCategory, events: CanonicalEvent[]): Record<string, unknown> {
  switch (category) {
    case "prompt_injection":
      return mapPromptInjection(caseId, events);
    case "secret_pii_leakage":
      return mapSecretPiiLeakage(caseId, events);
    case "unsafe_tool_use":
      return mapUnsafeToolUse(caseId, events);
    case "policy_bypass":
      return mapPolicyBypass(caseId, events);
    case "harness_error":
      throw new EvidenceMappingError(caseId, category, "harness_error cases are never scored by Jev (no question catalog entry)");
  }
}
