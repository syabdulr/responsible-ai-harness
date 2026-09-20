/**
 * Shared, closed, versioned per-category Jev evidence shapes — the small
 * approved set of redacted facts each category's question catalog
 * (jev-questions.ts) actually needs. No arrays, no nested objects, no
 * open-ended records: every field is a bounded string or a boolean.
 *
 * Two callers share this single definition rather than each declaring
 * their own shape:
 *   - `src/mcp/jev-mcp-connector.ts` validates externally-supplied MCP
 *     tool input against these schemas.
 *   - `src/judges/evidence-mapper.ts` builds evidence FROM already-
 *     normalized, already-redacted canonical events and validates its
 *     own output against the same schemas before it ever reaches a judge.
 * One shape, two producers, both structurally bounded the same way.
 */

import { z } from "zod";

export const CASE_ID_MAX = 200;
/** A redacted excerpt, not a raw blob — bounded so no field can carry an unbounded document. */
export const EXCERPT_MAX = 2000;
export const TOOL_NAME_MAX = 100;
export const RECIPIENT_MAX = 200;

export const caseIdField = z.string().min(1).max(CASE_ID_MAX);
/** A single already-redacted line/paragraph, not free-form nested content. */
export const excerpt = () => z.string().min(1).max(EXCERPT_MAX);
export const optionalExcerpt = () => z.string().min(1).max(EXCERPT_MAX).optional();

export const PromptInjectionEvidence = z.strictObject({
  /** Redacted excerpt of the untrusted content (retrieved doc, tool output, ...). */
  untrustedContentExcerpt: excerpt(),
  /** Redacted excerpt of what the assistant actually said/did in response. */
  assistantResponseExcerpt: excerpt(),
});
export type PromptInjectionEvidence = z.infer<typeof PromptInjectionEvidence>;

export const SecretPiiLeakageEvidence = z.strictObject({
  /** Redacted excerpt of the assistant's visible output. */
  assistantOutputExcerpt: excerpt(),
  /** Redacted excerpt of tool-call arguments, if any tool was called. */
  toolArgumentsExcerpt: optionalExcerpt(),
  /** Redacted excerpt of a tool result, if any tool was called. */
  toolResultExcerpt: optionalExcerpt(),
});
export type SecretPiiLeakageEvidence = z.infer<typeof SecretPiiLeakageEvidence>;

export const UnsafeToolUseEvidence = z.strictObject({
  /** The tool's own name (e.g. "message.send"), not a description. */
  toolName: z.string().min(1).max(TOOL_NAME_MAX),
  /** Redacted recipient/account/scope the tool call targeted, if applicable. */
  recipient: z.string().min(1).max(RECIPIENT_MAX).optional(),
  confirmationObtained: z.boolean(),
  authorizationGranted: z.boolean(),
});
export type UnsafeToolUseEvidence = z.infer<typeof UnsafeToolUseEvidence>;

export const PolicyBypassEvidence = z.strictObject({
  /** Redacted excerpt of the (possibly obfuscated) request — the "policy statement" being tested. */
  userRequestExcerpt: excerpt(),
  /** Redacted excerpt of the assistant's response. */
  assistantResponseExcerpt: excerpt(),
});
export type PolicyBypassEvidence = z.infer<typeof PolicyBypassEvidence>;

/**
 * The closed, versioned assessment schema — a discriminated union on
 * `category`, each branch `.strict()`-checked at every level: no unknown
 * top-level field, no unknown nested field, and no field type this shape
 * doesn't explicitly define (no arrays, no open objects, no unbounded
 * strings).
 */
export const EvaluateCaseInputSchema = z.discriminatedUnion("category", [
  z.strictObject({ caseId: caseIdField, category: z.literal("prompt_injection"), evidence: PromptInjectionEvidence }),
  z.strictObject({ caseId: caseIdField, category: z.literal("secret_pii_leakage"), evidence: SecretPiiLeakageEvidence }),
  z.strictObject({ caseId: caseIdField, category: z.literal("unsafe_tool_use"), evidence: UnsafeToolUseEvidence }),
  z.strictObject({ caseId: caseIdField, category: z.literal("policy_bypass"), evidence: PolicyBypassEvidence }),
]);

export type EvaluateCaseInput = z.infer<typeof EvaluateCaseInputSchema>;
