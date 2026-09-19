/**
 * Local Jev MCP connector — a Model Context Protocol server exposing
 * exactly one tool: `evaluate_responsible_ai_case`.
 *
 * Design constraints (all enforced structurally, not just by convention):
 * - Exactly one tool is ever registered on the returned `McpServer`. There
 *   are no resources, no prompts, and no other tools — no filesystem
 *   access, no shell execution, no arbitrary HTTP fetch, no environment
 *   dump. The only environment variable this module ever reads is
 *   `TYPESAFE_API_KEY`, and only inside the secret provider closure.
 * - The tool accepts ONLY the closed, versioned assessment schema below
 *   (`EvaluateCaseInputSchema`) — a discriminated union on `category`,
 *   where each branch lists the small, explicit, bounded set of redacted
 *   evidence facts that category's question catalog actually needs (see
 *   `jev-questions.ts`). Every object is `strictObject`-checked at every
 *   nesting level, every string has a length bound, and there are no
 *   arrays, no free-form nested objects, and no field for a prompt, an
 *   endpoint/URL, a raw events array, a provider config, a model
 *   override, or a secretRef. There is no way to redirect the call
 *   anywhere but the one hardcoded Jev transport, and no way to smuggle
 *   an unbounded blob through a field that looks legitimate.
 * - Every actual network call runs through `JevJudge`, so the one-call/
 *   no-retry guarantee, the allowlisted outbound state, the redact-again
 *   pass, the residual-risk gate, and the fixed-public-error-code
 *   sanitization in `jev.ts` / `jev-transport-typesafe.ts` all apply
 *   here unmodified — this connector adds no second code path to any of
 *   that, it only calls the same `JevJudge.score()`.
 * - The tool result contains ONLY the validated `JudgeResult` fields
 *   (label, confidence, reasonCodes, evidenceRefs, modelMetadata) or a
 *   sanitized error `{code, message, timeout}` — never a raw exception,
 *   never the request payload echoed back, never the resolved API key.
 */

import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { JudgeEnvelope } from "../contracts/types.ts";
import { JevJudge } from "../judges/jev.ts";
import type { JevClientFactory, RuntimeSecretProvider } from "../judges/jev.ts";
import { createTypeSafeJevTransport } from "../judges/jev-transport-typesafe.ts";

export const JEV_MCP_CONNECTOR_VERSION = "2.0.0";
export const EVALUATE_TOOL_NAME = "evaluate_responsible_ai_case";
export const JEV_MCP_SECRET_REF = "env:TYPESAFE_API_KEY";
/** Versions the *shape* of EvaluateCaseInputSchema; bump on any field/bound change. */
export const EVALUATE_CASE_SCHEMA_VERSION = "1.0.0";

/** Bounded, fixed per-call timeout for the one TypeSafe call this tool makes. */
export const EVALUATE_TIMEOUT_MS = 15_000;

const CASE_ID_MAX = 200;
/** A redacted excerpt, not a raw blob — bounded so no field can carry an unbounded document. */
const EXCERPT_MAX = 2000;
const TOOL_NAME_MAX = 100;
const RECIPIENT_MAX = 200;

const caseId = z.string().min(1).max(CASE_ID_MAX);
/** A single already-redacted line/paragraph, not free-form nested content. */
const excerpt = () => z.string().min(1).max(EXCERPT_MAX);
const optionalExcerpt = () => z.string().min(1).max(EXCERPT_MAX).optional();

/**
 * Closed, versioned, per-category evidence shapes — the small approved
 * set of redacted facts each category's question catalog (jev-questions.ts)
 * actually needs. No arrays, no nested objects, no open-ended records:
 * every field is a bounded string or a boolean, and `.strict()` rejects
 * anything else at every level.
 */
const PromptInjectionEvidence = z.strictObject({
  /** Redacted excerpt of the untrusted content (retrieved doc, tool output, ...). */
  untrustedContentExcerpt: excerpt(),
  /** Redacted excerpt of what the assistant actually said/did in response. */
  assistantResponseExcerpt: excerpt(),
});

const SecretPiiLeakageEvidence = z.strictObject({
  /** Redacted excerpt of the assistant's visible output. */
  assistantOutputExcerpt: excerpt(),
  /** Redacted excerpt of tool-call arguments, if any tool was called. */
  toolArgumentsExcerpt: optionalExcerpt(),
  /** Redacted excerpt of a tool result, if any tool was called. */
  toolResultExcerpt: optionalExcerpt(),
});

const UnsafeToolUseEvidence = z.strictObject({
  /** The tool's own name (e.g. "message.send"), not a description. */
  toolName: z.string().min(1).max(TOOL_NAME_MAX),
  /** Redacted recipient/account/scope the tool call targeted, if applicable. */
  recipient: z.string().min(1).max(RECIPIENT_MAX).optional(),
  confirmationObtained: z.boolean(),
  authorizationGranted: z.boolean(),
});

const PolicyBypassEvidence = z.strictObject({
  /** Redacted excerpt of the (possibly obfuscated) request. */
  userRequestExcerpt: excerpt(),
  /** Redacted excerpt of the assistant's response. */
  assistantResponseExcerpt: excerpt(),
});

/**
 * The closed, versioned assessment schema — the ONLY shape this tool
 * accepts. A discriminated union on `category`, each branch
 * `.strict()`-checked at every level: no unknown top-level field, no
 * unknown nested field, and no field type this tool doesn't explicitly
 * define (no arrays, no open objects, no unbounded strings).
 */
export const EvaluateCaseInputSchema = z.discriminatedUnion("category", [
  z.strictObject({ caseId, category: z.literal("prompt_injection"), evidence: PromptInjectionEvidence }),
  z.strictObject({ caseId, category: z.literal("secret_pii_leakage"), evidence: SecretPiiLeakageEvidence }),
  z.strictObject({ caseId, category: z.literal("unsafe_tool_use"), evidence: UnsafeToolUseEvidence }),
  z.strictObject({ caseId, category: z.literal("policy_bypass"), evidence: PolicyBypassEvidence }),
]);

export type EvaluateCaseInput = z.infer<typeof EvaluateCaseInputSchema>;

/** Repackages the closed per-category evidence facts into the same allowlisted `{caseId, category, evidence}` shape JevJudge builds internally (see jev.ts). */
function toJevEvidence(input: EvaluateCaseInput): Record<string, unknown> {
  return { ...input.evidence };
}

/** Only these fields ever leave the connector on a successful evaluation. */
export interface EvaluateCaseSuccess {
  ok: true;
  label: string;
  confidence: number;
  reasonCodes: string[];
  evidenceRefs: string[];
  modelMetadata: Record<string, string | number>;
}

/** A sanitized, fixed-code error — never a raw exception (see jev.ts). */
export interface EvaluateCaseFailure {
  ok: false;
  code: string;
  message: string;
  timeout: boolean;
}

export type EvaluateCaseOutput = EvaluateCaseSuccess | EvaluateCaseFailure;

function envelopeToOutput(envelope: JudgeEnvelope): EvaluateCaseOutput {
  if (envelope.ok) {
    const { label, confidence, reasonCodes, evidenceRefs, modelMetadata } = envelope.result;
    return { ok: true, label, confidence, reasonCodes, evidenceRefs, modelMetadata };
  }
  return { ok: false, code: envelope.error.code, message: envelope.error.message, timeout: envelope.error.timeout };
}

/**
 * Core tool logic, independent of the MCP transport — this is what
 * `evaluate_responsible_ai_case` runs, and what tests call directly with
 * a fake `JevJudge` to avoid any network dependency.
 */
export async function evaluateResponsibleAiCase(input: EvaluateCaseInput, jev: JevJudge): Promise<EvaluateCaseOutput> {
  const envelope = await jev.score({ caseId: input.caseId, category: input.category, evidence: toJevEvidence(input), events: [] });
  return envelopeToOutput(envelope);
}

/**
 * Resolves the API key ONLY from `process.env.TYPESAFE_API_KEY`, and only
 * inside this closure — never stored on an object, never logged. This is
 * the one place in the connector process allowed to read an environment
 * variable.
 */
export function createEnvSecretProvider(): RuntimeSecretProvider {
  return {
    resolve(secretRef: string): string | undefined {
      if (secretRef !== JEV_MCP_SECRET_REF) return undefined;
      const value = process.env.TYPESAFE_API_KEY;
      return value !== undefined && value.length > 0 ? value : undefined;
    },
  };
}

export interface CreateJevMcpServerOptions {
  /** Override for tests: inject a fake transport factory instead of the real TypeSafe SDK. */
  clientFactory?: JevClientFactory;
  /** Override for tests: inject a fake secret provider instead of reading TYPESAFE_API_KEY. */
  secretProvider?: RuntimeSecretProvider;
}

/**
 * Build the connector's MCP server. Exactly one tool is registered:
 * `evaluate_responsible_ai_case`. No resources, no prompts, no other
 * tools — this function is the entire attack surface of the connector.
 */
export function createJevMcpServer(options: CreateJevMcpServerOptions = {}): McpServer {
  const secretProvider = options.secretProvider ?? createEnvSecretProvider();
  const clientFactory = options.clientFactory ?? ((apiKey: string) => createTypeSafeJevTransport(apiKey));
  const jev = new JevJudge({ secretRef: JEV_MCP_SECRET_REF, liveMode: true, timeoutMs: EVALUATE_TIMEOUT_MS }, secretProvider, clientFactory);

  const server = new McpServer({ name: "jev-connector", version: JEV_MCP_CONNECTOR_VERSION });

  server.registerTool(
    EVALUATE_TOOL_NAME,
    {
      title: "Evaluate a Responsible AI case with Jev",
      description:
        "Scores one already-redacted assessment case against Jev's atomic Noul question catalog for the given category. " +
        "Makes exactly one bounded, non-retried call to the TypeSafe API and returns only validated probabilities and safe metadata.",
      // The FULL schema (not just `.shape`) is passed so the SDK's own
      // pre-validation enforces `.strict()` and the evidence-size
      // `.superRefine` too — an unrecognized field or oversized evidence
      // is rejected before this handler ever runs, not merely stripped.
      inputSchema: EvaluateCaseInputSchema,
    },
    async (args) => {
      const parsed = EvaluateCaseInputSchema.safeParse(args);
      if (!parsed.success) {
        return {
          isError: true,
          content: [{ type: "text", text: JSON.stringify({ ok: false, code: "jev_mcp_invalid_input", message: "input failed schema validation", timeout: false }) }],
        };
      }
      const result = await evaluateResponsibleAiCase(parsed.data, jev);
      return {
        isError: !result.ok,
        content: [{ type: "text", text: JSON.stringify(result) }],
      };
    },
  );

  return server;
}
