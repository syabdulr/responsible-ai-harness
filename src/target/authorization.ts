/**
 * Harness-side authorization authority.
 *
 * Grants are minted ONLY here, keyed to one exact tool call: run, case,
 * tool-call event ID, tool name, canonical arguments digest, recipient,
 * trusted actor, and expiry. The guarded executor accepts a tool call
 * only when a matching grant exists AND the target-supplied
 * policy.decision event agrees. Target-forged events never suffice.
 */

import { createHash, randomUUID } from "node:crypto";
import type { AuthorizationGrant, CanonicalEvent } from "../contracts/types.ts";

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export function digestOf(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function normalizedRecipient(args: Record<string, unknown>): string {
  const to = args.to ?? args.recipient ?? args.target ?? "*";
  if (typeof to === "string") return to.trim().toLowerCase();
  if (typeof to === "number" || typeof to === "boolean") return String(to).toLowerCase();
  return "invalid_recipient";
}

export class AuthorizationAuthority {
  private readonly grants = new Map<string, AuthorizationGrant>();
  private readonly usedGrantIds = new Set<string>();

  constructor(private readonly trustedActor: string, private readonly now: () => Date) {}

  /** Mint a single-use grant for one exact tool call. */
  issue(g: {
    runId: string;
    caseId: string;
    toolCallId: string;
    tool: string;
    arguments_: Record<string, unknown>;
    ttlMs: number;
  }): AuthorizationGrant {
    const grant: AuthorizationGrant = {
      grantId: `grant_${randomUUID()}`,
      runId: g.runId,
      caseId: g.caseId,
      toolCallId: g.toolCallId,
      tool: g.tool,
      argumentsDigest: digestOf(g.arguments_),
      recipient: normalizedRecipient(g.arguments_),
      actor: this.trustedActor,
      expiresAt: new Date(this.now().getTime() + g.ttlMs).toISOString(),
    };
    this.grants.set(grant.grantId, grant);
    return grant;
  }

  /**
   * Verify a tool call against the harness-issued grant AND the
   * target-supplied policy.decision event. Both must match exactly;
   * otherwise not authorized. Single-use: replay consumes nothing
   * because the grantId is bound to one toolCallId.
   */
  verify(opts: {
    runId: string;
    caseId: string;
    tool: string;
    toolCallId: string;
    arguments_: Record<string, unknown>;
    targetDecision: CanonicalEvent | undefined;
  }): { authorized: boolean; reason: string } {
    const d = opts.targetDecision;
    if (d === undefined) return { authorized: false, reason: "no_policy_decision_event" };
    if (d.actor !== "harness") return { authorized: false, reason: "decision_actor_not_harness" };
    if (d.runId !== opts.runId) return { authorized: false, reason: "decision_run_mismatch" };

    const grantId = d.content.grantId;
    if (typeof grantId !== "string") return { authorized: false, reason: "decision_missing_grant_id" };
    const grant = this.grants.get(grantId);
    if (grant === undefined) return { authorized: false, reason: "unknown_grant" };

    if (grant.runId !== opts.runId) return { authorized: false, reason: "grant_run_mismatch" };
    if (grant.caseId !== opts.caseId) return { authorized: false, reason: "grant_case_mismatch" };
    if (grant.toolCallId !== opts.toolCallId) return { authorized: false, reason: "grant_tool_call_mismatch" };
    if (grant.tool !== opts.tool) return { authorized: false, reason: "grant_tool_mismatch" };
    if (grant.argumentsDigest !== digestOf(opts.arguments_)) return { authorized: false, reason: "grant_arguments_mismatch" };
    if (grant.recipient !== normalizedRecipient(opts.arguments_)) return { authorized: false, reason: "grant_recipient_mismatch" };
    if (this.usedGrantIds.has(grant.grantId)) return { authorized: false, reason: "grant_already_used" };
    if (this.now().getTime() > Date.parse(grant.expiresAt)) return { authorized: false, reason: "grant_expired" };

    this.usedGrantIds.add(grant.grantId);
    return { authorized: true, reason: "authorized" };
  }
}
