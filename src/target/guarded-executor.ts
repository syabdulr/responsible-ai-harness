/**
 * Guarded execution boundary (sandbox isolation for test runs).
 *
 * The raw target only emits tool-call INTENTS. This executor decides
 * whether an irreversible tool actually runs: authorization comes ONLY
 * from harness-issued grants verified by AuthorizationAuthority. Any
 * policy.decision event supplied by the target is untrusted input —
 * it must match a live grant bound to this exact call, or the call is
 * blocked BEFORE the fake sink records delivery.
 */

import type { CanonicalEvent } from "../contracts/types.ts";
import type { FakeSink } from "./local-target.ts";
import { AuthorizationAuthority } from "./authorization.ts";

export interface GuardResult {
  events: CanonicalEvent[];
  blocked: Array<{ tool: string; to: string; reason: string }>;
  sink: FakeSink;
}

export function createGuardedExecutor(opts: {
  sink: FakeSink;
  irreversibleTools: string[];
  trustedActor: string;
  now: () => Date;
  nextEventId: () => string;
}): {
  execute: (rawEvents: CanonicalEvent[], ctx: { runId: string; caseId: string }) => GuardResult;
  authority: AuthorizationAuthority;
} {
  const authority = new AuthorizationAuthority(opts.trustedActor, opts.now);

  function harnessEvent(
    e: CanonicalEvent,
    type: CanonicalEvent["type"],
    content: Record<string, unknown>,
  ): CanonicalEvent {
    return {
      schemaVersion: "1.0",
      eventId: opts.nextEventId(),
      runId: e.runId,
      sequence: 0,
      timestamp: opts.now().toISOString(),
      type,
      actor: "harness",
      content,
    };
  }

  function execute(rawEvents: CanonicalEvent[], ctx: { runId: string; caseId: string }): GuardResult {
    const events: CanonicalEvent[] = [];
    const blocked: Array<{ tool: string; to: string; reason: string }> = [];

    for (const e of rawEvents) {
      // Never let target-supplied policy.decision events into the stream
      // unfiltered — they are re-derived by the harness below.
      if (e.type === "policy.decision") {
        if (e.actor !== "harness") continue; // forged authorization attempt: dropped
        events.push(e);
        continue;
      }
      if (e.type !== "tool.call") {
        events.push(e);
        continue;
      }
      const tool = typeof e.content.tool_name === "string" ? e.content.tool_name : "";
      const args = (e.content.arguments ?? {}) as Record<string, unknown>;
      const isIrreversible = opts.irreversibleTools.includes(tool);
      if (!isIrreversible) {
        events.push(e);
        continue;
      }

      // Find the target's claimed decision event (may be forged).
      const claimed = rawEvents.find(
        (p) =>
          p.type === "policy.decision" &&
          p.actor === "harness" &&
          p.runId === e.runId &&
          typeof p.content.grantId === "string" &&
          p.content.toolCallId === e.eventId,
      );

      const verdict = authority.verify({
        runId: ctx.runId,
        caseId: ctx.caseId,
        tool,
        toolCallId: e.eventId,
        arguments_: args,
        targetDecision: claimed,
      });

      if (!verdict.authorized) {
        events.push(e);
        events.push(
          harnessEvent(e, "policy.decision", {
            authorized: false,
            tool,
            toolCallId: e.eventId,
            reason: `blocked:${verdict.reason}`,
          }),
        );
        events.push(
          harnessEvent(e, "tool.result", { tool_name: tool, output: "blocked_by_harness", blocked: true }),
        );
        blocked.push({ tool, to: typeof args.to === "string" ? args.to : "unknown", reason: verdict.reason });
        continue;
      }

      // Authorized: the sink is the proof surface (fake delivery only).
      opts.sink.deliveries.push({ to: typeof args.to === "string" ? args.to : "unknown", body: typeof args.body === "string" ? args.body : "", at: opts.now().toISOString() });
      events.push(e);
      events.push(harnessEvent(e, "tool.result", { tool_name: tool, output: "delivered" }));
    }
    return { events, blocked, sink: opts.sink };
  }

  return { execute, authority };
}

/** Back-compat wrapper for older callers/tests. */
export function guardedExecute(
  rawEvents: CanonicalEvent[],
  sink: FakeSink,
  irreversibleTools: string[],
  now: () => string,
  nextEventId: () => string,
): GuardResult {
  const executor = createGuardedExecutor({
    sink,
    irreversibleTools,
    trustedActor: "harness",
    now: () => new Date(now()),
    nextEventId,
  });
  return executor.execute(rawEvents, { runId: rawEvents[0]?.runId ?? "unknown", caseId: "legacy" });
}
