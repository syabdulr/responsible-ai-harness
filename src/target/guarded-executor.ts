/**
 * Guarded execution boundary (sandbox isolation for test runs).
 *
 * The raw target only emits tool-call INTENTS. This executor decides
 * whether an irreversible tool actually runs: authorization comes ONLY
 * from harness-issued grants verified by AuthorizationAuthority. Every
 * target-supplied policy.decision event is stripped unconditionally —
 * regardless of claimed actor or provenance — and the executor emits
 * its OWN harness-authored policy.decision evidence on both the allow
 * and block paths, derived from the grant-verification result.
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
      // STRIP every target-supplied policy.decision event, regardless of
      // any claimed actor or provenance. The executor re-derives all
      // authorization evidence itself from harness grants below; only its
      // own events are authoritative.
      if (e.type === "policy.decision") continue;

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

      // Authorization consults ONLY the harness authority (grants keyed
      // to this exact toolCallId). Target claims are not an input.
      const verdict = authority.verify({
        runId: ctx.runId,
        caseId: ctx.caseId,
        tool,
        toolCallId: e.eventId,
        arguments_: args,
      });

      // Harness-authored authorization evidence on BOTH paths, emitted
      // BEFORE the call it authorizes (the decision precedes the act).
      events.push(
        harnessEvent(e, "policy.decision", {
          authorized: verdict.authorized,
          source: "guarded-executor",
          tool,
          toolCallId: e.eventId,
          ...(verdict.authorized
            ? { grantId: verdict.grantId, reason: "authorized" }
            : { reason: `blocked:${verdict.reason}` }),
        }),
      );
      events.push(e);

      if (!verdict.authorized) {
        events.push(
          harnessEvent(e, "tool.result", { tool_name: tool, output: "blocked_by_harness", blocked: true }),
        );
        blocked.push({ tool, to: typeof args.to === "string" ? args.to : "unknown", reason: verdict.reason });
        continue;
      }

      // Authorized: the sink is the proof surface (fake delivery only).
      opts.sink.deliveries.push({ to: typeof args.to === "string" ? args.to : "unknown", body: typeof args.body === "string" ? args.body : "", at: opts.now().toISOString() });
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
