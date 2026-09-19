import type { CanonicalEvent } from "../contracts/types.ts";
import type { FakeSink } from "./local-target.ts";

/**
 * Guarded execution boundary (sandbox isolation for test runs).
 *
 * The raw target only emits tool-call INTENTS. This executor decides
 * whether an irreversible tool actually runs: without a prior
 * policy.decision authorization event the call is blocked BEFORE the
 * fake sink records delivery. Assessment findings are unaffected —
 * the attempt still fails the hard rule.
 */

export interface GuardResult {
  events: CanonicalEvent[];
  blocked: { tool: string; to: string }[];
  sink: FakeSink;
}

export function guardedExecute(
  rawEvents: CanonicalEvent[],
  sink: FakeSink,
  irreversibleTools: string[],
  now: () => string,
  nextEventId: () => string,
): GuardResult {
  const events: CanonicalEvent[] = [];
  const blocked: { tool: string; to: string }[] = [];

  for (const e of rawEvents) {
    if (e.type === "tool.call") {
      const tool = typeof e.content.tool_name === "string" ? e.content.tool_name : "";
      const args = (e.content.arguments ?? {}) as Record<string, unknown>;
      if (irreversibleTools.includes(tool)) {
        const authorized = events.some(
          (p) => p.type === "policy.decision" && p.content.authorized === true && p.content.tool === tool,
        );
        events.push(e);
        if (!authorized) {
          events.push({
            schemaVersion: "1.0",
            eventId: nextEventId(),
            runId: e.runId,
            sequence: 0,
            timestamp: now(),
            type: "policy.decision",
            actor: "harness",
            content: { authorized: false, tool, reason: "no_prior_authorization", blocked: true },
          });
          events.push({
            schemaVersion: "1.0",
            eventId: nextEventId(),
            runId: e.runId,
            sequence: 0,
            timestamp: now(),
            type: "tool.result",
            actor: "harness",
            content: { tool_name: tool, output: "blocked_by_harness", blocked: true },
          });
          blocked.push({ tool, to: typeof args.to === "string" ? args.to : "unknown" });
          continue;
        }
        sink.deliveries.push({ to: typeof args.to === "string" ? args.to : "unknown", body: typeof args.body === "string" ? args.body : "", at: now() });
        events.push({
          schemaVersion: "1.0",
          eventId: nextEventId(),
          runId: e.runId,
          sequence: 0,
          timestamp: now(),
          type: "tool.result",
          actor: "harness",
          content: { tool_name: tool, output: "delivered" },
        });
        continue;
      }
      events.push(e);
      continue;
    }
    if (e.type === "tool.result" && e.actor === "tool") {
      // Results for irreversible tools are synthesized by the guard above;
      // drop the target's own (it never really executed).
      const tool = typeof e.content.tool_name === "string" ? e.content.tool_name : "";
      if (irreversibleTools.includes(tool)) continue;
    }
    events.push(e);
  }
  return { events, blocked, sink };
}
