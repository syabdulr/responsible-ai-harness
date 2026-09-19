import { createHash } from "node:crypto";
import type { CanonicalEvent } from "../contracts/types.ts";

/** Normalize raw target events: assign monotonic sequences, hash content. */
export function normalizeEvents(raw: CanonicalEvent[], runId: string): { events: CanonicalEvent[]; artifact: { sha256: string; bytes: number } } {
  const sorted = [...raw].sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));
  const events = sorted.map((e, i) => ({ ...e, runId, sequence: i + 1 }));
  const serialized = JSON.stringify(events);
  return { events, artifact: { sha256: sha256(serialized), bytes: Buffer.byteLength(serialized) } };
}

export function sha256(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}
