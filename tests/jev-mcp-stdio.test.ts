/**
 * Spawns the REAL `mcp-jev-connector-serve.ts` entrypoint as a child
 * process over stdio (the same one `npm run mcp:jev` and
 * `smoke-jev-mcp.ts` use) and connects a real MCP `Client` to it. This is
 * the one piece of stdio plumbing `tests/jev-mcp-connector.test.ts` can't
 * cover with its in-process linked-transport pair.
 *
 * This test deliberately stops at `tools/list` and never calls the tool
 * — the running server always has `liveMode: true` with no test hook to
 * inject a fake transport, so actually invoking `evaluate_responsible_ai_case`
 * here would either attempt a real network call (if a real
 * TYPESAFE_API_KEY were present) or fail closed on a missing secret
 * (harmless, but proves nothing new). Listing tools is enough to prove
 * the real stdio server process boots, speaks the MCP protocol
 * correctly, and exposes exactly one tool — with zero network calls
 * either way. The live end-to-end tool call is `smoke-jev-mcp.ts`'s job,
 * and it is opt-in and never run automatically.
 */

import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { EVALUATE_TOOL_NAME } from "../src/mcp/jev-mcp-connector.ts";

const TSX_BIN = join(process.cwd(), "node_modules", ".bin", "tsx");
const SERVER_SCRIPT = join(process.cwd(), "scripts", "mcp-jev-connector-serve.ts");

describe("mcp-jev-connector-serve.ts — real stdio server process, zero network", () => {
  it("boots and exposes exactly one tool over a real spawned stdio transport", async () => {
    expect(existsSync(TSX_BIN)).toBe(true);
    expect(existsSync(SERVER_SCRIPT)).toBe(true);

    // Deliberately no TYPESAFE_API_KEY in the child's environment — this
    // test never calls the tool, so the key is irrelevant here, and
    // getDefaultEnvironment() already excludes it unless we add it back.
    const transport = new StdioClientTransport({ command: TSX_BIN, args: [SERVER_SCRIPT], env: getDefaultEnvironment() });
    const client = new Client({ name: "stdio-boot-test", version: "0.0.0" });
    try {
      await client.connect(transport);
      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name)).toEqual([EVALUATE_TOOL_NAME]);
    } finally {
      await client.close();
    }
  }, 20_000);
});
