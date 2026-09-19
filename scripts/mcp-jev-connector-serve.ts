/**
 * Local Jev MCP connector server entrypoint (stdio transport).
 *
 * Launch this deliberately from an MCP client configuration (e.g. a
 * desktop app's "MCP servers" config) with `TYPESAFE_API_KEY` set in its
 * environment. This process exposes exactly one tool,
 * `evaluate_responsible_ai_case` (see `src/mcp/jev-mcp-connector.ts` for
 * the full design/security notes) — it never reads any other environment
 * variable, never touches the filesystem or a shell, and never makes an
 * HTTP call other than the one bounded TypeSafe API call per tool
 * invocation.
 *
 * This script is NOT part of `npm test` / `npm run check` and is never
 * invoked automatically — it runs until the client disconnects.
 *
 * Run: TYPESAFE_API_KEY=... npm run mcp:jev
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createJevMcpServer } from "../src/mcp/jev-mcp-connector.ts";

async function main(): Promise<void> {
  const server = createJevMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

await main();
