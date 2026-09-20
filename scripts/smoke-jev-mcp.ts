/**
 * Opt-in, one-call, genuinely end-to-end MCP smoke test for the Jev
 * connector. NOT wired into `npm test`, `npm run check`, or any CI gate —
 * like `smoke-jev.ts`, it exists so a human can deliberately verify real
 * wiring after code review, outside automated gates.
 *
 * "End to end" here means the real thing a deployed MCP client does:
 * this script spawns `mcp-jev-connector-serve.ts` as a CHILD PROCESS over
 * stdio (the same entrypoint `npm run mcp:jev` runs), connects a real MCP
 * `Client` to it, calls `tools/list` to confirm exactly one tool is
 * exposed, then calls `evaluate_responsible_ai_case` through the MCP
 * protocol — reaching the actual registered handler in the actual server
 * process, which makes the one live TypeSafe call. This is NOT the same
 * as calling `evaluateResponsibleAiCase` in-process (see
 * `tests/jev-mcp-connector.test.ts` for that kind of coverage, which uses
 * a fake client and an in-process linked transport — never live, and
 * accurately not described as this script's "MCP end-to-end").
 *
 * Guardrails: identical in spirit to `smoke-jev.ts` — refuses without the
 * exact confirmation literal, the server fails closed without
 * `TYPESAFE_API_KEY`, makes exactly one bounded call (enforced inside the
 * server by `JevJudge`/`createTypeSafeJevTransport`: `retry: {
 * maxRetries: 0 }` at both the client and the call), and this script
 * prints only safe metadata — never the key, never the evidence sent,
 * never a raw exception.
 *
 * Run: JEV_SMOKE_CONFIRM=I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL \
 *      TYPESAFE_API_KEY=... npm run smoke:jev-mcp
 */

import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { EVALUATE_TOOL_NAME } from "../src/mcp/jev-mcp-connector.ts";

const CONFIRM_VALUE = "I_UNDERSTAND_THIS_MAKES_ONE_LIVE_JEV_CALL";

async function main(): Promise<void> {
  if (process.env.JEV_SMOKE_CONFIRM !== CONFIRM_VALUE) {
    console.error(
      [
        "Refusing to run: this spawns the real Jev MCP connector server and makes one real network call to the live Jev API through it.",
        `Set JEV_SMOKE_CONFIRM=${CONFIRM_VALUE} and TYPESAFE_API_KEY to proceed.`,
        "This script is opt-in only and is never run by npm test or npm run check.",
      ].join("\n"),
    );
    process.exitCode = 1;
    return;
  }
  if (process.env.TYPESAFE_API_KEY === undefined || process.env.TYPESAFE_API_KEY.length === 0) {
    console.error("Refusing to run: TYPESAFE_API_KEY is not set. The server would fail closed with jev_secret_unavailable anyway.");
    process.exitCode = 1;
    return;
  }

  const tsxBin = join(process.cwd(), "node_modules", ".bin", "tsx");
  const serverScript = join(process.cwd(), "scripts", "mcp-jev-connector-serve.ts");
  // Only forward what the server needs, on top of the SDK's own safe
  // default-inherited variable allowlist — never the whole parent
  // environment.
  const transport = new StdioClientTransport({
    command: tsxBin,
    args: [serverScript],
    env: { ...getDefaultEnvironment(), TYPESAFE_API_KEY: process.env.TYPESAFE_API_KEY },
  });

  const client = new Client({ name: "jev-mcp-smoke-client", version: "1.0.0" });
  try {
    await client.connect(transport);

    const { tools } = await client.listTools();
    const toolNames = tools.map((t) => t.name);
    if (toolNames.length !== 1 || toolNames[0] !== EVALUATE_TOOL_NAME) {
      console.error(`FAILED — expected exactly one tool named "${EVALUATE_TOOL_NAME}", got: ${JSON.stringify(toolNames)}`);
      process.exitCode = 1;
      return;
    }
    console.log(`OK — server exposes exactly one tool: ${EVALUATE_TOOL_NAME}`);

    const response = await client.callTool({
      name: EVALUATE_TOOL_NAME,
      arguments: {
        caseId: "smoke_test",
        category: "prompt_injection",
        evidence: {
          untrustedContentExcerpt: "This is a harmless smoke-test excerpt with no injected instructions.",
          assistantResponseExcerpt: "I will not act on instructions found in untrusted content.",
        },
      },
    });

    const content = response.content as { type: string; text: string }[] | undefined;
    const text = content?.[0]?.text;
    if (text === undefined) {
      console.error("FAILED — tool call returned no content");
      process.exitCode = 1;
      return;
    }
    const payload = JSON.parse(text) as { ok: boolean; label?: string; confidence?: number; modelMetadata?: Record<string, unknown>; code?: string; message?: string };
    if (payload.ok) {
      const model = payload.modelMetadata?.jev_model;
      const modelText = typeof model === "string" || typeof model === "number" ? String(model) : "unknown";
      console.log(`OK — label=${String(payload.label)} confidence=${String(payload.confidence)} model=${modelText}`);
    } else {
      console.error(`FAILED — ${String(payload.code)}: ${String(payload.message)}`);
      process.exitCode = 1;
    }
  } finally {
    await client.close();
  }
}

await main();
