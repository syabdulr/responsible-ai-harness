/**
 * Minimal in-process pair of MCP `Transport` implementations, used only
 * in tests to drive a real `McpServer` with a real `Client` without any
 * process spawn, stdio, or network — the SDK doesn't export a stable
 * `InMemoryTransport` from its public subpaths, so this is a tiny,
 * from-scratch stand-in implementing the same documented interface.
 */

import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

class LinkedTransport implements Transport {
  onmessage?: (message: JSONRPCMessage) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  private peer: LinkedTransport | undefined;

  linkTo(peer: LinkedTransport): void {
    this.peer = peer;
  }

  start(): Promise<void> {
    return Promise.resolve();
  }

  send(message: JSONRPCMessage): Promise<void> {
    queueMicrotask(() => this.peer?.onmessage?.(message));
    return Promise.resolve();
  }

  close(): Promise<void> {
    this.onclose?.();
    return Promise.resolve();
  }
}

export function createLinkedTransportPair(): [Transport, Transport] {
  const a = new LinkedTransport();
  const b = new LinkedTransport();
  a.linkTo(b);
  b.linkTo(a);
  return [a, b];
}
