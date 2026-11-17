// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — owned workbench protocol boundaries

/**
 * Validate owned workbench discovery and bounded Chromium response frames.
 * Keep protocol admission independent of the editor API and network transport.
 * @module
 */

import assert from "node:assert/strict";

/** Completion of one matching response or an authored protocol refusal. */
export type WorkbenchCompletion = (error: Error | undefined, value: unknown) => void;

/**
 * Read the actual port line from the owned profile's DevToolsActivePort contents.
 * @param contents - Unchanged text published by the owned application.
 * @returns Exact finite loopback port.
 */
export function workbenchPort(contents: string): number {
  const text = contents.split("\n")[0];
  assert.ok(text !== undefined && /^\d+$/u.test(text));
  const port = Number(text);
  assert.ok(Number.isSafeInteger(port) && port > 0 && port <= 65_535);
  return port;
}

/**
 * Bind one explicit renderer endpoint to its already observed owned profile port.
 * @param address - Actual endpoint selected from Chromium target discovery.
 * @param port - Port read from the same owned profile.
 */
export function requireWorkbenchAddress(address: URL, port: number): void {
  assert.equal(address.protocol, "ws:");
  assert.equal(address.hostname, "127.0.0.1");
  assert.equal(address.port, String(port));
  assert.ok(address.pathname.startsWith("/devtools/page/"));
}

/**
 * Recognize a workbench page in an actual browser target-list response.
 * @param item - Unknown target entry, including browser events unrelated to a renderer.
 * @returns Whether the entry identifies the page whose endpoint still needs validation.
 */
export function isWorkbenchTarget(item: unknown): boolean {
  return (
    typeof item === "object" &&
    item !== null &&
    "type" in item &&
    item.type === "page" &&
    "url" in item &&
    typeof item.url === "string" &&
    item.url.includes("workbench")
  );
}

/**
 * Select the real workbench renderer from the browser's target-list response.
 * @param targets - Unknown JSON returned by the owned browser discovery endpoint.
 * @param port - Independently read owned profile port.
 * @returns Checked loopback renderer address.
 */
export function workbenchAddress(targets: unknown, port: number): URL {
  assert.ok(Array.isArray(targets));
  const target: unknown = targets.find(isWorkbenchTarget);
  assert.ok(
    typeof target === "object" &&
      target !== null &&
      "webSocketDebuggerUrl" in target &&
      typeof target.webSocketDebuggerUrl === "string",
  );
  const address = new URL(target.webSocketDebuggerUrl);
  requireWorkbenchAddress(address, port);
  return address;
}

/**
 * Dispatch only the matching bounded response, or preserve an authored frame refusal.
 * @param payload - Actual WebSocket message data; no object or parser is substituted.
 * @param id - Exact outstanding request identity.
 * @param complete - Owner notification; unrelated valid frames produce no notification.
 */
export function dispatchWorkbenchReply(
  payload: unknown,
  id: number,
  complete: WorkbenchCompletion,
): void {
  if (typeof payload !== "string" || payload.length > 16_777_216) {
    complete(new Error("owned workbench returned an invalid protocol frame"), undefined);
    return;
  }
  let value: unknown;
  try {
    value = JSON.parse(payload) as unknown;
  } catch {
    complete(new Error("owned workbench returned malformed protocol JSON"), undefined);
    return;
  }
  if (typeof value === "object" && value !== null && "id" in value && value.id === id) {
    complete(undefined, value);
  }
}

/**
 * Admit the actual completed browser result after its original envelope is journaled.
 * @param envelope - Matching response returned by the actual transport.
 * @param method - Authored browser method used only for a refusal explanation.
 * @returns The browser's unmodified result value.
 */
export function workbenchResult(envelope: unknown, method: string): unknown {
  assert.ok(typeof envelope === "object" && envelope !== null);
  assert.ok(!("error" in envelope), `owned workbench refused ${method}`);
  assert.ok("result" in envelope);
  return envelope.result;
}
