// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — owned renderer protocol inputs

/**
 * Validate public discovery and response inputs without substituting any browser.
 * These are protocol examples; actual workbench lifecycle proof lives in integration tests.
 * @module
 */

import assert from "node:assert/strict";
import test from "node:test";
import {
  dispatchWorkbenchReply,
  requireWorkbenchAddress,
  workbenchAddress,
  workbenchPort,
  workbenchResult,
} from "../support/workbenchProtocol.js";

void test("profile ports and renderer addresses retain their exact loopback binding", () => {
  assert.equal(workbenchPort("43210\n/devtools/browser/owned\n"), 43210);
  assert.equal(workbenchPort("1"), 1);
  assert.equal(workbenchPort("65535"), 65535);
  for (const input of ["", "x", "-1", "1.5", "0", "65536", "9".repeat(40)]) {
    assert.throws(() => workbenchPort(input));
  }
  requireWorkbenchAddress(new URL("ws://127.0.0.1:43210/devtools/page/owned"), 43210);
  for (const input of [
    "wss://127.0.0.1:43210/devtools/page/owned",
    "ws://localhost:43210/devtools/page/owned",
    "ws://127.0.0.1:43211/devtools/page/owned",
    "ws://127.0.0.1:43210/devtools/browser/owned",
  ]) {
    assert.throws(() => {
      requireWorkbenchAddress(new URL(input), 43210);
    });
  }
});

void test("discovery selects only a workbench page with a checked renderer endpoint", () => {
  const endpoint = "ws://127.0.0.1:43210/devtools/page/owned";
  const ignored: unknown[] = [
    1,
    null,
    {},
    { type: "worker" },
    { type: "page" },
    { type: "page", url: 1 },
    { type: "page", url: "welcome" },
  ];
  assert.equal(
    workbenchAddress(
      [
        ...ignored,
        { type: "page", url: "vscode-file://workbench.html", webSocketDebuggerUrl: endpoint },
      ],
      43210,
    ).href,
    endpoint,
  );
  for (const targets of [
    null,
    {},
    "[]",
    [],
    ignored,
    [{ type: "page", url: "workbench" }],
    [{ type: "page", url: "workbench", webSocketDebuggerUrl: 1 }],
    [{ type: "page", url: "workbench", webSocketDebuggerUrl: "invalid" }],
  ]) {
    assert.throws(() => workbenchAddress(targets, 43210));
  }
});

void test("response dispatch ignores unrelated frames and preserves matching envelopes", () => {
  const observed: { error: Error | undefined; value: unknown }[] = [];
  const complete = (error: Error | undefined, value: unknown): void => {
    observed.push({ error, value });
  };
  for (const input of ["null", "1", "[]", "{}", '{"id":2}', '{"method":"event"}']) {
    dispatchWorkbenchReply(input, 1, complete);
  }
  assert.deepEqual(observed, []);
  dispatchWorkbenchReply('{"id":1,"result":{"value":7}}', 1, complete);
  assert.deepEqual(observed, [{ error: undefined, value: { id: 1, result: { value: 7 } } }]);
  for (const input of [Buffer.from("{}"), " ".repeat(16_777_217), "{]"]) {
    const received: { error: Error | undefined; value: unknown }[] = [];
    dispatchWorkbenchReply(input, 1, (error, value): void => {
      received.push({ error, value });
    });
    assert.equal(received.length, 1);
    const actual = received[0];
    assert.ok(actual);
    assert.ok(actual.error instanceof Error);
    assert.equal(actual.value, undefined);
    assert.equal(
      actual.error.message,
      input === "{]"
        ? "owned workbench returned malformed protocol JSON"
        : "owned workbench returned an invalid protocol frame",
    );
  }
  dispatchWorkbenchReply(" ".repeat(16_777_214) + "{}", 1, complete);
  assert.equal(observed.length, 1);
});

void test("result admission preserves browser values and refuses malformed or error envelopes", () => {
  const result = { accepted: [1, null] };
  assert.equal(workbenchResult({ id: 1, result }, "Runtime.evaluate"), result);
  assert.equal(workbenchResult({ result: null }, "Runtime.evaluate"), null);
  for (const input of [null, 1, {}, { id: 1 }]) {
    assert.throws(() => workbenchResult(input, "Runtime.evaluate"));
  }
  assert.throws(
    () => workbenchResult({ error: { message: "refused" } }, "Runtime.evaluate"),
    /owned workbench refused Runtime.evaluate/u,
  );
});
