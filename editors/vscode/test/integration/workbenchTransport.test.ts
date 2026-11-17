// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — actual owned workbench connection lifecycle

/**
 * Exercise the real installed application from an independent Node controller.
 * Retain owned profiles and original protocol/process evidence for every outcome.
 * @module
 */

import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import type { TestContext } from "node:test";
import { setInterval as interval, setTimeout as delay } from "node:timers/promises";
import { inspect } from "node:util";
import type { CommandResult } from "../../src/cli.js";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";
import { isWorkbenchTarget, workbenchPort } from "../support/workbenchProtocol.js";
import { connectNativeUi, connectWorkbench } from "../support/workbenchTransport.js";
import type { NativeUiConnection } from "../support/workbenchTransport.js";

/** One actual application launch whose finite process result remains observed. */
interface OwnedWorkbench {
  /** Real workspace and evidence directory under the maintained test output tree. */
  readonly fixture: string;
  /** Live connection to this launch's actual workbench renderer. */
  readonly connection: NativeUiConnection;
  /** Original bounded process outcome; rejection is observed immediately. */
  readonly completion: Promise<PromiseSettledResult<CommandResult>[]>;
  /** Real launch timestamp, used to issue input before the owned process deadline. */
  readonly started: number;
  /** Original overall discovery budget, never renewed for a later request. */
  readonly discoveryDeadline: AbortSignal;
}

/**
 * Start an isolated installed workbench and discover its own published endpoint.
 * @param context - Test lifecycle retaining original process evidence on all outcomes.
 * @param deadline - Finite application lifetime, also enforced when an assertion fails.
 * @returns Actual connection and independently observed process completion.
 */
async function launchWorkbench(context: TestContext, deadline: number): Promise<OwnedWorkbench> {
  const executable = process.env["VSCODE_EXECUTABLE"];
  assert.ok(executable, "VSCODE_EXECUTABLE must name the actual installed application");
  const fixtures = path.resolve(__dirname, "../../fixtures");
  await mkdir(fixtures, { recursive: true });
  const root = await mkdtemp(path.join(fixtures, "rigor-workbench-"));
  const fixture = path.join(root, "workspace");
  const profile = path.join(root, "user-data");
  const extensions = path.join(root, "extensions");
  await mkdir(path.join(fixture, ".rigor"), { recursive: true });
  await mkdir(path.join(profile, "User"), { recursive: true });
  await mkdir(extensions);
  await writeFile(
    path.join(profile, "User", "settings.json"),
    JSON.stringify({
      "chat.disableAIFeatures": true,
      "window.dialogStyle": "custom",
      "workbench.startupEditor": "none",
      "security.workspace.trust.enabled": false,
    }) + "\n",
  );
  const environment = { ...process.env };
  delete environment["ELECTRON_RUN_AS_NODE"];
  delete environment["NODE_OPTIONS"];
  const started = Date.now();
  const completion = Promise.allSettled([
    runCli(
      executable,
      [
        "--shared-data-dir",
        path.join(root, "shared-data"),
        "--user-data-dir",
        profile,
        "--extensions-dir",
        extensions,
        "--wait",
        "--new-window",
        "--disable-extensions",
        "--disable-workspace-trust",
        "--skip-welcome",
        "--skip-release-notes",
        "--disable-telemetry",
        "--disable-gpu",
        "--remote-debugging-port=0",
        "--remote-debugging-address=127.0.0.1",
        fixture,
      ],
      { cwd: root, timeoutMilliseconds: deadline, environment },
    ),
  ]);
  context.after(async () => {
    await writeFile(
      path.join(fixture, ".rigor", "process-outcome.txt"),
      inspect(await completion, { depth: null, maxStringLength: null }) + "\n",
    );
  });
  const discoveryDeadline = AbortSignal.timeout(10_000);
  for await (const directory of interval(50, profile, { signal: discoveryDeadline })) {
    if (!(await readdir(directory)).includes("DevToolsActivePort")) continue;
    const port = workbenchPort(await readFile(path.join(profile, "DevToolsActivePort"), "utf8"));
    const response = await fetch(`http://127.0.0.1:${String(port)}/json/list`, {
      signal: discoveryDeadline,
    });
    assert.equal(response.ok, true);
    const targets: unknown = await response.json();
    await appendFile(
      path.join(fixture, ".rigor", "target-discovery.ndjson"),
      JSON.stringify({ port, targets }) + "\n",
    );
    assert.ok(Array.isArray(targets));
    if (targets.some(isWorkbenchTarget)) break;
  }
  const connection = await connectNativeUi(fixture);
  context.after(() => {
    connection.close();
  });
  await connection.send("Runtime.enable");
  const version = await connection.send("Browser.getVersion");
  await writeFile(
    path.join(fixture, ".rigor", "browser-version.json"),
    JSON.stringify(version) + "\n",
  );
  return { fixture, connection, completion, started, discoveryDeadline };
}

void test(
  "real workbench retains its command deadline and refuses its closed endpoint",
  { timeout: 60_000 },
  async (context) => {
    const { fixture, connection, completion, discoveryDeadline } = await launchWorkbench(
      context,
      45_000,
    );
    await assert.rejects(
      connection.send("Runtime.evaluate", {
        expression: "globalThis.rigorWorkbenchPending = new Promise(() => {})",
        awaitPromise: true,
      }),
      { message: "owned workbench command exceeded its deadline" },
    );
    assert.equal(discoveryDeadline.aborted, true);
    await assert.rejects(
      fetch(`http://127.0.0.1:${String(connection.port)}/json/list`, {
        signal: discoveryDeadline,
      }),
      { name: "TimeoutError" },
    );
    await writeFile(
      path.join(fixture, ".rigor", "discovery-deadline.json"),
      JSON.stringify({
        originalBudgetMilliseconds: 10_000,
        sameSignalUsedForIntervalAndEveryDiscoveryRequest: true,
        originalSignalAborted: discoveryDeadline.aborted,
        requestToActualOwnedEndpointRefusedWithExpiredSignal: true,
        actualRendererPort: connection.port,
      }) + "\n",
    );
    await assert.rejects(
      connection.send("RigorFoundry.undefinedMethod"),
      /owned workbench refused RigorFoundry.undefinedMethod/u,
    );
    const close = await Promise.allSettled([connection.send("Page.close")]);
    await writeFile(path.join(fixture, ".rigor", "close-outcome.txt"), inspect(close) + "\n");
    const outcomes = await completion;
    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0]?.status, "fulfilled");
    await assert.rejects(
      connectWorkbench(
        connection.address,
        connection.port,
        path.join(fixture, ".rigor", "native-ui-protocol.ndjson"),
      ),
      { message: "owned workbench connection failed" },
    );
  },
);

void test(
  "real owned application termination immediately refuses an outstanding command",
  { timeout: 45_000 },
  async (context) => {
    const { connection, completion, started } = await launchWorkbench(context, 20_000);
    await delay(Math.max(0, started + 15_000 - Date.now()));
    await assert.rejects(
      connection.send("Runtime.evaluate", {
        expression: "globalThis.rigorWorkbenchPending = new Promise(() => {})",
        awaitPromise: true,
      }),
      { message: "owned workbench connection closed during input" },
    );
    const outcomes = await completion;
    assert.equal(outcomes.length, 1);
    const outcome = outcomes[0];
    assert.ok(outcome);
    assert.equal(outcome.status, "rejected");
    assert.ok(outcome.reason instanceof CommandExecutionFailure);
    assert.equal(outcome.reason.message, "RigorFoundry CLI timed out after 20000 ms");
  },
);
