// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — real workbench file-picker input

/**
 * Operate the actual owned VS Code workbench through its loopback Chromium protocol.
 * Observe real controls, send user input, and retain screenshots and original protocol responses.
 * @module
 */

import assert from "node:assert/strict";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import * as vscode from "vscode";

import { connectNativeUi } from "./workbenchTransport.js";
import type { NativeUiConnection } from "./workbenchTransport.js";

/**
 * Read only the extension's actual output file below its owned host log directory.
 * @param directory - Existing directory in the temporary profile's log tree.
 * @returns Extension output text; unrelated application logs are never opened.
 */
async function collectEvidenceOutput(directory: string): Promise<string> {
  let output = "";
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      output += await collectEvidenceOutput(file);
    } else if (entry.isFile() && entry.name.endsWith("-RigorFoundry.log")) {
      output += await readFile(file, "utf8");
    }
  }
  return output;
}

/**
 * Read the real evidence output without invoking a private extension function.
 * @param fixture - Actual adopter inside the owned host sandbox.
 * @returns Current persisted evidence-channel output.
 */
export async function readEvidenceOutput(fixture: string): Promise<string> {
  return await collectEvidenceOutput(path.join(path.dirname(fixture), "user-data", "logs"));
}

/**
 * Wait for an actual newly appended command explanation in the evidence channel.
 * @param fixture - Actual adopter inside the owned host sandbox.
 * @param before - Channel bytes observed before the explicit command.
 * @param expected - Authored explanation expected from the actual refusal.
 * @returns Newly appended output after the expected explanation is persisted.
 */
export async function waitForEvidenceOutput(
  fixture: string,
  before: string,
  expected: string,
): Promise<string> {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const current = await readEvidenceOutput(fixture);
    assert.ok(current.startsWith(before), "owned evidence output must remain append-only");
    const added = current.slice(before.length);
    if (added.includes(expected)) {
      return added;
    }
    await delay(25);
  }
  throw new Error("actual command explanation was not persisted before its deadline");
}

/**
 * Wait for a real renderer predicate without setting application or extension state.
 * @param connection - Actual workbench transport for the owned host.
 * @param expression - Read-only DOM observation in the real renderer.
 * @returns Completion after the visible control reaches the required state.
 */
async function waitForUi(connection: NativeUiConnection, expression: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const value = await connection.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
    });
    assert.ok(typeof value === "object" && value !== null && "result" in value);
    const result = value.result;
    assert.ok(typeof result === "object" && result !== null && "value" in result);
    assert.equal(typeof result.value, "boolean");
    if (result.value === true) {
      return;
    }
    await delay(25);
  }
  throw new Error("actual workbench control did not reach its required state");
}

/**
 * Select or cancel the actual file picker opened by a registered evidence command.
 * @param fixture - Actual adopter and screenshot/protocol evidence root.
 * @param command - Registered report or review-loading command.
 * @param selectedPath - Existing actual evidence file, or undefined for real Escape cancellation.
 * @param artifactName - Descriptive screenshot name for this concrete UI state.
 * @returns Completion after actual user input closes the picker and the command settles.
 */
export async function chooseEvidenceFile(
  fixture: string,
  command: "rigorFoundry.loadReport" | "rigorFoundry.loadReviews",
  selectedPath: string | undefined,
  artifactName: string,
): Promise<void> {
  assert.match(artifactName, /^[a-z][a-z0-9-]*$/u);
  const connection = await connectNativeUi(fixture);
  try {
    const pending = vscode.commands.executeCommand(command);
    await waitForUi(
      connection,
      `(() => {
      const input = document.querySelector(".quick-input-widget input");
      return input instanceof HTMLInputElement && input === document.activeElement &&
        input.getClientRects().length > 0;
    })()`,
    );
    const screenshot = await connection.send("Page.captureScreenshot", { format: "png" });
    assert.ok(
      typeof screenshot === "object" &&
        screenshot !== null &&
        "data" in screenshot &&
        typeof screenshot.data === "string",
    );
    const directory = path.join(fixture, ".rigor", "ui");
    await mkdir(directory, { recursive: true });
    await writeFile(
      path.join(directory, artifactName + ".png"),
      Buffer.from(screenshot.data, "base64"),
    );
    if (selectedPath === undefined) {
      await connection.send("Input.dispatchKeyEvent", {
        type: "keyDown",
        key: "Escape",
        code: "Escape",
        windowsVirtualKeyCode: 27,
      });
      await connection.send("Input.dispatchKeyEvent", {
        type: "keyUp",
        key: "Escape",
        code: "Escape",
        windowsVirtualKeyCode: 27,
      });
    } else {
      await connection.send("Input.dispatchKeyEvent", {
        type: "keyDown",
        key: "a",
        code: "KeyA",
        modifiers: 2,
        windowsVirtualKeyCode: 65,
      });
      await connection.send("Input.dispatchKeyEvent", {
        type: "keyUp",
        key: "a",
        code: "KeyA",
        modifiers: 2,
        windowsVirtualKeyCode: 65,
      });
      await connection.send("Input.insertText", { text: selectedPath });
      await connection.send("Input.dispatchKeyEvent", {
        type: "keyDown",
        key: "Enter",
        code: "Enter",
        windowsVirtualKeyCode: 13,
      });
      await connection.send("Input.dispatchKeyEvent", {
        type: "keyUp",
        key: "Enter",
        code: "Enter",
        windowsVirtualKeyCode: 13,
      });
    }
    await waitForUi(
      connection,
      `(() => {
      const input = document.querySelector(".quick-input-widget input");
      return !(input instanceof HTMLInputElement) || input.getClientRects().length === 0;
    })()`,
    );
    await pending;
  } finally {
    connection.close();
  }
}

/**
 * Open the actual contributed evidence view and retain its native viewport.
 * @param fixture - Actual adopter containing the screenshot and protocol journal.
 * @param category - Real report category that must appear in a visible tree row.
 * @returns Completion after the native tree is visible and its geometry and pixels are saved.
 */
export async function captureEvidenceView(fixture: string, category: string): Promise<void> {
  await vscode.commands.executeCommand("rigorFoundry.candidates.focus");
  const connection = await connectNativeUi(fixture);
  try {
    await waitForUi(
      connection,
      `Array.from(document.querySelectorAll('[role="treeitem"]')).some(
      element => element.getClientRects().length > 0 && element.textContent.includes(${JSON.stringify(category)})
    )`,
    );
    const geometry = await connection.send("Runtime.evaluate", {
      expression: `(() => ({
        viewportWidth: window.innerWidth,
        viewportHeight: window.innerHeight,
        rows: Array.from(document.querySelectorAll('[role="treeitem"]'))
          .filter(element => element.getClientRects().length > 0)
          .map(element => {
            const bounds = element.getBoundingClientRect();
            return {text: element.textContent, x: bounds.x, y: bounds.y, width: bounds.width, height: bounds.height};
          })
      }))()`,
      returnByValue: true,
    });
    const directory = path.join(fixture, ".rigor", "ui");
    await mkdir(directory, { recursive: true });
    await writeFile(
      path.join(directory, "evidence-tree-geometry.json"),
      JSON.stringify(geometry) + "\n",
      "utf8",
    );
    const screenshot = await connection.send("Page.captureScreenshot", { format: "png" });
    assert.ok(
      typeof screenshot === "object" &&
        screenshot !== null &&
        "data" in screenshot &&
        typeof screenshot.data === "string",
    );
    await writeFile(
      path.join(directory, "evidence-tree.png"),
      Buffer.from(screenshot.data, "base64"),
    );
  } finally {
    connection.close();
  }
}
