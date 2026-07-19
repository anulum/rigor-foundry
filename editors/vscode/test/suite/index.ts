// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — real VS Code host integration test

import assert from "node:assert/strict";
import {appendFile, writeFile} from "node:fs/promises";
import path from "node:path";
import * as vscode from "vscode";
import {RigorFoundryApi} from "../../src/extension.js";
import {testTreeView} from "./treeView.test.js";

export async function run(): Promise<void> {
  testTreeView();
  const fixture = process.env.RF_VSCODE_FIXTURE;
  assert.ok(fixture, "RF_VSCODE_FIXTURE is required");
  const extension = vscode.extensions.getExtension<RigorFoundryApi>("anulum.rigor-foundry-vscode");
  assert.ok(extension, "development extension was not discovered");
  const api = await extension.activate();

  const commands = await vscode.commands.getCommands(true);
  assert.ok(commands.includes("rigorFoundry.scanWorkspace"));
  assert.ok(commands.includes("rigorFoundry.validateReviews"));
  assert.ok(!commands.some((command) => command.startsWith("rigorFoundry.remediate")));
  assert.ok(!commands.some((command) => command.startsWith("rigorFoundry.promote")));

  await vscode.commands.executeCommand("rigorFoundry.scanWorkspace");
  const scanned = api.getSnapshot();
  assert.ok(scanned.report);
  assert.ok(scanned.report.candidates.length > 0, "real fixture scan should yield evidence candidates");

  await api.loadReviews(fixture, path.join(fixture, ".rigor", "reviews.json"));
  await vscode.commands.executeCommand("rigorFoundry.validateReviews");
  assert.equal(api.getSnapshot().canonicallyValidated, true);
  await appendFile(path.join(fixture, ".rigor", "reviews.json"), "\n", "utf8");
  const watcherDeadline = Date.now() + 5000;
  while (api.getSnapshot().canonicallyValidated && Date.now() < watcherDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.equal(api.getSnapshot().canonicallyValidated, false, "ledger change must clear validation");
  await writeFile(path.join(fixture, ".rigor", "vscode-test-complete"), "ok\n", "utf8");
}
