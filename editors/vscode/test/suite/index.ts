// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — real VS Code host integration test

/**
 * Run the scan, ledger-validation, tree, and watcher journey inside the real extension host.
 * Write a completion proof after the native assertions have finished.
 * @module
 */

import assert from "node:assert/strict";
import { appendFile, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import * as vscode from "vscode";
import type { RigorFoundryApi } from "../../src/extension.js";
import { testTreeView } from "./treeView.test.js";
import { testValidationRaces } from "./cli.test.js";
import { testNativeUiDeadlines } from "./nativeUi.test.js";
import { testCommandOutput } from "./commandOutput.test.js";
import {
  testCommandRefusals,
  testEmptyValidation,
  testReportWithoutLedger,
} from "./extension.test.js";
import { captureEvidenceView, chooseEvidenceFile } from "../support/nativeUi.js";

/**
 * Execute the evidence scan, ledger validation, tree rendering, and watcher journey in VS Code.
 * @returns Completion after the actual extension host has written its success proof.
 */
export async function run(): Promise<void> {
  const fixture = process.env["RF_VSCODE_FIXTURE"];
  assert.ok(fixture, "RF_VSCODE_FIXTURE is required");
  await writeFile(
    path.join(fixture, ".rigor", "vscode-host.json"),
    JSON.stringify({
      vscodeVersion: vscode.version,
      nodeVersion: process.version,
      platform: process.platform,
      architecture: process.arch,
      aiFeaturesDisabled: vscode.workspace
        .getConfiguration("chat")
        .get<boolean>("disableAIFeatures"),
    }) + "\n",
    "utf8",
  );
  const extension = vscode.extensions.getExtension<RigorFoundryApi>("anulum.rigor-foundry-vscode");
  assert.ok(extension, "development extension was not discovered");
  const api = await extension.activate();

  const commands = await vscode.commands.getCommands(true);
  assert.ok(commands.includes("rigorFoundry.scanWorkspace"));
  assert.ok(commands.includes("rigorFoundry.validateReviews"));
  assert.ok(!commands.some((command) => command.startsWith("rigorFoundry.remediate")));
  assert.ok(!commands.some((command) => command.startsWith("rigorFoundry.promote")));

  await testEmptyValidation(api, fixture);
  await vscode.commands.executeCommand("rigorFoundry.scanWorkspace");
  const scanned = api.getSnapshot();
  assert.ok(scanned.report);
  assert.ok(
    scanned.report.candidates.length > 0,
    "real fixture scan should yield evidence candidates",
  );

  const rows = testTreeView(scanned);
  const sourceRow = rows.find((row) => row.candidate.anchor.kind === "tracked-blob");
  assert.ok(sourceRow, "the real production owner must have a source-anchored candidate");
  const ledgerPath = path.join(fixture, ".rigor", "reviews.json");
  const ledgerBefore = await readFile(ledgerPath);
  await vscode.commands.executeCommand("rigorFoundry.copyCandidateIdentity", sourceRow);
  const identity = await vscode.env.clipboard.readText();
  assert.ok(identity.includes(`report=${scanned.report.report_digest}`));
  assert.ok(identity.includes(`candidate=${sourceRow.candidate.candidate_id}`));
  await vscode.commands.executeCommand("rigorFoundry.openEvidence", sourceRow);
  const editor = vscode.window.activeTextEditor;
  assert.ok(editor);
  assert.equal(
    editor.document.uri.fsPath,
    vscode.Uri.file(path.join(fixture, sourceRow.candidate.anchor.path)).fsPath,
  );
  assert.equal(editor.selection.start.line, sourceRow.candidate.anchor.line_start - 1);
  await vscode.commands.executeCommand("rigorFoundry.refresh");
  assert.equal(api.getSnapshot().report?.report_digest, scanned.report.report_digest);
  assert.deepEqual(
    await readFile(ledgerPath),
    ledgerBefore,
    "inspection must preserve ledger bytes",
  );

  const initialReport = path.join(fixture, ".rigor", "initial-report.json");
  await chooseEvidenceFile(fixture, "rigorFoundry.loadReport", initialReport, "load-report");
  assert.equal(api.getSnapshot().reportPath, initialReport);
  assert.equal(api.getSnapshot().reviewPath, undefined);
  await testReportWithoutLedger(api, fixture);
  const beforeCancel = api.getSnapshot();
  await chooseEvidenceFile(fixture, "rigorFoundry.loadReport", undefined, "cancel-report");
  assert.deepEqual(api.getSnapshot(), beforeCancel);
  await chooseEvidenceFile(fixture, "rigorFoundry.loadReviews", undefined, "cancel-review");
  assert.deepEqual(api.getSnapshot(), beforeCancel);
  await chooseEvidenceFile(fixture, "rigorFoundry.loadReviews", ledgerPath, "load-review");
  assert.equal(api.getSnapshot().reviewPath, ledgerPath);
  assert.ok(api.getSnapshot().reviews.size > 0);
  const category = scanned.report.candidates[0]?.category;
  assert.ok(category);
  await testCommandRefusals(api, fixture, sourceRow);
  await testCommandOutput(api, fixture);
  await captureEvidenceView(fixture, category);
  await writeFile(
    path.join(fixture, ".rigor", "native-ui-controls.json"),
    JSON.stringify({
      reportPath: api.getSnapshot().reportPath,
      reviewPath: api.getSnapshot().reviewPath,
      reportDigest: api.getSnapshot().report?.report_digest,
      reviewRecords: api.getSnapshot().reviews.size,
      reportCancellationPreservedSnapshot: true,
      reviewCancellationPreservedSnapshot: true,
      sourceOpened: editor.document.uri.fsPath,
      clipboardIdentity: identity,
    }) + "\n",
    "utf8",
  );

  await testValidationRaces(api, fixture);
  await api.loadReviews(fixture, path.join(fixture, ".rigor", "reviews.json"));
  await vscode.commands.executeCommand("rigorFoundry.validateReviews");
  assert.equal(api.getSnapshot().canonicallyValidated, true);
  testTreeView(api.getSnapshot());
  await appendFile(path.join(fixture, ".rigor", "reviews.json"), "\n", "utf8");
  const watcherDeadline = Date.now() + 5000;
  while (api.getSnapshot().canonicallyValidated && Date.now() < watcherDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.equal(
    api.getSnapshot().canonicallyValidated,
    false,
    "ledger change must clear validation",
  );
  await testNativeUiDeadlines(api, fixture);
  await writeFile(path.join(fixture, ".rigor", "vscode-test-complete"), "ok\n", "utf8");
}
