// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — loaded report ownership in a real multi-root host

/**
 * Exercise registered evidence commands across two real Git and CLI-produced repositories.
 * Preserve active-folder independence, removed-owner refusal and report replacement.
 * @module
 */

import assert from "node:assert/strict";
import { once } from "node:events";
import { appendFile, copyFile, writeFile } from "node:fs/promises";
import path from "node:path";
import * as vscode from "vscode";
import type { RigorFoundryApi } from "../../src/extension.js";
import { testTreeView, testUnvalidatedTreeEvidence } from "./treeView.test.js";
import {
  chooseEvidenceFile,
  readEvidenceOutput,
  waitForEvidenceOutput,
} from "../support/nativeUi.js";

/**
 * Observe an authored registered-command refusal without changing the loaded pair.
 * @param api - Actual extension API owning the loaded report.
 * @param root - First fixture whose host logs contain the real output channel.
 * @param command - Registered evidence command.
 * @param argument - Optional actual candidate row.
 * @param expected - Authored explanation for the actual workspace or evidence refusal.
 * @returns Completion after the refusal and unchanged snapshot are verified.
 */
async function expectWorkspaceRefusal(
  api: RigorFoundryApi,
  root: string,
  command: string,
  argument?: unknown,
  expected = "loaded report repository is no longer an open workspace folder",
): Promise<void> {
  const before = api.getSnapshot();
  const clipboard = await vscode.env.clipboard.readText();
  const output = await readEvidenceOutput(root);
  await vscode.commands.executeCommand(command, argument);
  await waitForEvidenceOutput(root, output, expected);
  assert.deepEqual(api.getSnapshot(), before);
  assert.equal(await vscode.env.clipboard.readText(), clipboard);
}

/**
 * Change only the second workspace folder and await the real workspace event.
 * @param root - Actual owner directory to insert, or absent when removing it.
 * @param unrelatedRoot - Existing folder temporarily added to verify that unrelated events cannot finish the wait.
 * @returns Completion after VS Code publishes its workspace-folder change.
 */
async function changeSecondFolder(root?: string, unrelatedRoot?: string): Promise<void> {
  const original = vscode.workspace.workspaceFolders;
  assert.ok(original);
  let expectedPath: string;
  if (root === undefined) {
    const removed = original[1];
    assert.ok(removed);
    expectedPath = removed.uri.fsPath;
  } else expectedPath = vscode.Uri.file(root).fsPath;
  const completion = new EventTarget();
  const cancellation = new AbortController();
  const observed = once(completion, "changed", {
    signal: cancellation.signal,
  });
  let matched = false;
  const subscription = vscode.workspace.onDidChangeWorkspaceFolders((change) => {
    const folders = root === undefined ? change.removed : change.added;
    if (folders.some((folder) => folder.uri.fsPath === expectedPath)) {
      matched = true;
      completion.dispatchEvent(new Event("changed"));
    }
    completion.dispatchEvent(new Event("observed"));
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(reject, 5000, new Error("workspace folder change was not observed"));
  });
  try {
    const update = Promise.resolve().then(async () => {
      if (unrelatedRoot !== undefined) {
        await Promise.all([
          once(completion, "observed", { signal: cancellation.signal }),
          Promise.resolve().then(() => {
            assert.equal(
              vscode.workspace.updateWorkspaceFolders(original.length, 0, {
                uri: vscode.Uri.file(unrelatedRoot),
              }),
              true,
            );
          }),
        ]);
        assert.equal(matched, false);
      }
      const accepted =
        root === undefined
          ? vscode.workspace.updateWorkspaceFolders(1, 1)
          : vscode.workspace.updateWorkspaceFolders(1, 0, { uri: vscode.Uri.file(root) });
      if (!accepted) throw new Error("workspace folder change was refused");
    });
    await Promise.race([expired, Promise.all([observed, update])]);
    if (unrelatedRoot !== undefined) {
      const current = vscode.workspace.workspaceFolders;
      assert.ok(current);
      const index = current.findIndex(
        (folder) => folder.uri.fsPath === vscode.Uri.file(unrelatedRoot).fsPath,
      );
      assert.ok(index >= 0);
      await Promise.race([
        expired,
        Promise.all([
          once(completion, "observed", { signal: cancellation.signal }),
          Promise.resolve().then(() => {
            assert.equal(vscode.workspace.updateWorkspaceFolders(index, 1), true);
          }),
        ]),
      ]);
    }
  } finally {
    clearTimeout(timer);
    cancellation.abort();
    subscription.dispose();
  }
}

/**
 * Run the complete public multi-root report-owner lifecycle in the actual editor host.
 * @returns Completion after both real owners and removed-owner refusals have passed.
 */
export async function run(): Promise<void> {
  const root = process.env["RF_VSCODE_WORKSPACE_A"];
  const other = process.env["RF_VSCODE_WORKSPACE_B"];
  assert.ok(root && other);
  await writeFile(
    path.join(root, ".rigor", "workspace-host.json"),
    JSON.stringify({
      vscodeVersion: vscode.version,
      nodeVersion: process.version,
      platform: process.platform,
      architecture: process.arch,
    }) + "\n",
    "utf8",
  );
  assert.deepEqual(
    vscode.workspace.workspaceFolders?.map((folder) => folder.uri.fsPath),
    [other, root].map((file) => vscode.Uri.file(file).fsPath),
  );
  await assert.rejects(changeSecondFolder(root), /workspace folder change was refused/u);
  assert.ok(vscode.workspace.workspaceFolders);
  assert.deepEqual(
    vscode.workspace.workspaceFolders.map((folder) => folder.uri.fsPath),
    [other, root].map((file) => vscode.Uri.file(file).fsPath),
  );
  const extension = vscode.extensions.getExtension<RigorFoundryApi>("anulum.rigor-foundry-vscode");
  assert.ok(extension);
  const api = await extension.activate();
  const report = path.join(root, ".rigor", "report.json");
  const reviews = path.join(root, ".rigor", "reviews.json");
  await assert.rejects(
    api.loadReviews(root, reviews),
    /load an audit report before inspecting its workspace/u,
  );
  assert.equal(api.getSnapshot().report, undefined);
  await api.loadReport(root, report);
  await api.loadReviews(root, reviews);
  const rows = testTreeView(api.getSnapshot());
  const row = rows.find((item) => item.candidate.anchor.kind === "tracked-blob");
  assert.ok(row);
  const relative = row.candidate.anchor.path;
  const focusOther = async (): Promise<void> => {
    const document = await vscode.workspace.openTextDocument(
      vscode.Uri.file(path.join(other, relative)),
    );
    await vscode.window.showTextDocument(document);
    assert.equal(
      vscode.window.activeTextEditor?.document.uri.fsPath,
      vscode.Uri.file(path.join(other, relative)).fsPath,
    );
  };
  await focusOther();
  await vscode.commands.executeCommand("rigorFoundry.openEvidence", row);
  const observed = vscode.window.activeTextEditor?.document.uri.fsPath;
  await writeFile(
    path.join(root, ".rigor", "workspace-binding.ndjson"),
    JSON.stringify({
      case: "active-B-open-loaded-A",
      reportRoot: root,
      activeBefore: other,
      vscodeVersion: vscode.version,
      nodeVersion: process.version,
      expected: path.join(root, relative),
      observed,
    }) + "\n",
    "utf8",
  );
  assert.equal(
    observed,
    vscode.Uri.file(path.join(root, relative)).fsPath,
    "loaded A evidence must never open the matching B file",
  );

  const otherConfig = vscode.workspace.getConfiguration("rigorFoundry", vscode.Uri.file(other));
  const executable = otherConfig.get<string>("executable");
  assert.ok(executable);
  await otherConfig.update(
    "executable",
    path.join(other, ".rigor", "absent-cli"),
    vscode.ConfigurationTarget.WorkspaceFolder,
  );
  try {
    await focusOther();
    await vscode.commands.executeCommand("rigorFoundry.validateReviews");
    assert.equal(
      api.getSnapshot().canonicallyValidated,
      true,
      "validation must use loaded A configuration while B is active",
    );
  } finally {
    await otherConfig.update("executable", executable, vscode.ConfigurationTarget.WorkspaceFolder);
  }
  await chooseEvidenceFile(
    root,
    "rigorFoundry.loadReviews",
    reviews,
    "loaded-a-ledger-with-b-active",
  );
  assert.equal(api.getSnapshot().reviewPath, reviews);

  const copiedLedger = path.join(other, ".rigor", "copied-A-ledger.json");
  await copyFile(reviews, copiedLedger);
  const beforeForeign = api.getSnapshot();
  await assert.rejects(
    api.loadReviews(other, copiedLedger),
    /review ledger workspace does not match the loaded report/u,
  );
  assert.deepEqual(api.getSnapshot(), beforeForeign);

  await vscode.commands.executeCommand("workbench.action.closeAllEditors");
  const closedEditor = vscode.window.activeTextEditor;
  assert.equal(closedEditor, undefined);
  for (const command of ["rigorFoundry.scanWorkspace", "rigorFoundry.loadReport"]) {
    await expectWorkspaceRefusal(
      api,
      root,
      command,
      undefined,
      "select a file in the workspace whose evidence should be inspected",
    );
  }
  await vscode.commands.executeCommand("rigorFoundry.openEvidence", row);
  assert.equal(
    vscode.window.activeTextEditor?.document.uri.fsPath,
    vscode.Uri.file(path.join(root, relative)).fsPath,
  );
  const sourceDocument = vscode.window.activeTextEditor.document;
  assert.ok(sourceDocument);
  assert.ok(row.candidate.anchor.line_end > 1);
  const edit = new vscode.WorkspaceEdit();
  edit.replace(
    sourceDocument.uri,
    new vscode.Range(
      new vscode.Position(0, 0),
      sourceDocument.lineAt(sourceDocument.lineCount - 1).range.end,
    ),
    "shortened source",
  );
  assert.equal(await vscode.workspace.applyEdit(edit), true);
  try {
    assert.equal(sourceDocument.lineCount, 1);
    await expectWorkspaceRefusal(
      api,
      root,
      "rigorFoundry.openEvidence",
      row,
      "candidate anchor line span exceeds the current source file",
    );
  } finally {
    await vscode.commands.executeCommand("workbench.action.files.revert");
  }
  assert.equal(sourceDocument.isDirty, false);
  assert.ok(sourceDocument.lineCount >= row.candidate.anchor.line_end);
  await vscode.commands.executeCommand("workbench.action.closeAllEditors");
  await vscode.commands.executeCommand("rigorFoundry.validateReviews");
  assert.equal(api.getSnapshot().canonicallyValidated, true);

  await focusOther();
  await changeSecondFolder(undefined, path.dirname(root));
  try {
    await expectWorkspaceRefusal(api, root, "rigorFoundry.openEvidence", row);
    await expectWorkspaceRefusal(api, root, "rigorFoundry.copyCandidateIdentity", row);
    await expectWorkspaceRefusal(api, root, "rigorFoundry.validateReviews");
    await expectWorkspaceRefusal(api, root, "rigorFoundry.loadReviews");
    await api.loadReport(other, path.join(other, ".rigor", "report.json"));
    assert.equal(
      api.getSnapshot().reviewPath,
      undefined,
      "replacing the owner must clear the previous ledger",
    );
    await api.loadReviews(other, path.join(other, ".rigor", "reviews.json"));
    const replacement = testTreeView(api.getSnapshot()).find(
      (item) => item.candidate.anchor.kind === "tracked-blob",
    );
    assert.ok(replacement);
    await vscode.commands.executeCommand("rigorFoundry.openEvidence", replacement);
    const replacementEditor = vscode.window.activeTextEditor;
    assert.ok(replacementEditor);
    assert.equal(
      replacementEditor.document.uri.fsPath,
      vscode.Uri.file(path.join(other, replacement.candidate.anchor.path)).fsPath,
    );
    await vscode.commands.executeCommand("rigorFoundry.validateReviews");
    assert.equal(api.getSnapshot().canonicallyValidated, true);
  } finally {
    await changeSecondFolder(root);
  }

  await focusOther();
  const originalReportPath = otherConfig.get<string>("reportPath", ".rigor/report.json");
  const nextReportPath = ".rigor/active-folder-report.json";
  await otherConfig.update(
    "reportPath",
    nextReportPath,
    vscode.ConfigurationTarget.WorkspaceFolder,
  );
  try {
    await vscode.commands.executeCommand("rigorFoundry.scanWorkspace");
    assert.equal(
      api.getSnapshot().report?.repository_root,
      other,
      "scan still follows the actively selected repository",
    );
    assert.equal(api.getSnapshot().reportPath, path.join(other, nextReportPath));
    assert.equal(api.getSnapshot().reviewPath, undefined);
  } finally {
    await otherConfig.update(
      "reportPath",
      originalReportPath,
      vscode.ConfigurationTarget.WorkspaceFolder,
    );
  }
  const firstDocument = await vscode.workspace.openTextDocument(
    vscode.Uri.file(path.join(root, relative)),
  );
  await vscode.window.showTextDocument(firstDocument);
  await chooseEvidenceFile(
    root,
    "rigorFoundry.loadReport",
    report,
    "replace-b-with-selected-a-report",
  );
  assert.equal(api.getSnapshot().report?.repository_root, root);
  assert.equal(api.getSnapshot().reviewPath, undefined);
  await api.loadReviews(root, reviews);
  await api.loadReport(root, path.join(root, ".rigor", "tree-report.json"));
  await testUnvalidatedTreeEvidence(
    api,
    root,
    path.join(root, ".rigor", "tree-report.json"),
    path.join(root, ".rigor", "tree-reviews.json"),
  );
  const treeRow = testTreeView(api.getSnapshot()).find(
    (item) => item.candidate.anchor.kind === "repository-tree",
  );
  assert.ok(treeRow);
  await expectWorkspaceRefusal(
    api,
    root,
    "rigorFoundry.openEvidence",
    treeRow,
    "repository-tree evidence has no single source file to open",
  );
  await vscode.commands.executeCommand("rigorFoundry.copyCandidateIdentity", treeRow);
  const treeIdentity = await vscode.env.clipboard.readText();
  assert.ok(treeRow.candidate.anchor.kind === "repository-tree");
  assert.ok(treeIdentity.includes(`tree=${treeRow.candidate.anchor.tree_oid}`));
  assert.ok(
    treeIdentity.includes(
      `tracked_content_sha256=${treeRow.candidate.anchor.tracked_content_sha256}`,
    ),
  );
  await api.loadReport(root, report);
  await api.loadReviews(root, reviews);
  await appendFile(
    path.join(root, ".rigor", "workspace-binding.ndjson"),
    JSON.stringify({
      case: "complete-owner-lifecycle",
      focusIndependentOpen: true,
      focusIndependentValidation: true,
      ledgerPickerOwnerBound: true,
      foreignRootRefused: true,
      noActiveEditorOpenAndValidate: true,
      removedOwnerRefusals: 4,
      replacementOwnerValidated: true,
      activeScanAndReportPicker: true,
      ambiguousActiveFolderRefused: true,
      editedSourceSpanRefused: true,
      repositoryTreeOpenRefusedAndIdentityCopied: true,
      vscodeVersion: vscode.version,
    }) + "\n",
    "utf8",
  );
  await writeFile(path.join(root, ".rigor", "workspace-test-complete"), "ok\n", "utf8");
}
