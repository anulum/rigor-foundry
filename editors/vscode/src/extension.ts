// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — VS Code evidence-review integration

import {mkdir} from "node:fs/promises";
import path from "node:path";
import * as vscode from "vscode";
import {runCli} from "./cli.js";
import {
  resolveWorkspacePath,
  verifyExistingRegularWorkspacePath,
  verifyExistingWorkspacePath,
} from "./fileAccess.js";
import {EvidenceSnapshot, EvidenceStore} from "./store.js";
import {CandidateNode, EvidenceTreeProvider} from "./treeView.js";

/** Testable read/load surface returned by extension activation. */
export interface RigorFoundryApi {
  readonly getSnapshot: () => EvidenceSnapshot;
  readonly loadReport: (workspaceRoot: string, reportPath: string, maximumBytes?: number) => Promise<void>;
  readonly loadReviews: (workspaceRoot: string, reviewPath: string, maximumBytes?: number) => Promise<void>;
}

interface ExtensionConfiguration {
  readonly executable: string;
  readonly reportPath: string;
  readonly reviewPath: string;
  readonly policyPath: string;
  readonly maximumEvidenceBytes: number;
  readonly cliTimeoutMilliseconds: number;
}

const DEFAULT_MAXIMUM_BYTES = 16_777_216;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function workspaceFolder(): vscode.WorkspaceFolder {
  const folders = vscode.workspace.workspaceFolders;
  if (folders === undefined || folders.length === 0) {
    throw new Error("open a local RigorFoundry repository workspace first");
  }
  if (folders.length === 1 && folders[0] !== undefined) {
    return folders[0];
  }
  const active = vscode.window.activeTextEditor?.document.uri;
  const selected = active === undefined ? undefined : vscode.workspace.getWorkspaceFolder(active);
  if (selected === undefined) {
    throw new Error("select a file in the workspace whose evidence should be inspected");
  }
  return selected;
}

function configuration(folder: vscode.WorkspaceFolder): ExtensionConfiguration {
  const config = vscode.workspace.getConfiguration("rigorFoundry", folder.uri);
  const timeoutSeconds = config.get<number>("cliTimeoutSeconds", 120);
  return {
    executable: config.get<string>("executable", "rigor"),
    reportPath: config.get<string>("reportPath", ".rigor/report.json"),
    reviewPath: config.get<string>("reviewPath", ".rigor/reviews.json"),
    policyPath: config.get<string>("policyPath", "rigor-foundry-policy.json"),
    maximumEvidenceBytes: config.get<number>("maximumEvidenceBytes", DEFAULT_MAXIMUM_BYTES),
    cliTimeoutMilliseconds: timeoutSeconds * 1000,
  };
}

function isCandidateNode(value: unknown): value is CandidateNode {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const node = value as {readonly kind?: unknown};
  return node.kind === "candidate";
}

/** Register evidence-only commands and return the integration-test API. */
export function activate(context: vscode.ExtensionContext): RigorFoundryApi {
  const store = new EvidenceStore();
  const tree = new EvidenceTreeProvider();
  const output = vscode.window.createOutputChannel("RigorFoundry");
  let reportWatcher: vscode.FileSystemWatcher | undefined;
  let reviewWatcher: vscode.FileSystemWatcher | undefined;
  context.subscriptions.push(
    output,
    vscode.window.registerTreeDataProvider("rigorFoundry.candidates", tree),
    new vscode.Disposable(() => {
      reportWatcher?.dispose();
      reviewWatcher?.dispose();
    }),
  );

  const refresh = (): void => tree.update(store.snapshot());
  const watchEvidenceFile = (file: string, label: string): vscode.FileSystemWatcher => {
    const watcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(path.dirname(file), path.basename(file)),
    );
    const invalidate = (): void => {
      store.clearCanonicalValidation();
      refresh();
      output.appendLine(`${label} changed on disk; canonical validation status was cleared.`);
    };
    watcher.onDidChange(invalidate);
    watcher.onDidCreate(invalidate);
    watcher.onDidDelete(invalidate);
    return watcher;
  };
  const runCommand = (task: (argument?: unknown) => Promise<void>): ((argument?: unknown) => Promise<void>) => {
    return async (argument?: unknown): Promise<void> => {
      try {
        await task(argument);
      } catch (error: unknown) {
        const message = errorMessage(error);
        output.appendLine(message);
        await vscode.window.showErrorMessage(`RigorFoundry: ${message}`);
      }
    };
  };

  const loadReport = async (
    root: string,
    reportPath: string,
    maximumBytes = DEFAULT_MAXIMUM_BYTES,
  ): Promise<void> => {
    const report = await store.loadReport(root, reportPath, maximumBytes);
    reviewWatcher?.dispose();
    reviewWatcher = undefined;
    reportWatcher?.dispose();
    reportWatcher = watchEvidenceFile(reportPath, "Audit report");
    refresh();
    output.appendLine(
      `Loaded report ${report.report_digest} with ${report.candidates.length} candidates. Structural display checks are not canonical CLI validation.`,
    );
  };

  const loadReviews = async (
    root: string,
    reviewPath: string,
    maximumBytes = DEFAULT_MAXIMUM_BYTES,
  ): Promise<void> => {
    const document = await store.loadReviews(root, reviewPath, maximumBytes);
    reviewWatcher?.dispose();
    reviewWatcher = watchEvidenceFile(reviewPath, "Review ledger");
    refresh();
    output.appendLine(
      `Loaded ${document.reviews.length} review records. Run Validate Review Ledger for canonical CLI validation.`,
    );
  };

  context.subscriptions.push(
    vscode.commands.registerCommand(
      "rigorFoundry.loadReport",
      runCommand(async () => {
        const folder = workspaceFolder();
        const config = configuration(folder);
        const selected = await vscode.window.showOpenDialog({
          title: "Load RigorFoundry audit report",
          canSelectMany: false,
          canSelectFiles: true,
          canSelectFolders: false,
          defaultUri: vscode.Uri.file(resolveWorkspacePath(folder.uri.fsPath, config.reportPath)),
          filters: {JSON: ["json"]},
        });
        const uri = selected?.[0];
        if (uri === undefined) {
          return;
        }
        const verified = await verifyExistingWorkspacePath(folder.uri.fsPath, uri.fsPath);
        await loadReport(folder.uri.fsPath, verified, config.maximumEvidenceBytes);
      }),
    ),
    vscode.commands.registerCommand(
      "rigorFoundry.loadReviews",
      runCommand(async () => {
        const folder = workspaceFolder();
        const config = configuration(folder);
        const selected = await vscode.window.showOpenDialog({
          title: "Load RigorFoundry review ledger",
          canSelectMany: false,
          canSelectFiles: true,
          canSelectFolders: false,
          defaultUri: vscode.Uri.file(resolveWorkspacePath(folder.uri.fsPath, config.reviewPath)),
          filters: {JSON: ["json"]},
        });
        const uri = selected?.[0];
        if (uri === undefined) {
          return;
        }
        const verified = await verifyExistingWorkspacePath(folder.uri.fsPath, uri.fsPath);
        await loadReviews(folder.uri.fsPath, verified, config.maximumEvidenceBytes);
      }),
    ),
    vscode.commands.registerCommand(
      "rigorFoundry.scanWorkspace",
      runCommand(async () => {
        const folder = workspaceFolder();
        const root = folder.uri.fsPath;
        const config = configuration(folder);
        const policy = await verifyExistingRegularWorkspacePath(
          root,
          resolveWorkspacePath(root, config.policyPath),
        );
        const report = resolveWorkspacePath(root, config.reportPath);
        await mkdir(path.dirname(report), {recursive: true});
        const reportParent = await verifyExistingWorkspacePath(root, path.dirname(report));
        const reportTarget = path.join(reportParent, path.basename(report));
        output.appendLine(`Running ${config.executable} scan (explicit user command).`);
        const result = await runCli(
          config.executable,
          ["scan", "--root", root, "--policy", policy, "--json-out", reportTarget],
          {cwd: root, timeoutMilliseconds: config.cliTimeoutMilliseconds},
        );
        if (result.stdout.length > 0) {
          output.append(result.stdout);
        }
        if (result.stderr.length > 0) {
          output.append(result.stderr);
        }
        await loadReport(root, reportTarget, config.maximumEvidenceBytes);
        await vscode.window.showInformationMessage("RigorFoundry scan completed; evidence report loaded.");
      }),
    ),
    vscode.commands.registerCommand(
      "rigorFoundry.validateReviews",
      runCommand(async () => {
        const folder = workspaceFolder();
        const root = folder.uri.fsPath;
        const config = configuration(folder);
        const snapshot = store.snapshot();
        if (snapshot.reportPath === undefined || snapshot.reviewPath === undefined) {
          throw new Error("load both the report and review ledger before validation");
        }
        await verifyExistingWorkspacePath(root, snapshot.reportPath);
        await verifyExistingWorkspacePath(root, snapshot.reviewPath);
        const result = await runCli(
          config.executable,
          ["validate-review", "--report", snapshot.reportPath, "--review", snapshot.reviewPath],
          {cwd: root, timeoutMilliseconds: config.cliTimeoutMilliseconds},
        );
        if (result.stdout.length > 0) {
          output.append(result.stdout);
        }
        if (result.stderr.length > 0) {
          output.append(result.stderr);
        }
        await loadReport(root, snapshot.reportPath, config.maximumEvidenceBytes);
        await loadReviews(root, snapshot.reviewPath, config.maximumEvidenceBytes);
        store.markCanonicallyValidated();
        refresh();
        await vscode.window.showInformationMessage("Review ledger passed canonical RigorFoundry CLI validation.");
      }),
    ),
    vscode.commands.registerCommand("rigorFoundry.refresh", refresh),
    vscode.commands.registerCommand(
      "rigorFoundry.openEvidence",
      runCommand(async (rawNode) => {
        if (!isCandidateNode(rawNode)) {
          throw new Error("select a candidate evidence item first");
        }
        const candidate = rawNode.candidate;
        if (candidate.anchor.kind !== "tracked-blob") {
          throw new Error("repository-tree evidence has no single source file to open");
        }
        const folder = workspaceFolder();
        const target = resolveWorkspacePath(folder.uri.fsPath, candidate.anchor.path);
        const verified = await verifyExistingRegularWorkspacePath(folder.uri.fsPath, target);
        const document = await vscode.workspace.openTextDocument(vscode.Uri.file(verified));
        if (
          candidate.anchor.line_start > document.lineCount ||
          candidate.anchor.line_end > document.lineCount
        ) {
          throw new Error("candidate anchor line span exceeds the current source file");
        }
        const editor = await vscode.window.showTextDocument(document);
        const start = new vscode.Position(candidate.anchor.line_start - 1, 0);
        const end = document.lineAt(candidate.anchor.line_end - 1).range.end;
        const range = new vscode.Range(start, end);
        editor.selection = new vscode.Selection(start, start);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
      }),
    ),
    vscode.commands.registerCommand(
      "rigorFoundry.copyCandidateIdentity",
      runCommand(async (rawNode) => {
        if (!isCandidateNode(rawNode)) {
          throw new Error("select a candidate evidence item first");
        }
        const snapshot = store.snapshot();
        const anchor = rawNode.candidate.anchor;
        const identity = [
          `report=${snapshot.report?.report_digest ?? "unknown"}`,
          `candidate=${rawNode.candidate.candidate_id}`,
          `anchor=${anchor.path}:${anchor.line_start}-${anchor.line_end}`,
          anchor.kind === "tracked-blob"
            ? `blob=${anchor.blob_oid}\ncontent_sha256=${anchor.content_sha256}`
            : `tree=${anchor.tree_oid}\ntracked_content_sha256=${anchor.tracked_content_sha256}`,
        ].join("\n");
        await vscode.env.clipboard.writeText(identity);
      }),
    ),
  );

  refresh();
  return {
    getSnapshot: () => store.snapshot(),
    loadReport,
    loadReviews,
  };
}

/** Leave resource disposal to the subscriptions owned by the extension context. */
export function deactivate(): void {
  // VS Code disposes registered resources from the extension context.
}
