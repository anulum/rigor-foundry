// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — configured CLI diagnostics in the actual evidence output

/**
 * Exercise registered scan and validation commands through a genuine canonical CLI launcher.
 * Require both actual process streams in the output channel and preserve the loaded evidence pair.
 * @module
 */

import assert from "node:assert/strict";
import { once } from "node:events";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import * as vscode from "vscode";
import { runCli } from "../../src/cli.js";
import type { RigorFoundryApi } from "../../src/extension.js";
import { createDiagnosticCli } from "../support/diagnosticCli.js";
import { readEvidenceOutput, waitForEvidenceOutput } from "../support/nativeUi.js";

/**
 * Check actual stdout and stderr passthrough from successful configured CLI commands.
 * @param api - Activated production extension sharing state with the registered commands.
 * @param fixture - Real Git adopter whose report and ledger are produced by the canonical CLI.
 * @returns Completion after actual diagnostics, canonical results, settings and evidence restoration.
 */
export async function testCommandOutput(api: RigorFoundryApi, fixture: string): Promise<void> {
  const before = api.getSnapshot();
  assert.ok(before.reportPath && before.reviewPath && before.report);
  const ledgerBytes = await readFile(before.reviewPath);
  const config = vscode.workspace.getConfiguration("rigorFoundry", vscode.Uri.file(fixture));
  const cli = config.get<string>("executable");
  const reportPath = config.get<string>("reportPath");
  assert.equal(typeof cli, "string");
  assert.ok(cli);
  assert.ok(typeof reportPath === "string" && reportPath.length > 0);
  const originalReport = path.resolve(fixture, reportPath);
  const originalReportBytes = await readFile(originalReport);
  const launcher = await createDiagnosticCli(fixture, cli);
  const freshReport = path.join(launcher.directory, "report.json");
  const freshLedger = path.join(launcher.directory, "reviews.json");
  const observations: unknown[] = [];
  try {
    await config.update(
      "reportPath",
      path.relative(fixture, freshReport),
      vscode.ConfigurationTarget.WorkspaceFolder,
    );
    await config.update(
      "executable",
      launcher.executable,
      vscode.ConfigurationTarget.WorkspaceFolder,
    );
    for (const operation of ["scan", "validate-review"]) {
      if (operation === "validate-review") {
        const args = ["review-template", "--report", freshReport, "--output", freshLedger];
        const stem = path.join(launcher.directory, "review-template");
        await writeFile(
          stem + ".argv.json",
          JSON.stringify({ executable: cli, args, cwd: fixture }) + "\n",
          "utf8",
        );
        const notification = new EventTarget();
        const observed = once(notification, "created", { signal: AbortSignal.timeout(5000) });
        const watcher = vscode.workspace.createFileSystemWatcher(
          new vscode.RelativePattern(launcher.directory, "reviews.json"),
        );
        const created: string[] = [];
        const subscription = watcher.onDidCreate((uri) => {
          created.push(uri.fsPath);
          notification.dispatchEvent(new Event("created"));
        });
        try {
          const [, template] = await Promise.all([
            observed,
            runCli(cli, args, { cwd: fixture, timeoutMilliseconds: 60_000 }),
          ]);
          await writeFile(stem + ".stdout", template.stdout, "utf8");
          await writeFile(stem + ".stderr", template.stderr, "utf8");
          assert.ok(created.includes(vscode.Uri.file(freshLedger).fsPath));
          await writeFile(stem + ".created-events.json", JSON.stringify(created) + "\n", "utf8");
        } finally {
          subscription.dispose();
          watcher.dispose();
        }
        await api.loadReviews(fixture, freshLedger);
      }
      const output = await readEvidenceOutput(fixture);
      const command =
        operation === "scan" ? "rigorFoundry.scanWorkspace" : "rigorFoundry.validateReviews";
      await vscode.commands.executeCommand(command);
      assert.equal(api.getSnapshot().reportPath, freshReport);
      assert.equal(api.getSnapshot().canonicallyValidated, operation === "validate-review");
      const added = await waitForEvidenceOutput(
        fixture,
        output,
        "configured CLI launcher stderr: " + operation,
      );
      assert.ok(added.includes("configured CLI launcher stdout: " + operation));
      const record: unknown = JSON.parse(
        await readFile(path.join(launcher.directory, operation + ".json"), "utf8"),
      );
      assert.ok(typeof record === "object" && record !== null);
      assert.ok("status" in record && record.status === 0);
      assert.ok("canonicalExecutable" in record && record.canonicalExecutable === cli);
      assert.ok("args" in record && Array.isArray(record.args) && record.args[0] === operation);
      assert.ok("launcherStdout" in record && typeof record.launcherStdout === "string");
      assert.ok("launcherStderr" in record && typeof record.launcherStderr === "string");
      assert.ok(added.includes(record.launcherStdout));
      assert.ok(added.includes(record.launcherStderr));
      const report: unknown = JSON.parse(await readFile(freshReport, "utf8"));
      assert.ok(typeof report === "object" && report !== null && "report_digest" in report);
      assert.equal(api.getSnapshot().report?.report_digest, report.report_digest);
      assert.notEqual(report.report_digest, before.report.report_digest);
      assert.ok("dirty_paths" in report && Array.isArray(report.dirty_paths));
      assert.ok(report.dirty_paths.includes(".vscode/settings.json"));
      assert.equal(api.getSnapshot().canonicallyValidated, operation === "validate-review");
      observations.push({ command, record, actualEvidenceOutput: added });
    }
  } finally {
    await config.update("executable", cli, vscode.ConfigurationTarget.WorkspaceFolder);
    await config.update("reportPath", reportPath, vscode.ConfigurationTarget.WorkspaceFolder);
    await api.loadReport(fixture, before.reportPath);
    await api.loadReviews(fixture, before.reviewPath);
  }
  assert.equal(config.get<string>("executable"), cli);
  assert.equal(config.get<string>("reportPath"), reportPath);
  assert.deepEqual(api.getSnapshot(), before);
  assert.deepEqual(await readFile(before.reviewPath), ledgerBytes);
  assert.deepEqual(await readFile(originalReport), originalReportBytes);
  await writeFile(
    path.join(launcher.directory, "registered-command-output-observations.json"),
    JSON.stringify({
      observations,
      settingsRestored: true,
      snapshotRestored: true,
      ledgerPreserved: true,
    }) + "\n",
    "utf8",
  );
}
