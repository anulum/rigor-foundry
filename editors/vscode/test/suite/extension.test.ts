// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — real command refusal and stale-selection journeys

/**
 * Exercise registered commands against actual empty, partial and replaced evidence states.
 * Retain real output explanations and prove refusal preserves evidence and clipboard.
 * @module
 */

import assert from "node:assert/strict";
import { appendFile, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import * as vscode from "vscode";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";
import type { RigorFoundryApi } from "../../src/extension.js";
import type { CandidateNode } from "../../src/treeView.js";
import { readEvidenceOutput, waitForEvidenceOutput } from "../support/nativeUi.js";

/**
 * Invoke a registered command and retain its actual explanation after state-preservation checks.
 * @param api - Activated public API sharing state with the actual registered command.
 * @param fixture - Owned adopter and native evidence directory.
 * @param caseLabel - Name identifying the real user-visible refusal scenario.
 * @param command - Registered command invoked without replacing its implementation.
 * @param expected - Authored explanation required from the actual output channel.
 * @param argument - Optional public command argument, including deliberately malformed input.
 * @returns Completion after the real command refuses without replacing state or clipboard.
 */
export async function expectCommandRefusal(
  api: RigorFoundryApi,
  fixture: string,
  caseLabel: string,
  command: string,
  expected: string,
  argument?: unknown,
): Promise<void> {
  const before = api.getSnapshot();
  const clipboard = await vscode.env.clipboard.readText();
  const output = await readEvidenceOutput(fixture);
  await vscode.commands.executeCommand(command, argument);
  const added = await waitForEvidenceOutput(fixture, output, expected);
  assert.ok(
    !added.includes("ENOENT"),
    "native diagnostics must stay outside the display explanation",
  );
  assert.deepEqual(api.getSnapshot(), before);
  assert.equal(await vscode.env.clipboard.readText(), clipboard);
  await appendFile(
    path.join(fixture, ".rigor", "native-command-refusals.ndjson"),
    JSON.stringify({
      caseLabel,
      command,
      expected,
      actualOutput: added,
      reportDigest: before.report?.report_digest,
      reportPath: before.reportPath,
      reviewPath: before.reviewPath,
      snapshotPreserved: true,
      clipboardPreserved: true,
    }) + "\n",
    "utf8",
  );
}

/**
 * Check validation before either evidence document has been loaded.
 * @param api - Newly activated extension with its genuine empty store.
 * @param fixture - Actual adopter whose host output records the refusal.
 * @returns Completion after validation explains the missing pair and preserves the empty state.
 */
export async function testEmptyValidation(api: RigorFoundryApi, fixture: string): Promise<void> {
  assert.equal(api.getSnapshot().report, undefined);
  assert.equal(api.getSnapshot().reviewPath, undefined);
  await expectCommandRefusal(
    api,
    fixture,
    "empty-validation",
    "rigorFoundry.validateReviews",
    "load both the report and review ledger before validation",
  );
}

/**
 * Check validation after a report is selected but its ledger is still absent.
 * @param api - Real extension immediately after loading the actual report.
 * @param fixture - Actual adopter whose host output records the refusal.
 * @returns Completion after the partial pair is refused without changing the selected report.
 */
export async function testReportWithoutLedger(
  api: RigorFoundryApi,
  fixture: string,
): Promise<void> {
  assert.ok(api.getSnapshot().report);
  assert.equal(api.getSnapshot().reviewPath, undefined);
  await expectCommandRefusal(
    api,
    fixture,
    "report-only-validation",
    "rigorFoundry.validateReviews",
    "load both the report and review ledger before validation",
  );
}

/**
 * Replace the report through a real alternate-policy scan and reject its old candidate row.
 * @param api - Actual extension with the original report and real ledger loaded.
 * @param fixture - Adopter containing both genuinely bootstrapped, Git-tracked policies.
 * @param sourceRow - Original production-owner row returned by the actual tree provider.
 * @param executable - Actual configured RigorFoundry CLI.
 * @param traceName - Separate retained command traces for successful and refused scans.
 * @returns Completion after stale-row refusal and restoration of the original loaded evidence pair.
 */
async function testStaleSelection(
  api: RigorFoundryApi,
  fixture: string,
  sourceRow: CandidateNode,
  executable: string,
  traceName = "stale-selection-scan",
): Promise<void> {
  const before = api.getSnapshot();
  const reportPath = before.reportPath;
  const reviewPath = before.reviewPath;
  assert.ok(reportPath && reviewPath && before.report);
  assert.equal(sourceRow.candidate.category, "godfile");
  const report = path.join(fixture, ".rigor", "stale-selection-report.json");
  const args = [
    "scan",
    "--root",
    fixture,
    "--policy",
    "stale-selection-policy.json",
    "--json-out",
    report,
  ];
  const stem = path.join(fixture, ".rigor", traceName);
  await writeFile(
    stem + ".argv.json",
    JSON.stringify({ executable, args, cwd: fixture }) + "\n",
    "utf8",
  );
  try {
    const result = await runCli(executable, args, { cwd: fixture, timeoutMilliseconds: 60_000 });
    await writeFile(stem + ".stdout", result.stdout, "utf8");
    await writeFile(stem + ".stderr", result.stderr, "utf8");
  } catch (error: unknown) {
    if (error instanceof CommandExecutionFailure) {
      await writeFile(stem + ".stdout", error.output.stdout, "utf8");
      await writeFile(stem + ".stderr", error.output.stderr, "utf8");
    }
    throw error;
  }
  try {
    await api.loadReport(fixture, report);
    const replacement = api.getSnapshot();
    assert.ok(replacement.report);
    assert.equal(replacement.reviewPath, undefined);
    assert.ok(
      !replacement.report.candidates.some(
        (candidate) => candidate.candidate_id === sourceRow.candidate.candidate_id,
      ),
    );
    await expectCommandRefusal(
      api,
      fixture,
      "actual-stale-row",
      "rigorFoundry.copyCandidateIdentity",
      "select a candidate from the currently loaded report",
      sourceRow,
    );
  } finally {
    await api.loadReport(fixture, reportPath);
    await api.loadReviews(fixture, reviewPath);
  }
  assert.deepEqual(api.getSnapshot(), before);
}

/**
 * Exercise actual command and scan refusals, retaining separate failed-scan diagnostics.
 * @param api - Activated extension sharing state with registered commands.
 * @param fixture - Owned workspace containing the loaded report and ledger.
 * @param sourceRow - Genuine production-owner row from the original CLI report.
 * @returns Completion after authored explanations, preserved state and restored settings/evidence.
 */
export async function testCommandRefusals(
  api: RigorFoundryApi,
  fixture: string,
  sourceRow: CandidateNode,
): Promise<void> {
  await expectCommandRefusal(
    api,
    fixture,
    "missing-selection",
    "rigorFoundry.copyCandidateIdentity",
    "select a candidate evidence item first",
  );
  await expectCommandRefusal(
    api,
    fixture,
    "malformed-selection",
    "rigorFoundry.copyCandidateIdentity",
    "select a candidate evidence item first",
    { kind: "candidate", candidate: null },
  );
  await expectCommandRefusal(
    api,
    fixture,
    "missing-candidate-identity",
    "rigorFoundry.copyCandidateIdentity",
    "select a candidate evidence item first",
    { kind: "candidate", candidate: {} },
  );

  const config = vscode.workspace.getConfiguration("rigorFoundry", vscode.Uri.file(fixture));
  const executable = config.get<string>("executable");
  const policyPath = config.get<string>("policyPath");
  assert.ok(typeof executable === "string" && typeof policyPath === "string");
  const originalPolicy = await readFile(path.join(fixture, policyPath));
  await config.update(
    "executable",
    path.join(fixture, ".rigor", "absent-executable"),
    vscode.ConfigurationTarget.WorkspaceFolder,
  );
  try {
    await expectCommandRefusal(
      api,
      fixture,
      "missing-executable",
      "rigorFoundry.scanWorkspace",
      "RigorFoundry CLI could not be started",
    );
  } finally {
    await config.update("executable", executable, vscode.ConfigurationTarget.WorkspaceFolder);
  }
  await config.update(
    "policyPath",
    ".rigor/absent-policy.json",
    vscode.ConfigurationTarget.WorkspaceFolder,
  );
  try {
    await expectCommandRefusal(
      api,
      fixture,
      "missing-policy",
      "rigorFoundry.scanWorkspace",
      "operation failed; verify the workspace, evidence files, and configured executable",
    );
  } finally {
    await config.update("policyPath", policyPath, vscode.ConfigurationTarget.WorkspaceFolder);
  }
  const stalePolicy = path.join(fixture, "stale-selection-policy.json");
  const stalePolicyBytes = await readFile(stalePolicy);
  const beforeRefusal = api.getSnapshot();
  let scanRefusal: CommandExecutionFailure | undefined;
  await writeFile(stalePolicy, "{\n", "utf8");
  try {
    await assert.rejects(
      testStaleSelection(api, fixture, sourceRow, executable, "stale-selection-policy-refusal"),
      (error: unknown): boolean => {
        assert.ok(error instanceof CommandExecutionFailure);
        assert.equal(error.message, "RigorFoundry CLI failed with exit code 2");
        scanRefusal = error;
        return true;
      },
    );
  } finally {
    await writeFile(stalePolicy, stalePolicyBytes);
  }
  assert.ok(scanRefusal);
  assert.deepEqual(api.getSnapshot(), beforeRefusal);
  assert.deepEqual(await readFile(stalePolicy), stalePolicyBytes);
  const refusedStem = path.join(fixture, ".rigor", "stale-selection-policy-refusal");
  assert.equal(await readFile(refusedStem + ".stdout", "utf8"), scanRefusal.output.stdout);
  assert.equal(await readFile(refusedStem + ".stderr", "utf8"), scanRefusal.output.stderr);
  assert.match(
    scanRefusal.output.stderr,
    /^repository audit error: cannot parse audit policy JSON\r?\n$/u,
  );
  await writeFile(
    refusedStem + ".observation.json",
    JSON.stringify({
      actualExitCode: 2,
      stdout: scanRefusal.output.stdout,
      stderr: scanRefusal.output.stderr,
      snapshotPreserved: true,
      policyRestored: true,
      commandStreamsRetained: true,
    }) + "\n",
    "utf8",
  );
  await testStaleSelection(api, fixture, sourceRow, executable);
  assert.deepEqual(await readFile(path.join(fixture, policyPath)), originalPolicy);
}
