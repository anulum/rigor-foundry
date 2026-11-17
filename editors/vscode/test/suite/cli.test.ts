// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — real registered validation completion races

/**
 * Pause an actual successful canonical CLI before its registered command completes.
 * Change real evidence or selection and require refusal without overwriting newer state.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  access,
  appendFile,
  copyFile,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import * as vscode from "vscode";
import type { RigorFoundryApi } from "../../src/extension.js";
import { createEvidenceRepository, createPosixValidationBarrier } from "../support/repository.js";

/**
 * Wait for the owned delegating process to publish genuine canonical CLI success.
 * @param file - Exclusive ready file written after the actual CLI exits successfully.
 * @returns Completion after checking the process's published success marker.
 */
async function waitForValidation(file: string): Promise<void> {
  const cancellation = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      reject,
      20_000,
      new assert.AssertionError({
        message: "real canonical CLI did not reach its completion barrier",
        operator: "fail",
      }),
    );
  });
  const poll = async (): Promise<void> => {
    for (;;) {
      cancellation.signal.throwIfAborted();
      const files = await readdir(path.dirname(file));
      cancellation.signal.throwIfAborted();
      if (files.includes(path.basename(file))) {
        assert.equal(
          await readFile(file, { encoding: "utf8", signal: cancellation.signal }),
          "validated\n",
        );
        return;
      }
      await delay(25, undefined, { signal: cancellation.signal });
    }
  };
  try {
    await Promise.race([expired, poll()]);
  } finally {
    clearTimeout(timer);
    cancellation.abort();
  }
}

/**
 * Observe actual fixture creation through the editor's ordered filesystem request channel.
 * Queue writes after watcher registration and verify disk bytes before canonical selection.
 * @param directory - Existing owned directory watched by the actual extension host.
 * @param reportBytes - Unchanged canonical report bytes for the case.
 * @param reviewBytes - Unchanged canonical review bytes for the case.
 * @returns Completion after both real file-creation events have been delivered.
 */
export async function writeObservedEvidencePair(
  directory: string,
  reportBytes: Buffer,
  reviewBytes: Buffer,
): Promise<void> {
  const reportPath = path.join(directory, "report.json");
  const reviewPath = path.join(directory, "reviews.json");
  const remaining = new Set([reportPath, reviewPath].map((file) => vscode.Uri.file(file).fsPath));
  const watcher = vscode.workspace.createFileSystemWatcher(
    new vscode.RelativePattern(directory, "*.json"),
  );
  let subscription: vscode.Disposable | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const observed = new Promise<void>((resolve, reject) => {
    timer = setTimeout(
      reject,
      5000,
      new Error("evidence fixture creation events were not observed"),
    );
    subscription = watcher.onDidCreate((uri) => {
      remaining.delete(uri.fsPath);
      if (remaining.size === 0) resolve();
    });
  });
  try {
    const written = (async (): Promise<void> => {
      await vscode.workspace.fs.writeFile(vscode.Uri.file(reportPath), reportBytes);
      await vscode.workspace.fs.writeFile(vscode.Uri.file(reviewPath), reviewBytes);
      assert.deepEqual(await readFile(reportPath), reportBytes);
      assert.deepEqual(await readFile(reviewPath), reviewBytes);
    })();
    await Promise.all([observed, written]);
  } finally {
    clearTimeout(timer);
    subscription?.dispose();
    watcher.dispose();
  }
}

/**
 * Exercise byte changes, new report selection, identical ledger reload and owner replacement.
 * @param api - Actual activated extension sharing state with registered commands.
 * @param fixture - Current real adopter repository, containing its accepted report and ledger.
 * @returns Completion after all registered commands refuse stale success and preserve new state.
 */
export async function testValidationRaces(api: RigorFoundryApi, fixture: string): Promise<void> {
  const original = api.getSnapshot();
  const originalReportPath = original.reportPath;
  const originalReviewPath = original.reviewPath;
  assert.ok(originalReportPath && originalReviewPath);
  const reportBytes = await readFile(originalReportPath);
  const reviewBytes = await readFile(originalReviewPath);
  const config = vscode.workspace.getConfiguration("rigorFoundry", vscode.Uri.file(fixture));
  const cli = config.get<string>("executable");
  assert.ok(cli);
  const other = await createEvidenceRepository();
  const observations: unknown[] = [];
  try {
    for (const scenario of [
      "review-bytes",
      "report-bytes",
      "report-selection",
      "ledger-selection",
      "owner-selection",
    ]) {
      const directory = await mkdtemp(path.join(fixture, ".rigor", "validation-case-"));
      const reportPath = path.join(directory, "report.json");
      const reviewPath = path.join(directory, "reviews.json");
      await writeObservedEvidencePair(directory, reportBytes, reviewBytes);
      await api.loadReport(fixture, reportPath);
      await api.loadReviews(fixture, reviewPath);
      const barrier = await createPosixValidationBarrier(fixture, cli);
      await config.update(
        "executable",
        barrier.executable,
        vscode.ConfigurationTarget.WorkspaceFolder,
      );
      const ready = waitForValidation(barrier.readyPath);
      const pending = vscode.commands.executeCommand("rigorFoundry.validateReviews");
      try {
        await ready;
        const trace: unknown = JSON.parse(await readFile(barrier.tracePath, "utf8"));
        assert.ok(typeof trace === "object" && trace !== null);
        assert.ok("status" in trace && trace.status === 0);
        assert.ok("signal" in trace && trace.signal === null);
        assert.ok("executable" in trace && trace.executable === cli);
        if (process.platform === "win32") {
          const pythonExecutable = process.env["RIGOR_FOUNDRY_TEST_PYTHON"];
          assert.ok(pythonExecutable);
          assert.ok(
            "nativeConsolePE" in trace &&
              typeof trace.nativeConsolePE === "string" &&
              trace.nativeConsolePE.endsWith(".exe"),
          );
          assert.ok(
            "pythonExecutable" in trace &&
              path.normalize(String(trace.pythonExecutable)) === path.normalize(pythonExecutable),
          );
          assert.ok("reportSecurity" in trace && typeof trace.reportSecurity === "string");
          assert.ok("reviewSecurity" in trace && typeof trace.reviewSecurity === "string");
          assert.ok("directorySecurity" in trace && typeof trace.directorySecurity === "string");
          const reportAcl = /^O:(S-1-(?:\d+-)*\d+)D:P\(A;;FR;;;\1\)$/u.exec(trace.reportSecurity);
          assert.ok(
            reportAcl,
            "private report must have an actual protected current-owner read-only DACL",
          );
          assert.equal(trace.reviewSecurity, trace.reportSecurity);
          assert.equal(trace.directorySecurity, trace.reportSecurity.replace(";;FR;", ";;FA;"));
        } else {
          assert.ok("nodeVersion" in trace && trace.nodeVersion === "v22.23.3");
          assert.ok("reportMode" in trace && trace.reportMode === 0o400);
          assert.ok("reviewMode" in trace && trace.reviewMode === 0o400);
          assert.ok("directoryMode" in trace && trace.directoryMode === 0o700);
        }
        assert.ok("reportPath" in trace && typeof trace.reportPath === "string");
        assert.ok("reviewPath" in trace && typeof trace.reviewPath === "string");
        assert.ok("reportSha256" in trace);
        assert.ok("reviewSha256" in trace);
        assert.equal(trace.reportSha256, createHash("sha256").update(reportBytes).digest("hex"));
        assert.equal(trace.reviewSha256, createHash("sha256").update(reviewBytes).digest("hex"));
        assert.notEqual(trace.reportPath, reportPath);
        assert.notEqual(trace.reviewPath, reviewPath);

        if (scenario === "review-bytes") {
          await appendFile(reviewPath, "\n", "utf8");
        } else if (scenario === "report-bytes") {
          await appendFile(reportPath, "\n", "utf8");
        } else if (scenario === "report-selection") {
          const replacement = path.join(directory, "newer-selected-report.json");
          await copyFile(reportPath, replacement);
          await api.loadReport(fixture, replacement);
          await api.loadReviews(fixture, reviewPath);
        } else if (scenario === "ledger-selection") {
          await api.loadReviews(fixture, reviewPath);
        } else {
          await api.loadReport(other.root, other.reportPath);
        }
        const selected = api.getSnapshot();
        assert.equal(selected.canonicallyValidated, false);
        await writeFile(barrier.releasePath, "release\n", "utf8");
        await pending;
        assert.deepEqual(api.getSnapshot(), selected);
        assert.equal(api.getSnapshot().canonicallyValidated, false);
        await assert.rejects(access(trace.reportPath), { code: "ENOENT" });
        await assert.rejects(access(trace.reviewPath), { code: "ENOENT" });
        observations.push({ scenario, actualCli: trace, selected, preserved: true });
      } finally {
        await writeFile(barrier.releasePath, "release\n", "utf8");
        await pending;
        await config.update("executable", cli, vscode.ConfigurationTarget.WorkspaceFolder);
        await api.loadReport(fixture, originalReportPath);
        await api.loadReviews(fixture, originalReviewPath);
        await rm(directory, { recursive: true, force: true });
      }
    }
    assert.equal(observations.length, 5);
    await writeFile(
      path.join(fixture, ".rigor", "native-validation-races.json"),
      JSON.stringify(observations, null, 2) + "\n",
      "utf8",
    );
  } finally {
    await api.loadReport(fixture, originalReportPath);
    await api.loadReviews(fixture, originalReviewPath);
    await rm(other.root, { recursive: true, force: true });
  }
}

/**
 * Run only this explicit registered-command race qualification in a real Extension Host.
 * @returns Completion after actual assertions and the dedicated completion proof.
 */
export async function run(): Promise<void> {
  const fixture = process.env["RF_VSCODE_FIXTURE"];
  assert.ok(fixture);
  const extension = vscode.extensions.getExtension<RigorFoundryApi>("anulum.rigor-foundry-vscode");
  assert.ok(extension);
  const api = await extension.activate();
  await api.loadReport(fixture, path.join(fixture, ".rigor", "report.json"));
  await api.loadReviews(fixture, path.join(fixture, ".rigor", "reviews.json"));
  await testValidationRaces(api, fixture);
  await vscode.commands.executeCommand("rigorFoundry.validateReviews");
  assert.equal(api.getSnapshot().canonicallyValidated, true);
  await writeFile(path.join(fixture, ".rigor", "vscode-validation-complete"), "ok\n", "utf8");
}
