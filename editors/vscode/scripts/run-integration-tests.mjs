// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — real Extension Development Host launcher

/**
 * Build a real production-source adopter fixture and execute the native extension host.
 * Retain bounded process traces and failed workspaces; preserve successful evidence before cleanup.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CommandExecutionFailure, runCli } from "#cli";

const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot =
  process.env["RIGOR_FOUNDRY_SOURCE_ROOT"] ?? path.resolve(extensionRoot, "../..");
const sandbox = await mkdtemp(path.join(tmpdir(), "rigor-vscode-integration-"));
const fixture = path.join(sandbox, "workspace");
const userData = path.join(sandbox, "user-data");
const extensions = path.join(sandbox, "extensions");
const artifactRoot = path.join(extensionRoot, "out", "fixtures", path.basename(sandbox));
const cli = process.env["RIGOR_FOUNDRY_CLI"] ?? "rigor";
const code = process.env["VSCODE_EXECUTABLE"] ?? "code";
let sequence = 0;
let succeeded = false;

/**
 * Execute one real process with bounded output, a deadline, and close-before-settlement semantics.
 * @param {string} executable - Actual Git, RigorFoundry, or VS Code program.
 * @param {string[]} args - Separate literal arguments passed without a shell.
 * @param {string} [cwd] - Existing working directory, defaulting to the owned adopter fixture.
 * @param {number} [timeoutMilliseconds] - Deadline, defaulting to sixty seconds for setup commands.
 * @param {Record<string, string | undefined>} [environment] - Complete child environment without changing the parent.
 * @returns {Promise<void>} Completion after traces have been saved for a successful closed process.
 */
async function run(
  executable,
  args,
  cwd = fixture,
  timeoutMilliseconds = 60_000,
  environment = process.env,
) {
  sequence += 1;
  const stem = path.join(fixture, ".rigor", "process-" + String(sequence));
  await writeFile(
    stem + ".argv.json",
    JSON.stringify({
      executable,
      args,
      cwd,
      timeoutMilliseconds,
    }) + "\n",
    "utf8",
  );
  try {
    const result = await runCli(executable, args, {
      cwd,
      timeoutMilliseconds,
      environment,
      maximumOutputBytes: 16_777_216,
    });
    await writeFile(stem + ".stdout", result.stdout, "utf8");
    await writeFile(stem + ".stderr", result.stderr, "utf8");
  } catch (error) {
    if (error instanceof CommandExecutionFailure) {
      await writeFile(stem + ".stdout", error.output.stdout, "utf8");
      await writeFile(stem + ".stderr", error.output.stderr, "utf8");
    }
    throw error;
  }
}

try {
  await mkdir(path.join(fixture, "src", "rigor_foundry"), { recursive: true });
  await mkdir(path.join(fixture, "tests"));
  await mkdir(path.join(fixture, ".rigor"));
  await mkdir(path.join(fixture, ".vscode"));
  await mkdir(userData);
  await mkdir(path.join(userData, "User"));
  await writeFile(
    path.join(userData, "User", "settings.json"),
    JSON.stringify(
      {
        "chat.disableAIFeatures": true,
        "files.simpleDialog.enable": true,
        "window.title": "RigorFoundry Native Test Host",
      },
      null,
      2,
    ) + "\n",
    "utf8",
  );
  await mkdir(extensions);
  await writeFile(path.join(fixture, ".gitignore"), ".rigor/\n", "utf8");
  /**
   * Exact identities of the complete source and original test files copied for the host run.
   * @type {{path: string, bytes: number, sha256: string}[]}
   */
  const sourcePins = [];
  for (const relative of ["src/rigor_foundry/git_inventory.py", "tests/test_git_inventory.py"]) {
    const bytes = await readFile(path.join(sourceRoot, relative));
    await writeFile(path.join(fixture, relative), bytes);
    sourcePins.push({
      path: relative,
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  }
  await writeFile(
    path.join(fixture, ".rigor", "production-source-pins.json"),
    JSON.stringify(
      {
        sourceRoot,
        sourcePins,
      },
      null,
      2,
    ) + "\n",
    "utf8",
  );
  await writeFile(
    path.join(fixture, ".vscode", "settings.json"),
    JSON.stringify(
      {
        "rigorFoundry.executable": cli,
        "rigorFoundry.reportPath": ".rigor/report.json",
        "rigorFoundry.reviewPath": ".rigor/reviews.json",
        "rigorFoundry.policyPath": "rigor-foundry-policy.json",
      },
      null,
      2,
    ) + "\n",
    "utf8",
  );

  await run("git", ["init", "--initial-branch=main"]);
  await run("git", ["config", "user.name", "RigorFoundry Integration"]);
  await run("git", ["config", "user.email", "integration@example.invalid"]);
  await run("git", ["config", "commit.gpgsign", "false"]);
  await run(cli, [
    "bootstrap",
    "--root",
    ".",
    "--policy",
    "rigor-foundry-policy.json",
    "--todo",
    ".rigor/TODO.md",
    "--review-ledger",
    ".rigor/reviews.json",
    "--source-root",
    "src",
    "--test-root",
    "tests",
    "--source-line-threshold",
    "500",
  ]);
  const sourceLineCeiling = (
    await readFile(path.join(fixture, "src", "rigor_foundry", "git_inventory.py"), "utf8")
  ).split("\n").length;
  await run(cli, [
    "bootstrap",
    "--root",
    ".",
    "--policy",
    "stale-selection-policy.json",
    "--todo",
    ".rigor/stale-selection-TODO.md",
    "--review-ledger",
    ".rigor/stale-selection-reviews.json",
    "--source-root",
    "src",
    "--test-root",
    "tests",
    "--source-line-threshold",
    String(sourceLineCeiling),
  ]);
  await run("git", [
    "add",
    ".gitignore",
    "rigor-foundry-policy.json",
    "stale-selection-policy.json",
    "src",
    "tests",
  ]);
  await run("git", ["add", "--force", ".vscode/settings.json"]);
  await run("git", [
    "commit",
    "-m",
    "test: capture complete production owner for extension integration",
  ]);
  await run(cli, [
    "scan",
    "--root",
    ".",
    "--policy",
    "rigor-foundry-policy.json",
    "--json-out",
    ".rigor/report.json",
  ]);
  await run(cli, [
    "review-template",
    "--report",
    ".rigor/report.json",
    "--output",
    ".rigor/reviews.json",
  ]);
  await cp(
    path.join(fixture, ".rigor", "report.json"),
    path.join(fixture, ".rigor", "initial-report.json"),
  );
  await rm(path.join(fixture, ".rigor", "report.json"));
  const emptyWindow = path.join(sandbox, "empty-window");
  const emptyWorkspace = path.join(emptyWindow, "workspace");
  const emptyUserData = path.join(emptyWindow, "user-data");
  await cp(fixture, emptyWorkspace, { recursive: true });
  await rm(path.join(emptyWorkspace, ".rigor", "initial-report.json"));
  await cp(userData, emptyUserData, { recursive: true });
  await run(
    cli,
    [
      "scan",
      "--root",
      ".",
      "--policy",
      "rigor-foundry-policy.json",
      "--json-out",
      ".rigor/initial-report.json",
    ],
    emptyWorkspace,
  );
  const hostArgs = [
    "--wait",
    "--disable-workspace-trust",
    "--skip-welcome",
    "--skip-release-notes",
    "--disable-telemetry",
    "--disable-gpu",
    "--remote-debugging-port=0",
    "--remote-debugging-address=127.0.0.1",
    "--extensionDevelopmentPath=" + extensionRoot,
    "--extensionTestsPath=" + path.join(extensionRoot, "out", "test", "suite", "index.js"),
  ];
  await run(
    code,
    [
      ...hostArgs,
      "--shared-data-dir=" + path.join(emptyWindow, "shared-data"),
      "--user-data-dir=" + emptyUserData,
      "--extensions-dir=" + path.join(emptyWindow, "extensions"),
      "--new-window",
    ],
    extensionRoot,
    60_000,
    { ...process.env, RF_VSCODE_FIXTURE: emptyWorkspace, RF_VSCODE_EMPTY_WINDOW: "1" },
  );
  const refusals = path.join(emptyWorkspace, ".rigor", "native-command-refusals.ndjson");
  const emptyCompletion = path.join(emptyWorkspace, ".rigor", "empty-window-test-complete");
  assert.equal(await readFile(emptyCompletion, "utf8"), "ok\n");
  await run(
    code,
    [
      ...hostArgs,
      "--shared-data-dir=" + path.join(sandbox, "shared-data"),
      "--user-data-dir=" + userData,
      "--extensions-dir=" + extensions,
      fixture,
    ],
    extensionRoot,
    180_000,
    { ...process.env, RF_VSCODE_FIXTURE: fixture, RF_VSCODE_EMPTY_WINDOW: "0" },
  );

  const completion = await readFile(path.join(fixture, ".rigor", "vscode-test-complete"), "utf8");
  if (completion !== "ok\n") {
    throw new Error("VS Code extension integration test did not write its completion proof");
  }
  await mkdir(artifactRoot, { recursive: true });
  await cp(fixture, path.join(artifactRoot, "workspace"), { recursive: true });
  await cp(refusals, path.join(artifactRoot, "empty-window-refusals.ndjson"));
  await cp(emptyCompletion, path.join(artifactRoot, "empty-window-test-complete"));
  await cp(path.join(userData, "logs"), path.join(artifactRoot, "user-data-logs"), {
    recursive: true,
  });
  succeeded = true;
} finally {
  if (succeeded) {
    await rm(sandbox, { recursive: true, force: true });
  } else {
    process.stderr.write("RigorFoundry integration evidence retained at " + sandbox + "\n");
  }
}
