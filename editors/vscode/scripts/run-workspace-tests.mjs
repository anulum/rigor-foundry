// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — genuine multi-root workspace test launcher

/**
 * Open two complete production-source adopter repositories in one real editor window.
 * Retain original command output and workspace-owner observations without a substitute host.
 * @module
 */

import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runCli, CommandExecutionFailure } from "#cli";
import { createEvidenceRepository } from "#test-repository";

const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sandbox = await mkdtemp(path.join(tmpdir(), "rigor-workspace-host-"));
const originalTemporaryDirectories = new Map(
  ["TMPDIR", "TEMP", "TMP"].map((key) => [key, process.env[key]]),
);
for (const key of originalTemporaryDirectories.keys()) process.env[key] = sandbox;
try {
  const first = await createEvidenceRepository();
  const second = await createEvidenceRepository();
  const userData = path.join(sandbox, "user-data");
  await mkdir(path.join(userData, "User"), { recursive: true });
  await writeFile(
    path.join(userData, "User", "settings.json"),
    JSON.stringify({
      "chat.disableAIFeatures": true,
      "files.simpleDialog.enable": true,
    }) + "\n",
    "utf8",
  );
  for (const repository of [first, second]) {
    await mkdir(path.join(repository.root, ".vscode"));
    await writeFile(
      path.join(repository.root, ".vscode", "settings.json"),
      JSON.stringify({
        "rigorFoundry.executable": process.env["RIGOR_FOUNDRY_CLI"] ?? "rigor",
        "rigorFoundry.reportPath": ".rigor/report.json",
        "rigorFoundry.reviewPath": ".rigor/reviews.json",
        "rigorFoundry.policyPath": "native-evidence-policy.json",
      }) + "\n",
      "utf8",
    );
  }
  const workspace = path.join(sandbox, "two-repositories.code-workspace");
  await writeFile(
    workspace,
    JSON.stringify({ folders: [{ path: second.root }, { path: first.root }] }) + "\n",
    "utf8",
  );
  const executable = process.env["VSCODE_EXECUTABLE"] ?? "code";
  const args = [
    "--wait",
    "--disable-workspace-trust",
    "--skip-welcome",
    "--skip-release-notes",
    "--disable-telemetry",
    "--disable-gpu",
    "--remote-debugging-port=0",
    "--remote-debugging-address=127.0.0.1",
    "--shared-data-dir=" + path.join(sandbox, "shared-data"),
    "--user-data-dir=" + userData,
    "--extensions-dir=" + path.join(sandbox, "extensions"),
    "--extensionDevelopmentPath=" + extensionRoot,
    "--extensionTestsPath=" +
      path.join(extensionRoot, "out", "test", "suite", "workspace.test.js"),
    workspace,
  ];
  const stem = path.join(sandbox, "workspace-host");
  await writeFile(
    stem + ".argv.json",
    JSON.stringify({ executable, args, first: first.root, second: second.root }) + "\n",
    "utf8",
  );
  try {
    const result = await runCli(executable, args, {
      cwd: extensionRoot,
      timeoutMilliseconds: 180_000,
      maximumOutputBytes: 16_777_216,
      environment: {
        ...process.env,
        RF_VSCODE_WORKSPACE_A: first.root,
        RF_VSCODE_WORKSPACE_B: second.root,
      },
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
  if (
    (await readFile(path.join(first.root, ".rigor", "workspace-test-complete"), "utf8")) !== "ok\n"
  ) {
    throw new Error("multi-root host did not complete its original assertions");
  }
  const artifacts = path.join(extensionRoot, "out", "fixtures", path.basename(sandbox));
  await mkdir(artifacts, { recursive: true });
  await cp(first.root, path.join(artifacts, "workspace-A"), { recursive: true });
  await cp(second.root, path.join(artifacts, "workspace-B"), { recursive: true });
  await cp(path.join(userData, "logs"), path.join(artifacts, "host-logs"), { recursive: true });
  for (const suffix of [".argv.json", ".stdout", ".stderr"]) {
    await cp(stem + suffix, path.join(artifacts, "workspace-host" + suffix));
  }
  await rm(sandbox, { recursive: true, force: true });
  process.stdout.write("RigorFoundry multi-root evidence preserved at " + artifacts + "\n");
} catch (error) {
  process.stderr.write("RigorFoundry multi-root evidence retained at " + sandbox + "\n");
  throw error;
} finally {
  for (const [key, original] of originalTemporaryDirectories) {
    if (original === undefined) Reflect.deleteProperty(process.env, key);
    else process.env[key] = original;
  }
}
