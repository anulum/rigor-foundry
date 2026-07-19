// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — real Extension Development Host launcher

import {execFileSync, spawn} from "node:child_process";
import {mkdtemp, mkdir, readFile, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import path from "node:path";
import {fileURLToPath} from "node:url";

const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = await mkdtemp(path.join(tmpdir(), "rigor-vscode-integration-"));
const userData = await mkdtemp(path.join(tmpdir(), "rigor-vscode-user-"));
const extensions = await mkdtemp(path.join(tmpdir(), "rigor-vscode-extensions-"));
const cli = process.env.RIGOR_FOUNDRY_CLI ?? "rigor";
const code = process.env.VSCODE_EXECUTABLE ?? "code";

function run(executable, args, cwd = fixture) {
  execFileSync(executable, args, {cwd, encoding: "utf8", stdio: "pipe", timeout: 120_000});
}

try {
  await mkdir(path.join(fixture, "src"), {recursive: true});
  await mkdir(path.join(fixture, "tests"), {recursive: true});
  await mkdir(path.join(fixture, ".rigor"), {recursive: true});
  await mkdir(path.join(fixture, ".vscode"), {recursive: true});
  await writeFile(path.join(fixture, ".gitignore"), ".rigor/\n", "utf8");
  await writeFile(
    path.join(fixture, "src", "app.py"),
    "def unsafe(user_input: str) -> object:\n    return eval(user_input)\n",
    "utf8",
  );
  await writeFile(
    path.join(fixture, "tests", "test_app.py"),
    "from src.app import unsafe\n\ndef test_literal() -> None:\n    assert unsafe('1') == 1\n",
    "utf8",
  );
  run("git", ["init", "--initial-branch=main"]);
  run("git", ["config", "user.name", "RigorFoundry Integration"]);
  run("git", ["config", "user.email", "integration@example.invalid"]);
  run(cli, [
    "bootstrap",
    "--root", ".",
    "--policy", "rigor-foundry-policy.json",
    "--todo", ".rigor/TODO.md",
    "--review-ledger", ".rigor/reviews.json",
    "--source-root", "src",
    "--test-root", "tests",
  ]);
  run("git", ["add", ".gitignore", "rigor-foundry-policy.json", "src", "tests"]);
  run("git", ["commit", "-m", "test: create extension integration fixture"]);
  run(cli, ["scan", "--root", ".", "--policy", "rigor-foundry-policy.json", "--json-out", ".rigor/report.json"]);
  run(cli, ["review-template", "--report", ".rigor/report.json", "--output", ".rigor/reviews.json"]);
  await rm(path.join(fixture, ".rigor", "report.json"));
  await writeFile(
    path.join(fixture, ".vscode", "settings.json"),
    `${JSON.stringify({
      "rigorFoundry.executable": cli,
      "rigorFoundry.reportPath": ".rigor/report.json",
      "rigorFoundry.reviewPath": ".rigor/reviews.json",
      "rigorFoundry.policyPath": "rigor-foundry-policy.json",
    }, null, 2)}\n`,
    "utf8",
  );

  const detached = process.platform !== "win32";
  const child = spawn(code, [
    "--disable-workspace-trust",
    "--skip-welcome",
    "--skip-release-notes",
    "--disable-telemetry",
    `--user-data-dir=${userData}`,
    `--extensions-dir=${extensions}`,
    `--extensionDevelopmentPath=${extensionRoot}`,
    `--extensionTestsPath=${path.join(extensionRoot, "out", "test", "suite", "index.js")}`,
    fixture,
  ], {
    cwd: extensionRoot,
    detached,
    env: {...process.env, RF_VSCODE_FIXTURE: fixture},
    stdio: "inherit",
  });
  const exitCode = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      if (child.pid !== undefined) {
        try {
          if (detached) {
            process.kill(-child.pid, "SIGKILL");
          } else {
            child.kill("SIGKILL");
          }
        } catch (error) {
          if (!(error instanceof Error && "code" in error && error.code === "ESRCH")) {
            reject(error);
            return;
          }
        }
      }
      reject(new Error("VS Code extension integration tests timed out after 180 seconds"));
    }, 180_000);
    timeout.unref();
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("close", (codeValue) => {
      clearTimeout(timeout);
      resolve(codeValue ?? 1);
    });
  });
  if (exitCode !== 0) {
    throw new Error(`VS Code extension integration tests exited with ${exitCode}`);
  }
  const completion = await readFile(path.join(fixture, ".rigor", "vscode-test-complete"), "utf8");
  if (completion !== "ok\n") {
    throw new Error("VS Code extension integration test did not write its completion proof");
  }
} finally {
  await rm(fixture, {recursive: true, force: true});
  await rm(userData, {recursive: true, force: true});
  await rm(extensions, {recursive: true, force: true});
}
