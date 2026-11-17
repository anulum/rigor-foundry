// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — installed Python launcher build failure diagnostics

/**
 * Exercise the public validation launcher builder with a genuine unseeded Python environment.
 * Preserve the original process refusal and streams without publishing a readiness signal.
 * @module
 */

import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";
import { createEvidenceRepository } from "../support/repository.js";
import { createWindowsValidationBarrier } from "../support/windowsValidationBarrier.js";

void test(
  "retains the actual unseeded Python builder refusal and streams without readiness",
  { timeout: 120_000 },
  async () => {
    const fixture = await createEvidenceRepository();
    const evidence = path.join(fixture.root, ".rigor");
    const environment = await mkdtemp(path.join(evidence, "unseeded-python-"));
    const previous = process.env["RIGOR_FOUNDRY_TEST_PYTHON"];
    const python = previous ?? "python";
    const creation = await runCli(python, ["-m", "venv", "--without-pip", environment], {
      cwd: fixture.root,
      timeoutMilliseconds: 60_000,
    });
    await writeFile(path.join(environment, "creation.stdout"), creation.stdout, "utf8");
    await writeFile(path.join(environment, "creation.stderr"), creation.stderr, "utf8");
    const configuration = await readFile(path.join(environment, "pyvenv.cfg"), "utf8");
    assert.match(configuration, /include-system-site-packages = false/);
    const cleanPython = path.join(
      environment,
      process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
    );
    const cli = process.env["RIGOR_FOUNDRY_CLI"] ?? "rigor";
    let refusal: CommandExecutionFailure | undefined;
    process.env["RIGOR_FOUNDRY_TEST_PYTHON"] = cleanPython;
    try {
      await assert.rejects(
        createWindowsValidationBarrier(fixture.root, cli),
        (error: unknown): boolean => {
          assert.ok(error instanceof CommandExecutionFailure);
          refusal = error;
          return true;
        },
      );
    } finally {
      if (previous === undefined) {
        delete process.env["RIGOR_FOUNDRY_TEST_PYTHON"];
      } else {
        process.env["RIGOR_FOUNDRY_TEST_PYTHON"] = previous;
      }
    }
    assert.ok(refusal);
    assert.match(refusal.message, /exit code 1/);
    assert.match(refusal.output.stderr, /ModuleNotFoundError: No module named 'pip'/);
    const directories = (await readdir(evidence, { withFileTypes: true })).filter(
      (entry) => entry.isDirectory() && entry.name.startsWith("validation-barrier-"),
    );
    assert.equal(directories.length, 1);
    const entry = directories[0];
    assert.ok(entry);
    const directory = path.join(evidence, entry.name);
    assert.equal(
      await readFile(path.join(directory, "builder.stdout"), "utf8"),
      refusal.output.stdout,
    );
    assert.equal(
      await readFile(path.join(directory, "builder.stderr"), "utf8"),
      refusal.output.stderr,
    );
    for (const name of ["canonical-validation.exe", "ready", "release", "trace.json"]) {
      await assert.rejects(stat(path.join(directory, name)), { code: "ENOENT" });
    }
    await writeFile(
      path.join(directory, "builder-refusal-observation.json"),
      JSON.stringify({
        python: cleanPython,
        creationExecutable: python,
        originalErrorName: refusal.name,
        originalErrorMessage: refusal.message,
        stdout: refusal.output.stdout,
        stderr: refusal.output.stderr,
        actualPipImportRefusal: true,
        builderStreamsPreserved: true,
        noLauncherOrReadinessPublished: true,
        environmentRestored: process.env["RIGOR_FOUNDRY_TEST_PYTHON"] === previous,
      }) + "\n",
      "utf8",
    );
  },
);
