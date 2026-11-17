// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — complete launcher failure-retention contracts

/**
 * Exercise both complete launcher entry points with real Git and RigorFoundry adopters.
 * Refuse missing or empty editor executables and verify their actual setup traces.
 * @module
 */

import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";

/**
 * Check complete script boundaries and their retained real adopter repositories.
 * @returns Completion after both launchers reject each invalid executable configuration.
 */
async function run(): Promise<void> {
  const extensionRoot = path.resolve(__dirname, "../../..");
  const sourceRoot =
    process.env["RIGOR_FOUNDRY_SOURCE_ROOT"] ?? path.resolve(extensionRoot, "../..");
  const cli = process.env["RIGOR_FOUNDRY_CLI"] ?? "rigor";
  for (const [name, script, marker, configuration] of [
    [
      "single",
      "run-integration-tests.mjs",
      "RigorFoundry integration evidence retained at ",
      "missing",
    ],
    [
      "workspace",
      "run-workspace-tests.mjs",
      "RigorFoundry multi-root evidence retained at ",
      "missing",
    ],
    [
      "single-empty",
      "run-integration-tests.mjs",
      "RigorFoundry integration evidence retained at ",
      "empty",
    ],
    [
      "workspace-empty",
      "run-workspace-tests.mjs",
      "RigorFoundry multi-root evidence retained at ",
      "empty",
    ],
  ]) {
    assert.ok(name && script && marker && configuration);
    await test("retains actual setup after refused editor: " + name, async (context) => {
      const allocation = await mkdtemp(path.join(tmpdir(), "rigor-launcher-missing-editor-"));
      context.after(async () => {
        await rm(allocation, { recursive: true, force: true });
      });
      const missing = path.join(allocation, "missing-editor");
      await assert.rejects(stat(missing), { code: "ENOENT" });
      const executable = configuration === "empty" ? "" : missing;
      const failure = await runCli(
        process.execPath,
        [path.join(extensionRoot, "scripts", script)],
        {
          cwd: extensionRoot,
          timeoutMilliseconds: 60_000,
          maximumOutputBytes: 2_097_152,
          environment: {
            ...process.env,
            TMPDIR: allocation,
            TMP: allocation,
            TEMP: allocation,
            VSCODE_EXECUTABLE: executable,
            RIGOR_FOUNDRY_CLI: cli,
            RIGOR_FOUNDRY_SOURCE_ROOT: sourceRoot,
          },
        },
      ).then(
        (): never => assert.fail("the absent editor must not produce successful completion"),
        (error: unknown): CommandExecutionFailure => {
          assert.ok(error instanceof CommandExecutionFailure);
          return error;
        },
      );
      assert.equal(failure.message, "RigorFoundry CLI failed with exit code 1");
      assert.ok(!failure.message.includes(missing));
      assert.match(
        failure.output.stderr,
        configuration === "empty" ? /executable must be a non-empty string/u : /ENOENT/u,
      );
      const line = failure.output.stderr.split("\n").find((value) => value.startsWith(marker));
      assert.ok(line);
      const retained = line.slice(marker.length);
      assert.equal(path.dirname(retained), allocation);
      const repositories: string[] = [];
      let stem: string | undefined;
      if (name.startsWith("workspace")) {
        stem = path.join(retained, "workspace-host");
        const args: unknown = JSON.parse(await readFile(stem + ".argv.json", "utf8"));
        assert.ok(typeof args === "object" && args !== null);
        assert.ok("executable" in args && args.executable === executable);
        assert.ok("first" in args && typeof args.first === "string");
        assert.ok("second" in args && typeof args.second === "string");
        repositories.push(args.first, args.second);
      } else {
        const repository = path.join(retained, "workspace");
        repositories.push(repository);
        for (const trace of await readdir(path.join(repository, ".rigor"))) {
          if (!/^process-[0-9]+\.argv\.json$/u.test(trace)) continue;
          const candidate = path.join(repository, ".rigor", trace.slice(0, -10));
          const args: unknown = JSON.parse(await readFile(candidate + ".argv.json", "utf8"));
          assert.ok(typeof args === "object" && args !== null);
          if ("executable" in args && args.executable === executable) stem = candidate;
        }
      }
      assert.ok(stem);
      for (const suffix of [".stdout", ".stderr"]) {
        if (configuration === "empty") {
          await assert.rejects(stat(stem + suffix), { code: "ENOENT" });
        } else {
          assert.equal(await readFile(stem + suffix, "utf8"), "");
        }
      }
      for (const repository of repositories) {
        assert.ok(repository.startsWith(retained + path.sep));
        for (const source of [
          "src/rigor_foundry/git_inventory.py",
          "tests/test_git_inventory.py",
        ]) {
          assert.deepEqual(
            await readFile(path.join(repository, source)),
            await readFile(path.join(sourceRoot, source)),
          );
        }
        const git = await runCli("git", ["rev-parse", "--verify", "HEAD"], {
          cwd: repository,
          timeoutMilliseconds: 5000,
        });
        assert.match(git.stdout, /^[a-f0-9]{40}\n$/u);
        for (const completion of ["vscode-test-complete", "workspace-test-complete"]) {
          await assert.rejects(stat(path.join(repository, ".rigor", completion)), {
            code: "ENOENT",
          });
        }
      }
      await assert.rejects(
        stat(path.join(extensionRoot, "out", "fixtures", path.basename(retained))),
        { code: "ENOENT" },
      );
    });
  }
}
void run();
