// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — actual native image selection and configuration refusals

/**
 * Exercise the original native entrypoint with complete copied runtime files and actual libraries.
 * Check pre-initializer configuration refusals and the standard installed dependency image guard.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, unlink, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";

void test("checks native binding configuration before accepting the actual image", async () => {
  const source = path.resolve(__dirname, "../../..");
  const fixtures = path.join(source, "out", "fixtures");
  await mkdir(fixtures, { recursive: true });
  const allocation = await mkdtemp(path.join(fixtures, "rigor-native-image-"));
  if (process.platform !== "win32") {
    await assert.rejects(
      runCli(
        process.execPath,
        ["-e", "require(process.argv[1])", path.join(source, "out/src/windowsAbi.js")],
        {
          cwd: source,
          timeoutMilliseconds: 10_000,
        },
      ),
      (error: unknown): boolean => {
        assert.ok(error instanceof CommandExecutionFailure);
        assert.match(
          error.output.stderr,
          /native Windows resources require a qualified Windows x64 host/,
        );
        return true;
      },
    );
    return;
  }
  const originalRequire = createRequire(path.join(source, "package.json"));
  const npmEntry = originalRequire.resolve("@koromix/koffi-win32-x64");
  const npmImage = path.join(path.dirname(npmEntry), "win32_x64/koffi.node");
  const npmBytes = await readFile(npmImage);
  const ownedBytes = await readFile(
    path.join(source, "native/koffi/build/koffi/win32_x64/koffi.node"),
  );
  assert.notDeepEqual(npmBytes, ownedBytes);
  const driver = path.join(allocation, "observe.cjs");
  await writeFile(
    driver,
    [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      'const { createRequire } = require("node:module");',
      'const { createHash } = require("node:crypto");',
      "const [root, record, warm] = process.argv.slice(2);",
      'const load = createRequire(path.join(root, "package.json"));',
      'const images = () => Object.keys(require.cache).filter(name => path.basename(name) === "koffi.node").map(name => fs.realpathSync.native(name));',
      "try {",
      '  if (warm === "npm") load("koffi");',
      '  const abi = load("./out/src/windowsAbi.js");',
      "  const processHandle = abi.nativePointer(abi.getCurrentProcess());",
      '  if (typeof processHandle !== "bigint") throw new Error("actual process pseudo handle is unavailable");',
      '  const native = path.join(root, "native/koffi");',
      '  const resolved = createRequire(path.join(native, "src/koffi/src/static.cjs")).resolve("@koromix/koffi-win32-x64");',
      '  fs.writeFileSync(record, JSON.stringify({ resolved: fs.realpathSync.native(resolved), sha256: createHash("sha256").update(fs.readFileSync(resolved)).digest("hex"), images: images(), processHandle: String(processHandle), version: abi.koffi.version }) + "\\n");',
      "} catch (error) {",
      '  fs.writeFileSync(record, JSON.stringify({ refusal: String(error), images: images() }) + "\\n");',
      "  console.error(error);",
      "  process.exitCode = 1;",
      "}",
    ].join("\n"),
    "utf8",
  );
  const refusals: Record<string, RegExp> = {
    "missing-metadata": /ENOENT/,
    "different-export": /native binding resolves another image/,
    "cached-npm": /another native Koffi image was loaded/,
  };
  for (const scenario of ["valid", "missing-metadata", "different-export", "cached-npm"]) {
    const root = path.join(allocation, scenario);
    await mkdir(root);
    for (const directory of ["src", "out/src", "native/koffi"]) {
      const destination = path.join(root, directory);
      await mkdir(path.dirname(destination), { recursive: true });
      await cp(path.join(source, directory), destination, {
        recursive: true,
        errorOnExist: true,
        force: false,
      });
    }
    await cp(path.join(source, "package.json"), path.join(root, "package.json"), {
      force: false,
      errorOnExist: true,
    });
    const native = path.join(root, "native/koffi");
    if (scenario === "missing-metadata") await unlink(path.join(native, "package.json"));
    if (scenario === "different-export") {
      const selector = {
        name: "@koromix/koffi-win32-x64",
        private: true,
        type: "commonjs",
        exports: { ".": "./build/koffi/win32_x64/different.node" },
      };
      const bytes = JSON.stringify(selector, null, 2) + "\n";
      await writeFile(path.join(native, "package.json"), bytes, "utf8");
      await writeFile(path.join(native, "build/koffi/win32_x64/different.node"), npmBytes, {
        flag: "wx",
      });
      const provenance: unknown = JSON.parse(
        await readFile(path.join(native, "binding-provenance.json"), "utf8"),
      );
      assert.ok(typeof provenance === "object" && provenance !== null && "members" in provenance);
      assert.ok(typeof provenance.members === "object" && provenance.members !== null);
      Object.assign(provenance.members, {
        "package.json": createHash("sha256").update(bytes).digest("hex"),
      });
      await writeFile(
        path.join(native, "binding-provenance.json"),
        JSON.stringify(provenance) + "\n",
        "utf8",
      );
    }
    const record = path.join(allocation, scenario + ".json");
    const execution = await runCli(
      process.execPath,
      [driver, root, record, scenario === "cached-npm" ? "npm" : "cold"],
      {
        cwd: root,
        timeoutMilliseconds: 10_000,
      },
    ).catch((error: unknown): CommandExecutionFailure => {
      assert.ok(error instanceof CommandExecutionFailure);
      return error;
    });
    const streams = execution instanceof CommandExecutionFailure ? execution.output : execution;
    await writeFile(path.join(allocation, scenario + ".stdout"), streams.stdout, "utf8");
    await writeFile(path.join(allocation, scenario + ".stderr"), streams.stderr, "utf8");
    if (scenario === "valid") {
      assert.ok(!(execution instanceof CommandExecutionFailure));
    } else {
      assert.ok(execution instanceof CommandExecutionFailure);
      assert.match(execution.message, /exit code 1/);
      const expected = refusals[scenario];
      assert.ok(expected);
      assert.match(execution.output.stderr, expected);
    }
    const observation: unknown = JSON.parse(await readFile(record, "utf8"));
    assert.ok(typeof observation === "object" && observation !== null && "images" in observation);
    assert.ok(Array.isArray(observation.images));
    const owned = path.join(native, "build/koffi/win32_x64/koffi.node");
    if (scenario === "valid") {
      assert.ok("resolved" in observation && observation.resolved === owned);
      assert.ok("sha256" in observation);
      assert.equal(observation.sha256, createHash("sha256").update(ownedBytes).digest("hex"));
      assert.deepEqual(observation.images, [owned]);
      assert.ok("version" in observation && observation.version === "3.3.5");
      assert.ok("processHandle" in observation && observation.processHandle !== "0");
    } else if (scenario === "cached-npm") {
      assert.deepEqual(observation.images, [npmImage]);
    } else {
      assert.deepEqual(observation.images, []);
    }
    assert.deepEqual(
      await readFile(path.join(native, "build/koffi/win32_x64/koffi.node")),
      ownedBytes,
    );
  }
});
