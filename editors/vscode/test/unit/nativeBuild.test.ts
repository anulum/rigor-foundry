// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — unavailable native build prerequisite diagnostics

/**
 * Exercise the complete build entry point against real locked compiler inputs.
 * An empty installer location contains no substitute discovery tool or compiler.
 * Require the actual failed spawn and empty diagnostic streams to remain inspectable.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";

void test(
  "native build retains the original unavailable discovery-tool failure",
  { skip: process.platform !== "win32" },
  async (context) => {
    const extensionRoot = path.resolve(__dirname, "../../..");
    const allocation = await mkdtemp(path.join(tmpdir(), "rigor-build-failure-"));
    context.after(async () => {
      await rm(allocation, { recursive: true, force: true });
    });
    const editor = path.join(allocation, "product", "editors", "vscode");
    const copiedScript = path.join(editor, "scripts", "build-windows-native.mjs");
    const originalScript = path.join(extensionRoot, "scripts", "build-windows-native.mjs");
    const scriptBytes = await readFile(originalScript);
    for (const relative of [
      "scripts/build-windows-native.mjs",
      "native/koffi-source.json",
      "package-lock.json",
    ]) {
      const destination = path.join(editor, relative);
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, await readFile(path.join(extensionRoot, relative)), {
        flag: "wx",
      });
    }
    const source = path.join(editor, "node_modules", "koffi");
    await mkdir(path.dirname(source), { recursive: true });
    await cp(path.join(extensionRoot, "node_modules", "koffi"), source, {
      recursive: true,
      errorOnExist: true,
      force: false,
    });
    const temporary = path.join(allocation, "tmp");
    const installer = path.join(allocation, "unavailable-installer");
    await mkdir(temporary);
    await mkdir(installer);
    assert.deepEqual(await readdir(installer), []);
    await mkdir(path.join(extensionRoot, "out/fixtures"), { recursive: true });
    const evidence = await mkdtemp(path.join(extensionRoot, "out/fixtures/rigor-native-build-"));
    await writeFile(
      path.join(evidence, "source-origin.json"),
      JSON.stringify(
        {
          schema: 1,
          copies: [
            {
              url: pathToFileURL(copiedScript).href,
              source: "editors/vscode/scripts/build-windows-native.mjs",
              sha256: createHash("sha256").update(scriptBytes).digest("hex"),
            },
          ],
        },
        null,
        2,
      ) + "\n",
      { flag: "wx" },
    );
    assert.deepEqual(await readFile(copiedScript), scriptBytes);
    const failure = await runCli(process.execPath, [copiedScript], {
      cwd: editor,
      timeoutMilliseconds: 15_000,
      environment: {
        ...process.env,
        TMPDIR: temporary,
        TMP: temporary,
        TEMP: temporary,
        "ProgramFiles(x86)": installer,
      },
    }).catch((error: unknown): CommandExecutionFailure => {
      assert.ok(error instanceof CommandExecutionFailure);
      return error;
    });
    assert.ok(failure instanceof CommandExecutionFailure);
    assert.equal(failure.message, "RigorFoundry CLI failed with exit code 1");
    assert.equal(failure.output.stdout, "");
    assert.match(failure.output.stderr, /ENOENT/u);
    assert.doesNotMatch(failure.output.stderr, /ERR_INVALID_ARG_TYPE/u);
    const traces = (await readdir(temporary)).filter((name) => name.startsWith("rigor-native-"));
    assert.equal(traces.length, 1);
    const trace = traces[0];
    assert.ok(trace);
    const stem = path.join(temporary, trace, "msvc-discovery");
    assert.equal(await readFile(stem + ".stdout", "utf8"), "");
    assert.equal(await readFile(stem + ".stderr", "utf8"), "");
    const metadata: unknown = JSON.parse(await readFile(stem + ".json", "utf8"));
    assert.ok(typeof metadata === "object" && metadata !== null);
    assert.ok("error" in metadata && typeof metadata.error === "string");
    assert.match(metadata.error, /ENOENT/u);
    assert.ok("executable" in metadata);
    assert.equal(
      metadata.executable,
      path.join(installer, "Microsoft Visual Studio/Installer/vswhere.exe"),
    );
    assert.deepEqual(await readFile(copiedScript), scriptBytes);
    assert.deepEqual(await readdir(installer), []);
    context.diagnostic(
      "native build source binding " +
        JSON.stringify({
          path: copiedScript,
          originalPath: originalScript,
          sourceSha256: createHash("sha256").update(scriptBytes).digest("hex"),
        }),
    );
  },
);
