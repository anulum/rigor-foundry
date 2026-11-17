// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — real CLI launcher with retained diagnostic streams

/**
 * Build an executable launcher that delegates unchanged arguments to the actual canonical CLI.
 * Retain the real process result and emit its own labelled stdout and stderr diagnostics.
 * @module
 */

import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { runCli } from "../../src/cli.js";

/** Genuine executable and original tool/process evidence owned by one test adopter. */
export interface DiagnosticCli {
  /** Actual packaging-toolchain executable forwarding unchanged arguments to the canonical CLI. */
  readonly executable: string;
  /** Owned directory retaining the builder output, script and actual canonical CLI records. */
  readonly directory: string;
}

/**
 * Create a genuine executable using the installed Python packaging launcher toolchain.
 * @param root - Actual adopter whose ignored evidence directory owns the launcher and traces.
 * @param cli - Actual configured canonical executable invoked with unchanged command arguments.
 * @returns Executable and the directory retaining its builder and underlying CLI records.
 */
export async function createDiagnosticCli(root: string, cli: string): Promise<DiagnosticCli> {
  const directory = await mkdtemp(path.join(root, ".rigor", "diagnostic-cli-"));
  const script = path.join(directory, "canonical-diagnostics.py");
  const source = `#!python
import json
import os
from pathlib import Path
import subprocess
import sys

cli = ${JSON.stringify(cli)}
args = sys.argv[1:]
result = subprocess.run([cli, *args], capture_output=True, timeout=60)
stdout = result.stdout
stderr = result.stderr
if result.returncode == 0:
    stdout += ("configured CLI launcher stdout: " + args[0] + "\\n").encode("utf-8")
    stderr += ("configured CLI launcher stderr: " + args[0] + "\\n").encode("utf-8")
record = {"canonicalExecutable": cli, "args": args, "status": result.returncode, "canonicalStdout": result.stdout.decode("utf-8"), "canonicalStderr": result.stderr.decode("utf-8"), "launcherStdout": stdout.decode("utf-8"), "launcherStderr": stderr.decode("utf-8"), "pid": os.getpid(), "pythonExecutable": sys.executable, "pythonVersion": sys.version}
with (Path(${JSON.stringify(directory)}) / (args[0] + ".json")).open("x", encoding="utf-8") as output:
    output.write(json.dumps(record) + "\\n")
sys.stdout.buffer.write(stdout)
sys.stderr.buffer.write(stderr)
sys.exit(result.returncode)
`;
  await writeFile(script, source, { flag: "wx" });
  const destination = path.join(directory, "executable");
  await mkdir(destination);
  const python = process.env["RIGOR_FOUNDRY_TEST_PYTHON"] ?? "python";
  const builder =
    "import sys; from pathlib import Path; from pip._vendor.distlib.scripts import ScriptMaker; source=Path(sys.argv[1]); maker=ScriptMaker(str(source.parent),sys.argv[2]); maker.executable=sys.executable; maker.force=True; maker.set_mode=True; maker.variants={''}; print(maker.make(source.name))";
  const built = await runCli(python, ["-c", builder, script, destination], {
    cwd: root,
    timeoutMilliseconds: 30_000,
  });
  await writeFile(path.join(directory, "builder.stdout"), built.stdout, "utf8");
  await writeFile(path.join(directory, "builder.stderr"), built.stderr, "utf8");
  assert.equal(await readFile(script, "utf8"), source);
  const executable = path.join(
    destination,
    process.platform === "win32" ? "canonical-diagnostics.exe" : "canonical-diagnostics.py",
  );
  assert.ok((await stat(executable)).isFile(), "packaging toolchain must create a real launcher");
  return { executable, directory };
}
