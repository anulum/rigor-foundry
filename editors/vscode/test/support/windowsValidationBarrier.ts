// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — genuine Windows validation completion barrier

/**
 * Build a real Python console PE with the installed pip/distlib launcher toolchain.
 * Publish readiness only after actual canonical validation and native input observations.
 * @module
 */

import assert from "node:assert/strict";
import path from "node:path";
import { mkdtemp, writeFile, stat } from "node:fs/promises";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";
import type { ValidationBarrier } from "./repository.js";

/**
 * Create a finite native console process delegating unchanged arguments to the actual CLI.
 * @param root - Owned adopter whose evidence directory receives the test launcher and traces.
 * @param cli - Actual configured canonical PE executable.
 * @returns Genuine launcher and ready/release/trace paths for the unchanged five race cases.
 */
export async function createWindowsValidationBarrier(
  root: string,
  cli: string,
): Promise<ValidationBarrier> {
  const python = process.env["RIGOR_FOUNDRY_TEST_PYTHON"];
  assert.ok(
    python,
    "native barrier qualification requires an explicitly supplied installed test Python",
  );
  const directory = await mkdtemp(path.join(root, ".rigor", "validation-barrier-"));
  const readyPath = path.join(directory, "ready");
  const releasePath = path.join(directory, "release");
  const tracePath = path.join(directory, "trace.json");
  const script = path.join(directory, "canonical-validation.py");
  const source = `#!python
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

kernel = ctypes.WinDLL("kernel32", use_last_error=True)
advapi = ctypes.WinDLL("advapi32", use_last_error=True)
advapi.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
advapi.GetFileSecurityW.restype = wintypes.BOOL
advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
kernel.LocalFree.argtypes = [ctypes.c_void_p]
kernel.LocalFree.restype = ctypes.c_void_p

def security(path):
    required = wintypes.DWORD()
    if advapi.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(required)) or ctypes.get_last_error() != 122:
        raise RuntimeError("native descriptor did not return its actual required size")
    if not 0 < required.value <= 65536:
        raise RuntimeError("native descriptor size exceeds test bound")
    buffer = ctypes.create_string_buffer(required.value)
    if not advapi.GetFileSecurityW(str(path), 5, buffer, len(buffer), ctypes.byref(required)):
        raise ctypes.WinError(ctypes.get_last_error())
    result = wintypes.LPWSTR()
    if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(buffer, 1, 5, ctypes.byref(result), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return result.value
    finally:
        if kernel.LocalFree(result):
            raise ctypes.WinError(ctypes.get_last_error())

cli = ${JSON.stringify(cli)}
args = sys.argv[1:]
result = subprocess.run([cli, *args], capture_output=True, timeout=60)
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
sys.stdout.buffer.flush()
sys.stderr.buffer.flush()
report = Path(args[args.index("--report") + 1])
review = Path(args[args.index("--review") + 1])
trace = {"executable": cli, "args": args, "cwd": str(Path.cwd()), "pythonExecutable": sys.executable, "pythonVersion": sys.version, "nativeConsolePE": str(Path(sys.argv[0])), "status": result.returncode, "signal": None, "stdout": result.stdout.decode("utf-8"), "stderr": result.stderr.decode("utf-8"), "reportPath": str(report), "reviewPath": str(review), "reportSha256": hashlib.sha256(report.read_bytes()).hexdigest(), "reviewSha256": hashlib.sha256(review.read_bytes()).hexdigest(), "reportSecurity": security(report), "reviewSecurity": security(review), "directorySecurity": security(report.parent)}
with Path(${JSON.stringify(tracePath)}).open("x", encoding="utf-8", newline="") as output:
    output.write(json.dumps(trace) + "\\n")
if result.returncode != 0:
    sys.exit(result.returncode)
with Path(${JSON.stringify(readyPath)}).open("x", encoding="utf-8", newline="") as output:
    output.write("validated\\n")
deadline = time.monotonic() + 15
while not Path(${JSON.stringify(releasePath)}).exists():
    if time.monotonic() >= deadline:
        sys.exit(124)
    time.sleep(0.01)
sys.exit(result.returncode)
`;
  await writeFile(script, source, { flag: "wx" });
  const builder =
    "import sys; from pathlib import Path; from pip._vendor.distlib.scripts import ScriptMaker; source=Path(sys.argv[1]); maker=ScriptMaker(str(source.parent),sys.argv[2]); maker.executable=sys.executable; maker.force=True; maker.variants={''}; print(maker.make(source.name))";
  try {
    const output = await runCli(python, ["-c", builder, script, directory], {
      cwd: root,
      timeoutMilliseconds: 30000,
    });
    await writeFile(path.join(directory, "builder.stdout"), output.stdout, "utf8");
    await writeFile(path.join(directory, "builder.stderr"), output.stderr, "utf8");
  } catch (error: unknown) {
    if (error instanceof CommandExecutionFailure) {
      await writeFile(path.join(directory, "builder.stdout"), error.output.stdout, "utf8");
      await writeFile(path.join(directory, "builder.stderr"), error.output.stderr, "utf8");
    }
    throw error;
  }
  const executable = path.join(directory, "canonical-validation.exe");
  assert.ok(
    (await stat(executable)).isFile(),
    "distlib must produce an actual native console PE launcher",
  );
  return { executable, readyPath, releasePath, tracePath };
}
