// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — locked native Windows package assets

/**
 * Build the exact locked Koffi source with delayed Node imports for native Electron hosts.
 * Stage the unchanged vendor loader, actual native image, MIT notices and build provenance.
 * @module
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import { copyFile, lstat, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
assert.ok(
  process.platform === "win32" && process.arch === "x64",
  "native asset build requires actual Windows x64 and MSVC",
);

/**
 * Require an ordinary manifest record without assuming JSON input types.
 * @param {unknown} value - Parsed version or source manifest.
 * @returns {Record<string, unknown>} Fields that still need their specific contract checks.
 */
function record(value) {
  assert.ok(
    typeof value === "object" && value !== null && !Array.isArray(value),
    "native source manifest must be a record",
  );
  return /** @type {Record<string, unknown>} */ (value);
}

/**
 * Inventory real package files, refusing filesystem aliases in a compiler input tree.
 * @param {string} directory - Actual source package directory.
 * @param {string} [prefix] - Package-relative prefix used for exact inventory matching.
 * @returns {Promise<string[]>} Every real regular source member beneath the package.
 */
async function sourceFiles(directory, prefix = "") {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relative = prefix + entry.name;
    assert.ok(!entry.isSymbolicLink(), "locked compiler inputs must not contain links");
    if (entry.isDirectory())
      files.push(...(await sourceFiles(path.join(directory, entry.name), relative + "/")));
    else {
      assert.ok(entry.isFile(), "locked compiler inputs must be regular files");
      files.push(relative);
    }
  }
  return files;
}

/**
 * Retain a finite real build-tool invocation and its actual diagnostic streams.
 * A failed spawn can omit streams; retain them as empty files and rethrow the original error.
 * @param {string} executable - Actual existing native development tool.
 * @param {string[]} args - Literal trusted build arguments.
 * @param {string} label - Authored trace stem within this build allocation.
 * @param {string} allocation - Owned unique output directory.
 * @param {boolean} [verbatim] - Preserve the explicitly authored cmd.exe command text.
 * @returns {Promise<string>} Actual UTF-8 standard output after successful tool completion.
 */
async function run(executable, args, label, allocation, verbatim = false) {
  /** @type {import("node:child_process").SpawnSyncReturns<string | null | undefined>} */
  const result = spawnSync(executable, args, {
    cwd: root,
    shell: false,
    windowsHide: true,
    windowsVerbatimArguments: verbatim,
    timeout: 240000,
    maxBuffer: 16777216,
    encoding: "utf8",
    env: { ...process.env, CMAKE_BUILD_PARALLEL_LEVEL: "1" },
  });
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  await writeFile(path.join(allocation, label + ".stdout"), stdout, "utf8");
  await writeFile(path.join(allocation, label + ".stderr"), stderr, "utf8");
  await writeFile(
    path.join(allocation, label + ".json"),
    JSON.stringify({
      executable,
      args,
      status: result.status,
      signal: result.signal,
      error: result.error?.message ?? null,
    }) + "\n",
    "utf8",
  );
  if (result.error !== undefined) throw result.error;
  assert.equal(
    result.status,
    0,
    "native build tool failed; original streams retained at " + allocation,
  );
  return stdout;
}

const manifest = record(
  JSON.parse(await readFile(path.join(root, "native/koffi-source.json"), "utf8")),
);
const locked = record(JSON.parse(await readFile(path.join(root, "package-lock.json"), "utf8")));
const packages = record(locked["packages"]);
const koffiLock = record(packages["node_modules/koffi"]);
assert.equal(manifest["version"], "3.3.5");
assert.equal(koffiLock["version"], manifest["version"]);
assert.equal(koffiLock["integrity"], manifest["integrity"]);
assert.equal(koffiLock["resolved"], manifest["resolved"]);
const expectedFiles = record(manifest["files"]);
const source = path.join(root, "node_modules/koffi");
assert.deepEqual(
  (await sourceFiles(source)).sort(),
  Object.keys(expectedFiles).sort(),
  "complete compiler input inventory must equal the locked archive",
);
for (const [relative, expected] of Object.entries(expectedFiles)) {
  const bytes = await readFile(path.join(source, relative));
  assert.equal(
    createHash("sha256").update(bytes).digest("hex"),
    expected,
    "locked compiler source changed: " + relative,
  );
}
const allocation = await mkdtemp(path.join(tmpdir(), "rigor-native-"));
const programFiles = process.env["ProgramFiles(x86)"];
assert.ok(programFiles, "Visual Studio Installer location is unavailable");
const vswhere = path.join(programFiles, "Microsoft Visual Studio/Installer/vswhere.exe");
const installation = (
  await run(
    vswhere,
    [
      "-latest",
      "-products",
      "*",
      "-requires",
      "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
      "-property",
      "installationPath",
    ],
    "msvc-discovery",
    allocation,
  )
).trim();
assert.ok(
  installation.length > 0 && !installation.includes("\n"),
  "an installed MSVC x64 toolchain is required",
);
const vcvars = path.join(installation, "VC/Auxiliary/Build/vcvars64.bat");
assert.ok((await lstat(vcvars)).isFile(), "MSVC environment initializer is unavailable");
const output = path.join(allocation, "output");
const command = path.join(allocation, "compile.cmd");
for (const value of [process.execPath, vcvars, source, output, command])
  assert.doesNotMatch(value, /["%\r\n\0]/u, "build paths must have literal batch spelling");
const flags = "NODE_JS_LINK_FLAGS=/DELAYLOAD:NODE.EXE;delayimp.lib";
const batch = [
  "@echo off",
  "chcp 65001 >nul",
  `call "${vcvars}" >nul`,
  "if errorlevel 1 exit /b 1",
  `"${process.execPath}" "${path.join(source, "cnoke.cjs")}" build -P "${source}" -D "${path.join(source, "src/koffi")}" -O "${output}" --release --define "${flags}"`,
  "exit /b %errorlevel%",
  "",
].join("\r\n");
await writeFile(command, batch, { encoding: "utf8", flag: "wx" });
const systemRoot = process.env["SystemRoot"];
assert.ok(systemRoot, "Windows system directory is unavailable");
await run(
  path.join(systemRoot, "System32/cmd.exe"),
  ["/d", "/s", "/c", `""${command}""`],
  "native-compile",
  allocation,
  true,
);
const binary = await readFile(path.join(output, "koffi.node"));
assert.ok(binary.length > 0, "native compiler produced no image");
const destination = path.join(root, "native/koffi");
const members = [
  [path.join(source, "src/koffi/index.cjs"), "src/koffi/index.cjs"],
  [path.join(source, "src/koffi/src/static.cjs"), "src/koffi/src/static.cjs"],
  [path.join(source, "LICENSE.txt"), "notices/KOFFI-MIT.txt"],
  [path.join(source, "vendor/node-addon-api/LICENSE.md"), "notices/NODE-ADDON-API-MIT.txt"],
  [path.join(source, "vendor/node-api-headers/LICENSE"), "notices/NODE-API-HEADERS-MIT.txt"],
  [path.join(output, "koffi.node"), "build/koffi/win32_x64/koffi.node"],
];
/** @type {Record<string, string>} Exact staged member digests. */
const staged = {};
for (const [original, relative] of members) {
  assert.ok(original !== undefined && relative !== undefined);
  const target = path.join(destination, relative);
  await mkdir(path.dirname(target), { recursive: true });
  await copyFile(original, target, constants.COPYFILE_EXCL);
  staged[relative] = createHash("sha256")
    .update(await readFile(target))
    .digest("hex");
}
await copyFile(
  path.resolve(root, "../../LICENSE"),
  path.join(root, "LICENSE.txt"),
  constants.COPYFILE_EXCL,
);
await writeFile(
  path.join(destination, "provenance.json"),
  JSON.stringify(
    {
      producer: "rigor-foundry-windows-native-v1",
      version: manifest["version"],
      archiveIntegrity: manifest["integrity"],
      archiveSha256: manifest["tarball_sha256"],
      sourceFiles: expectedFiles,
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
      buildFlags: flags,
      buildAllocation: path.basename(allocation),
      members: staged,
    },
    null,
    2,
  ) + "\n",
  { encoding: "utf8", flag: "wx" },
);
await run(
  process.execPath,
  [path.join(root, "scripts/stage-windows-binding.mjs")],
  "native-binding",
  allocation,
);
process.stdout.write(
  JSON.stringify({
    nativeBinarySha256: createHash("sha256").update(binary).digest("hex"),
    sourceMembers: Object.keys(expectedFiles).length,
    destination,
    traces: allocation,
  }) + "\n",
);
