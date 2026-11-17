// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — required actual supported editor host producer

/**
 * Execute the complete maintained checks and real host journeys on one admitted CI profile.
 * Retain original process streams, actual application observations and unmodified V8 files.
 * @module
 */

import assert from "node:assert/strict";
import { cp, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { CommandExecutionFailure, runCli } from "#cli";
import { nativeInputs } from "./native-artifact-inputs.mjs";
import {
  editorInputs,
  githubIdentity,
  hostCliScript,
  hostProfiles,
} from "./editor-profile-inputs.mjs";

const editor = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const identity = githubIdentity(editor);
assert.equal(process.env["GITHUB_JOB"], "vscode-host");
const [version, output] = process.argv.slice(2);
assert.ok(version && output, "expected supported version and owned evidence directory");
const profile = (await hostProfiles(editor)).find(
  (item) => item["version"] === version && item["platform"] === process.platform,
);
assert.ok(profile, "unsupported editor host profile");
assert.equal(process.arch, "x64");
const directory = path.resolve(output);
assert.ok(!directory.startsWith(editor + path.sep));
await mkdir(directory, { recursive: true });
const code = process.env["VSCODE_EXECUTABLE"];
assert.ok(code, "actual installed VS Code executable is required");
assert.equal(path.resolve(process.env["NODE_V8_COVERAGE"] ?? ""), path.join(directory, "v8"));
const before = await editorInputs(editor);
const native = await nativeInputs(editor, editor);
const npm =
  process.platform === "win32"
    ? path.join(path.dirname(process.execPath), "node_modules/npm/bin/npm-cli.js")
    : path.resolve(path.dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js");
/** @type {{name: string, executable: string, args: string[], status: number}[]} Actual closed processes. */
const commands = [];

/**
 * Run one real required command and retain both streams before propagating its failure.
 * @param {string} name - Stable declared phase name.
 * @param {string} executable - Actual executable, never a shell substitute.
 * @param {string[]} args - Literal public command arguments.
 * @param {Record<string, string | undefined>} [environment] - Child-only environment for the actual application CLI.
 * @returns {Promise<string>} Original stdout from a successful closed process.
 */
async function run(name, executable, args, environment = process.env) {
  await writeFile(
    path.join(directory, name + ".argv.json"),
    JSON.stringify({ executable, args, cwd: editor }) + "\n",
    { flag: "wx" },
  );
  try {
    const result = await runCli(executable, args, {
      cwd: editor,
      timeoutMilliseconds: 600000,
      maximumOutputBytes: 16777216,
      environment,
    });
    await writeFile(path.join(directory, name + ".stdout"), result.stdout, { flag: "wx" });
    await writeFile(path.join(directory, name + ".stderr"), result.stderr, { flag: "wx" });
    commands.push({ name, executable, args, status: 0 });
    return result.stdout;
  } catch (error) {
    if (error instanceof CommandExecutionFailure) {
      await writeFile(path.join(directory, name + ".stdout"), error.output.stdout, { flag: "wx" });
      await writeFile(path.join(directory, name + ".stderr"), error.output.stderr, { flag: "wx" });
    }
    throw error;
  }
}

const installed = (
  await run("host-version", code, [await hostCliScript(code, profile), "--version"], {
    ...process.env,
    VSCODE_DEV: "",
    ELECTRON_RUN_AS_NODE: "1",
  })
)
  .trim()
  .split(/\r?\n/u);
assert.equal(installed[0], profile["version"]);
assert.equal(installed[1], profile["commit"]);
assert.equal(installed[2], "x64");
await run("check", process.execPath, [npm, "run", "check"]);
if (process.platform === "linux")
  await run("linux-filesystem", process.execPath, [npm, "run", "test:linux-filesystem"]);
await run("workspace-host", process.execPath, [
  path.join(editor, "scripts/run-workspace-tests.mjs"),
]);
await run("single-host", process.execPath, [
  path.join(editor, "scripts/run-integration-tests.mjs"),
]);
const workbenchFiles = (await readdir(path.join(editor, "out/test/integration")))
  .filter((name) => name.endsWith(".test.js"))
  .sort()
  .map((name) => path.join(editor, "out/test/integration", name));
assert.ok(workbenchFiles.length > 0, "all maintained workbench test files are required");
await run("workbench", process.execPath, ["--test", "--test-concurrency=1", ...workbenchFiles]);
const fixtures = path.join(editor, "out/fixtures");
/** @type {Record<string, unknown>[]} Actual host observation records. */
const hosts = [];
for (const entry of await readdir(fixtures, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  let kind;
  let relative;
  if (entry.name.startsWith("rigor-vscode-integration-")) {
    kind = "single";
    relative = "workspace/.rigor/vscode-host.json";
  } else if (entry.name.startsWith("rigor-workspace-host-")) {
    kind = "workspace";
    relative = "workspace-A/.rigor/workspace-host.json";
  } else if (
    entry.name.startsWith("rigor-native-binding-") ||
    entry.name.startsWith("rigor-native-build-")
  ) {
    const target = path.join(directory, "fixtures", entry.name);
    await mkdir(target, { recursive: true });
    for (const name of await readdir(path.join(fixtures, entry.name))) {
      if (name !== "source-origin.json" && !name.endsWith(".stdout") && !name.endsWith(".stderr"))
        continue;
      await cp(path.join(fixtures, entry.name, name), path.join(target, name), {
        errorOnExist: true,
        force: false,
      });
    }
    continue;
  } else if (
    entry.name.startsWith("rigor-workbench-") ||
    entry.name.startsWith("rigor-native-artifact-") ||
    entry.name.startsWith("rigor-editor-coverage-") ||
    entry.name.startsWith("rigor-editor-metadata-")
  ) {
    await cp(path.join(fixtures, entry.name), path.join(directory, "fixtures", entry.name), {
      recursive: true,
      errorOnExist: true,
      force: false,
    });
    continue;
  } else continue;
  let bytes;
  try {
    bytes = await readFile(path.join(fixtures, entry.name, relative));
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") continue;
    throw error;
  }
  const host = /** @type {unknown} */ (JSON.parse(bytes.toString("utf8")));
  assert.ok(
    typeof host === "object" &&
      host !== null &&
      "vscodeVersion" in host &&
      "platform" in host &&
      "architecture" in host &&
      "nodeVersion" in host,
  );
  assert.equal(host.vscodeVersion, version);
  assert.equal(host.platform, process.platform);
  assert.equal(host.architecture, "x64");
  assert.match(String(host.nodeVersion), /^v[0-9]+\.[0-9]+\.[0-9]+$/u);
  hosts.push({ kind, observation: host });
  await cp(path.join(fixtures, entry.name), path.join(directory, "fixtures", entry.name), {
    recursive: true,
    errorOnExist: true,
    force: false,
  });
}
assert.deepEqual(hosts.map((host) => host["kind"]).sort(), ["single", "workspace"]);
const inputs = await editorInputs(editor);
assert.deepEqual(inputs.sources, before.sources, "source changed during supported host execution");
assert.deepEqual(await nativeInputs(editor, editor), native);
assert.deepEqual(githubIdentity(editor), identity);
await writeFile(
  path.join(directory, "profile.json"),
  JSON.stringify(
    {
      schema: 1,
      kind: "supported-host",
      identity,
      profile: profile["id"],
      definition: profile,
      editorUri: pathToFileURL(editor + path.sep).href,
      node: process.version,
      inputs,
      native,
      commands,
      hosts,
      resources: {
        platform: process.platform,
        architecture: process.arch,
        memoryBytes: os.totalmem(),
        availableThreads: os.availableParallelism(),
      },
    },
    null,
    2,
  ) + "\n",
  { flag: "wx" },
);
