// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — required complete supported-editor coverage consumer

/**
 * Require the native build and every supported OS/version host producer before raw union.
 * The workflow adds this completed consumer's original V8 files before the strict all-owner gate.
 * @module
 */

import assert from "node:assert/strict";
import { mkdir, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { admitProfileFiles, githubIdentity, hostProfiles } from "./editor-profile-inputs.mjs";
import { record, readMember } from "./native-artifact-inputs.mjs";
import { stageEditorCoverage } from "./editor-coverage.mjs";

const editor = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const identity = githubIdentity(editor);
assert.equal(process.env["GITHUB_JOB"], "vscode");
const [input, output] = process.argv.slice(2);
assert.ok(input && output, "expected producer root and absent owned union directory");
const source = path.resolve(input);
const destination = path.resolve(output);
assert.ok(!destination.startsWith(editor + path.sep));
const definitions = await hostProfiles(editor);
const required = [
  "native-build",
  ...definitions.map((profile) => {
    const id = profile["id"];
    assert.equal(typeof id, "string");
    return /** @type {string} */ (id);
  }),
];
const directories = [];
for (const entry of await readdir(source, { withFileTypes: true })) {
  assert.ok(
    entry.isDirectory(),
    "editor producer input must contain only real artifact directories",
  );
  const directory = path.join(source, entry.name);
  await admitProfileFiles(directory);
  const metadata = record(
    JSON.parse((await readMember(directory, "profile.json")).toString("utf8")),
  );
  if (metadata["profile"] === "native-build") {
    assert.equal(metadata["kind"], "native-build");
  } else {
    const definition = definitions.find((profile) => profile["id"] === metadata["profile"]);
    assert.ok(definition, "unknown editor profile");
    assert.equal(metadata["kind"], "supported-host");
    assert.deepEqual(metadata["definition"], definition);
    const commands = metadata["commands"];
    assert.ok(Array.isArray(commands));
    const expected = [
      "host-version",
      "check",
      ...(definition["platform"] === "linux" ? ["linux-filesystem"] : []),
      "workspace-host",
      "single-host",
      "workbench",
    ];
    assert.deepEqual(
      commands.map((command) => record(command)["name"]),
      expected,
    );
    assert.ok(commands.every((command) => record(command)["status"] === 0));
    const installed = (await readMember(directory, "host-version.stdout"))
      .toString("utf8")
      .trim()
      .split(/\r?\n/u);
    assert.deepEqual(installed.slice(0, 3), [definition["version"], definition["commit"], "x64"]);
    const hosts = metadata["hosts"];
    assert.ok(Array.isArray(hosts));
    assert.deepEqual(hosts.map((host) => record(host)["kind"]).sort(), ["single", "workspace"]);
    for (const item of hosts) {
      const observation = record(record(item)["observation"]);
      assert.equal(observation["vscodeVersion"], definition["version"]);
      assert.equal(observation["platform"], definition["platform"]);
      assert.equal(observation["architecture"], "x64");
      assert.match(String(observation["nodeVersion"]), /^v[0-9]+\.[0-9]+\.[0-9]+$/u);
    }
  }
  directories.push(directory);
}
await mkdir(destination, { recursive: false });
const admission = await stageEditorCoverage(
  editor,
  directories,
  identity,
  required,
  path.join(destination, "v8"),
);
await writeFile(
  path.join(destination, "admission.json"),
  JSON.stringify(
    {
      schema: 1,
      identity,
      required,
      ...admission,
      scope:
        "all maintained editor/runtime/test/support/script/configuration owners; no owner, V8 function/range/count or threshold removed",
    },
    null,
    2,
  ) + "\n",
  { flag: "wx" },
);
