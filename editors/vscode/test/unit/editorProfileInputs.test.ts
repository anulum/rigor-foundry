// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — actual editor source and terminal evidence manifests

/**
 * Bind the complete real current editor inputs and seal actual bytes without hosted impersonation.
 * Require altered, added and repeated evidence to refuse admission.
 * @module
 */

import assert from "node:assert/strict";
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";
import { digest } from "../../scripts/native-artifact-inputs.mjs";
import {
  admitProfileFiles,
  editorInputs,
  hostCliScript,
  hostProfiles,
  sealProfileFiles,
} from "../../scripts/editor-profile-inputs.mjs";

void test("locates ordinary CLI files in legacy and versioned host layouts", async (context) => {
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-host-cli-layout-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const executable = path.join(allocation, "Code.exe");
  const editor = path.resolve(__dirname, "../../..");
  const source = await readFile(path.join(editor, "scripts/run-editor-profile.mjs"));
  for (const relative of ["resources/app/out/cli.js", "c4453f8ea4/resources/app/out/cli.js"]) {
    const filename = path.join(allocation, ...relative.split("/"));
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, source, { flag: "wx" });
    assert.equal(
      await hostCliScript(
        executable,
        relative.startsWith("resources/") ? {} : { cliRelativePath: relative },
      ),
      filename,
    );
    assert.deepEqual(await readFile(filename), source);
  }
  for (const cliRelativePath of [17, "", "../escape.js", "/escape.js", "resources\\cli.js"]) {
    await assert.rejects(hostCliScript(executable, { cliRelativePath }), /AssertionError/u);
  }
  await assert.rejects(hostCliScript(executable, { cliRelativePath: "absent.js" }), {
    code: "ENOENT",
  });
  const alias = path.join(allocation, "alias");
  await symlink(path.join(allocation, "resources"), alias, "junction");
  await assert.rejects(
    hostCliScript(executable, { cliRelativePath: "alias/app/out/cli.js" }),
    /parent must be a real directory/u,
  );
});

void test("binds all current source owners and exact terminal evidence files", async (context) => {
  const editor = path.resolve(__dirname, "../../..");
  const inputs = await editorInputs(editor);
  assert.ok(inputs.owners.includes("src/windowsResources.ts"));
  assert.ok(inputs.owners.includes("test/unit/editorProfileInputs.test.ts"));
  assert.ok(inputs.generated["out/test/unit/editorProfileInputs.test.js.map"]);
  assert.ok(inputs.sources[".github/actions/install-editor-host/action.yml"]);
  const profiles = await hostProfiles(editor);
  assert.deepEqual(
    profiles.map((profile) => [profile["platform"], profile["version"]]),
    [
      ["linux", "1.125.0"],
      ["linux", "1.145.2"],
      ["win32", "1.125.0"],
      ["win32", "1.145.2"],
    ],
  );
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-editor-inputs-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const payload = await readFile(path.join(editor, "out/test/unit/workbenchProtocol.test.js"));
  await mkdir(path.join(allocation, "original"));
  await writeFile(path.join(allocation, "original/current-code.js"), payload, { flag: "wx" });
  await sealProfileFiles(allocation);
  const original = await readFile(path.join(allocation, "files.json"));
  const admitted = await admitProfileFiles(allocation);
  assert.equal(Object.keys(admitted).length, 1);
  assert.deepEqual(await readFile(path.join(allocation, "original/current-code.js")), payload);
  await assert.rejects(sealProfileFiles(allocation), /already sealed/u);
  await writeFile(
    path.join(allocation, "original/current-code.js"),
    Buffer.concat([payload, Buffer.from("\n")]),
  );
  await assert.rejects(admitProfileFiles(allocation), /evidence file differs/u);
  await writeFile(path.join(allocation, "original/current-code.js"), payload);
  await writeFile(path.join(allocation, "extra"), "extra", { flag: "wx" });
  await assert.rejects(admitProfileFiles(allocation), /AssertionError/u);
  assert.deepEqual(await readFile(path.join(allocation, "files.json")), original);
});

void test("refuses local native-builder identity before writing a hosted profile", async (context) => {
  const editor = path.resolve(__dirname, "../../..");
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-editor-local-builder-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const directory = path.join(allocation, "coverage");
  await mkdir(directory);
  const original = await readFile(path.join(editor, "out/src/extension.js"));
  const member = path.join(directory, "original-current-code.js");
  await writeFile(member, original, { flag: "wx" });
  const module = pathToFileURL(path.join(editor, "scripts/editor-profile-inputs.mjs")).href;
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith("GITHUB_")),
  );
  await assert.rejects(
    runCli(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `import { recordNativeBuild } from ${JSON.stringify(module)}; await recordNativeBuild(...process.argv.slice(1));`,
        editor,
        directory,
        path.join(allocation, "absent-artifact"),
      ],
      { cwd: editor, environment, timeoutMilliseconds: 10_000 },
    ),
    (error: unknown): boolean => {
      assert.ok(error instanceof CommandExecutionFailure);
      assert.match(error.output.stderr, /editor profiles require actual GitHub execution/u);
      assert.equal(error.output.stdout, "");
      return true;
    },
  );
  await assert.rejects(lstat(path.join(directory, "profile.json")), { code: "ENOENT" });
  assert.deepEqual(await readFile(member), original);
});

void test("inventories the real source checkout before compilation and rejects invalid output roots", async (context) => {
  const originalEditor = path.resolve(__dirname, "../../..");
  const originalRoot = path.resolve(originalEditor, "../..");
  const original = await editorInputs(originalEditor);
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-editor-source-inputs-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const checkout = path.join(allocation, "checkout");
  const editor = path.join(checkout, "editors/vscode");
  for (const [name, hash] of Object.entries(original.sources)) {
    const bytes = await readFile(path.join(originalRoot, name));
    assert.equal(digest(bytes), hash);
    const destination = path.join(checkout, name);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, bytes, { flag: "wx" });
  }
  await runCli("git", ["init", "--quiet", checkout], {
    cwd: allocation,
    timeoutMilliseconds: 10_000,
  });
  const pristine = await editorInputs(editor);
  assert.deepEqual(pristine.sources, original.sources);
  assert.deepEqual(pristine.owners, original.owners);
  assert.deepEqual(pristine.generated, {});
  const output = path.join(editor, "out");
  await mkdir(path.join(output, "src"), { recursive: true });
  const generated = "out/src/extension.js";
  const bytes = await readFile(path.join(originalEditor, generated));
  await writeFile(path.join(editor, generated), bytes, { flag: "wx" });
  await writeFile(path.join(output, "src/README.md"), "compiler output is not a source owner");
  const compiled = await editorInputs(editor);
  assert.deepEqual(compiled.sources, pristine.sources);
  assert.deepEqual(compiled.owners, pristine.owners);
  assert.deepEqual(compiled.generated, { [generated]: digest(bytes) });
  await rm(output, { recursive: true });
  await writeFile(output, "ordinary file cannot contain compiler output", { flag: "wx" });
  await assert.rejects(editorInputs(editor), /compiler output root must be a real directory/u);
  await rm(output);
  await symlink(path.join(originalEditor, "out"), output, "junction");
  await assert.rejects(editorInputs(editor), /compiler output root must be a real directory/u);
  await rm(output);
  await mkdir(output);
  await symlink(path.join(originalEditor, "out/src"), path.join(output, "src"), "junction");
  await assert.rejects(editorInputs(editor), /root must be a real directory/u);
  assert.deepEqual(await editorInputs(originalEditor), original);
});

void test("refuses inconsistent supported hosts and untrusted terminal manifests", async (context) => {
  const editor = path.resolve(__dirname, "../../..");
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-editor-manifest-inputs-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const hostRoot = path.join(allocation, "hosts");
  await mkdir(path.join(hostRoot, "native"), { recursive: true });
  const hostBytes = await readFile(path.join(editor, "native/editor-hosts.json"));
  const hosts: unknown = JSON.parse(hostBytes.toString("utf8"));
  assert.ok(typeof hosts === "object" && hosts !== null && "profiles" in hosts);
  assert.ok(Array.isArray(hosts.profiles));
  const profiles: unknown[] = hosts.profiles;
  const hostFile = path.join(hostRoot, "native/editor-hosts.json");
  await writeFile(hostFile, hostBytes, { flag: "wx" });
  assert.deepEqual(await hostProfiles(hostRoot), await hostProfiles(editor));
  for (const value of [
    { ...hosts, schema: 2 },
    { ...hosts, architecture: "arm64" },
    { ...hosts, profiles: {} },
    { ...hosts, profiles: profiles.slice(1) },
    { ...hosts, profiles: [...profiles.slice(1), profiles[1]] },
    { ...hosts, profiles: [null, ...profiles.slice(1)] },
  ]) {
    await writeFile(hostFile, JSON.stringify(value));
    await assert.rejects(hostProfiles(hostRoot), /AssertionError/u);
  }
  const evidence = path.join(allocation, "evidence");
  await mkdir(evidence);
  const actual = await readFile(path.join(editor, "out/src/extension.js"));
  const member = path.join(evidence, "extension.js");
  await writeFile(member, actual, { flag: "wx" });
  const manifest = path.join(evidence, "files.json");
  await writeFile(manifest, JSON.stringify({ "extension.js": 1 }), { flag: "wx" });
  await assert.rejects(admitProfileFiles(evidence), /AssertionError/u);
  await writeFile(manifest, JSON.stringify({ "extension.js": digest(actual) }));
  assert.deepEqual(await admitProfileFiles(evidence), { "extension.js": digest(actual) });
  await rm(member);
  await mkdir(member);
  await assert.rejects(admitProfileFiles(evidence), /AssertionError/u);
  await rm(member, { recursive: true });
  await symlink(path.join(editor, "out/src"), member, "junction");
  await assert.rejects(admitProfileFiles(evidence), /linked or special entries/u);
  await rm(manifest);
  await assert.rejects(sealProfileFiles(evidence), /linked or special entries/u);
});
