// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — native payload input and alias refusal

/**
 * Validate original compiled payloads and refuse altered notices, build flags and directory aliases.
 * Exercise the public artifact input API without executing a Windows image on another platform.
 * Node ignores the directory-junction type on POSIX, preserving the same real link refusal.
 * @module
 */

import assert from "node:assert/strict";
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";
import {
  artifactMembers,
  git,
  nativeInputs,
  readMember,
  record,
  sourceInputs,
  sourcePaths,
} from "../../scripts/native-artifact-inputs.mjs";

void test("checks the complete real payload and refuses inconsistent compiler or filesystem inputs", async (context) => {
  const editor = path.resolve(__dirname, "../../..");
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-native-inputs-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const expected = await nativeInputs(editor, editor);
  for (const name of artifactMembers) {
    const filename = path.join(allocation, name);
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, await readFile(path.join(editor, name)), { flag: "wx" });
  }
  assert.deepEqual(await nativeInputs(editor, allocation), expected);
  const notice = path.join(allocation, "native/koffi/notices/KOFFI-MIT.txt");
  const originalNotice = await readFile(notice);
  await writeFile(notice, Buffer.concat([originalNotice, Buffer.from("\n")]));
  await assert.rejects(nativeInputs(editor, allocation), /AssertionError/u);
  await writeFile(notice, originalNotice);
  const provenancePath = path.join(allocation, "native/koffi/provenance.json");
  const provenanceBytes = await readFile(provenancePath);
  const provenance = record(JSON.parse(provenanceBytes.toString("utf8")));
  await writeFile(provenancePath, JSON.stringify({ ...provenance, buildFlags: "" }));
  await assert.rejects(nativeInputs(editor, allocation), /AssertionError/u);
  await writeFile(provenancePath, provenanceBytes);
  const notices = path.join(allocation, "native/koffi/notices");
  await rm(notices, { recursive: true });
  await symlink(path.join(editor, "native/koffi/notices"), notices, "junction");
  await assert.rejects(nativeInputs(editor, allocation), /linked or special entries/u);
  await assert.rejects(readMember(allocation, "../LICENSE"), /AssertionError/u);
  assert.deepEqual(await nativeInputs(editor, editor), expected);
});

void test("binds the complete checkout path scope and refuses absent actual Git before artifact writes", async (context) => {
  const editor = path.resolve(__dirname, "../../..");
  const root = path.resolve(editor, "../..");
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-native-source-paths-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const checkout = path.join(allocation, "checkout");
  const action = ".github/actions/install-editor-host/action.yml";
  const names = [
    action,
    ".github/workflows/ci-vscode.yml",
    "LICENSE",
    "editors/vscode/scripts/build-windows-native.mjs",
  ];
  for (const name of names) {
    const destination = path.join(checkout, name);
    await mkdir(path.dirname(destination), { recursive: true });
    const bytes = await readFile(path.join(root, name));
    await writeFile(destination, bytes, { flag: "wx" });
    assert.deepEqual(await readFile(destination), bytes);
  }
  for (const args of [
    ["init", "--quiet"],
    ["config", "core.autocrlf", "false"],
    ["add", "."],
    [
      "-c",
      "user.name=RigorFoundry source qualification",
      "-c",
      "user.email=qualification@example.invalid",
      "commit",
      "--quiet",
      "--no-gpg-sign",
      "--message=test: actual source path fixture",
    ],
  ]) {
    await runCli("git", args, { cwd: checkout, timeoutMilliseconds: 10_000 });
  }
  assert.ok(Object.isFrozen(sourcePaths));
  assert.ok(sourcePaths.includes(action));
  const status = ["status", "--porcelain", "--untracked-files=all", "--", ...sourcePaths];
  assert.equal(git(checkout, status), "");
  const before = await sourceInputs(checkout);
  await writeFile(
    path.join(checkout, action),
    Buffer.concat([await readFile(path.join(checkout, action)), Buffer.from("\n")]),
  );
  assert.match(git(checkout, status), / M \.github\/actions\/install-editor-host\/action\.yml/u);
  const after = await sourceInputs(checkout);
  assert.notEqual(after[action], before[action]);
  for (const name of names.filter((name) => name !== action))
    assert.equal(after[name], before[name]);
  const noGit: NodeJS.ProcessEnv = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => name.toUpperCase() !== "PATH"),
  );
  noGit["PATH"] = path.join(allocation, "no-executables");
  await mkdir(noGit["PATH"]);
  const absent = path.join(allocation, "missing-git-artifact");
  await assert.rejects(
    runCli(process.execPath, [path.join(editor, "scripts/native-artifact.mjs"), "pack", absent], {
      cwd: editor,
      environment: noGit,
      timeoutMilliseconds: 10_000,
    }),
    (error: unknown): boolean => {
      assert.ok(error instanceof CommandExecutionFailure);
      assert.match(error.output.stderr, /git ENOENT/u);
      assert.equal(error.output.stdout, "");
      return true;
    },
  );
  await assert.rejects(lstat(absent), { code: "ENOENT" });
});
