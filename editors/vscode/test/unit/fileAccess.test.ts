// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — bounded file-access tests

import assert from "node:assert/strict";
import {mkdtemp, rm, symlink, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import path from "node:path";
import test from "node:test";
import {readBoundedJson, resolveWorkspacePath} from "../../src/fileAccess.js";

test("reads bounded workspace JSON and rejects lexical escape", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-files-"));
  context.after(async () => await rm(root, {recursive: true, force: true}));
  const evidence = path.join(root, "report.json");
  await writeFile(evidence, "{\"ok\":true}\n", "utf8");
  assert.deepEqual(await readBoundedJson(root, evidence, 1024), {ok: true});
  assert.throws(() => resolveWorkspacePath(root, "../outside.json"), /escapes/u);
});

test("rejects a symlinked evidence file", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-files-"));
  const outside = await mkdtemp(path.join(tmpdir(), "rigor-vscode-outside-"));
  context.after(async () => {
    await rm(root, {recursive: true, force: true});
    await rm(outside, {recursive: true, force: true});
  });
  const target = path.join(outside, "report.json");
  const link = path.join(root, "report.json");
  await writeFile(target, "{}\n", "utf8");
  await symlink(target, link);
  await assert.rejects(readBoundedJson(root, link, 1024), /outside|symbolic/u);
});

test("rejects non-UTF-8 evidence bytes instead of replacing them", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-files-"));
  context.after(async () => await rm(root, {recursive: true, force: true}));
  const evidence = path.join(root, "report.json");
  await writeFile(evidence, Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]));
  await assert.rejects(readBoundedJson(root, evidence, 1024), /not valid UTF-8/u);
});
