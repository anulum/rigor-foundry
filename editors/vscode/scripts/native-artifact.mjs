// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — source-bound native artifact transport

/**
 * Build or locally retain a native payload, then admit exact bytes into matching source.
 * Local transport receipts cannot be admitted as fresh hosted Windows builds.
 * @module
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import { copyFile, lstat, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  artifactMembers,
  digest,
  git,
  members,
  nativeInputs,
  readMember,
  record,
  sourceInputs,
  sourcePaths,
} from "./native-artifact-inputs.mjs";

const editor = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const root = path.resolve(editor, "../..");
const [mode, directory, venue] = process.argv.slice(2);
assert.ok(
  mode === "pack" || mode === "build" || mode === "verify",
  "expected pack, build or verify",
);
assert.ok(
  directory && (venue === undefined || venue === "--github"),
  "expected artifact path and optional --github",
);
const artifact = path.resolve(directory);
assert.ok(
  artifact !== editor && !artifact.startsWith(editor + path.sep),
  "artifact must live outside editor sources",
);
const hosted = venue === "--github";
assert.ok(mode !== "build" || hosted, "fresh build requires hosted Windows identity");
assert.ok(mode !== "pack" || !hosted, "local retained payload cannot claim a hosted build");
const revision = git(root, ["rev-parse", "HEAD"]).trim();
assert.match(revision, /^[a-f0-9]{40}$/u);
const inputs = await sourceInputs(root);
const sourceSha256 = digest(JSON.stringify(inputs));
const identity = hosted
  ? {
      venue: "github",
      revision,
      repository: process.env["GITHUB_REPOSITORY"],
      runId: process.env["GITHUB_RUN_ID"],
      runAttempt: process.env["GITHUB_RUN_ATTEMPT"],
      producer: "vscode-native",
      platform: "win32",
      architecture: "x64",
      node: process.version,
    }
  : {
      venue: "local",
      revision,
      platform: process.platform,
      architecture: process.arch,
      node: process.version,
    };
if (hosted) {
  assert.equal(
    process.env["GITHUB_ACTIONS"],
    "true",
    "hosted admission requires actual GitHub execution",
  );
  assert.equal(
    process.env["GITHUB_SHA"],
    revision,
    "checkout does not match the invoking revision",
  );
  assert.match(identity.repository ?? "", /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/u);
  assert.match(identity.runId ?? "", /^[1-9][0-9]*$/u);
  assert.match(identity.runAttempt ?? "", /^[1-9][0-9]*$/u);
  const dirty = git(root, [
    "status",
    "--porcelain",
    "--untracked-files=all",
    "--",
    ...sourcePaths,
  ]);
  assert.equal(dirty, "", "hosted artifact source must match the clean invoking checkout");
}
const payload = path.join(artifact, "payload");
if (mode === "verify") {
  assert.deepEqual(
    await members(artifact),
    [...artifactMembers.map((name) => "payload/" + name), "receipt.json"].sort(),
    "native artifact member inventory differs",
  );
  const receiptText = (await readMember(artifact, "receipt.json")).toString("utf8");
  const receipt = record(JSON.parse(receiptText));
  assert.equal(receiptText, JSON.stringify(receipt, null, 2) + "\n", "ambiguous native receipt");
  const assets = await nativeInputs(editor, payload);
  assert.deepEqual(
    receipt,
    {
      schema: 1,
      identity,
      sourceSha256,
      sources: inputs,
      assets,
    },
    "native artifact identity, source or payload differs",
  );
  // Complete admission precedes every destination write, including existing-file checks.
  try {
    const existing = await members(path.join(editor, "native/koffi"));
    assert.ok(
      existing.every((name) => artifactMembers.includes("native/koffi/" + name)),
      "native destination contains unexpected members",
    );
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
  }
  for (const name of artifactMembers) {
    try {
      assert.ok(
        (await readMember(editor, name)).equals(await readMember(payload, name)),
        "existing native artifact destination differs",
      );
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
      // Check all existing ancestors before any recursive mkdir or write.
      let current = editor;
      for (const part of name.split("/").slice(0, -1)) {
        current = path.join(current, part);
        try {
          assert.ok(
            (await lstat(current)).isDirectory(),
            "native destination parent is not a real directory",
          );
        } catch (parentError) {
          if (!(
            parentError instanceof Error &&
            "code" in parentError &&
            parentError.code === "ENOENT"
          ))
            throw parentError;
        }
      }
    }
  }
  for (const name of artifactMembers) {
    const destination = path.join(editor, name);
    await mkdir(path.dirname(destination), { recursive: true });
    try {
      await copyFile(path.join(payload, name), destination, constants.COPYFILE_EXCL);
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "EEXIST")) throw error;
      assert.ok(
        (await readMember(editor, name)).equals(await readMember(payload, name)),
        "existing native artifact destination differs",
      );
    }
  }
  assert.deepEqual(await nativeInputs(editor, editor), assets);
  assert.deepEqual(await sourceInputs(root), inputs, "source changed during native admission");
} else {
  if (mode === "build") {
    assert.equal(process.platform, "win32", "native build requires actual Windows");
    assert.equal(process.arch, "x64");
    assert.equal(process.env["GITHUB_JOB"], "vscode-native");
    for (const name of ["native/koffi", "LICENSE.txt"]) {
      await assert.rejects(
        lstat(path.join(editor, name)),
        { code: "ENOENT" },
        "fresh hosted build must not reuse existing native assets",
      );
    }
    const build = spawnSync(
      process.execPath,
      [path.join(editor, "scripts/build-windows-native.mjs")],
      {
        cwd: editor,
        stdio: "inherit",
        shell: false,
      },
    );
    if (build.error) throw build.error;
    assert.equal(build.status, 0, "native compiler or binding staging failed");
  }
  const assets = await nativeInputs(editor, editor);
  await mkdir(artifact, { recursive: false });
  for (const name of artifactMembers) {
    const destination = path.join(payload, name);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, await readMember(editor, name), { flag: "wx" });
  }
  assert.deepEqual(
    await sourceInputs(root),
    inputs,
    "source changed during native artifact creation",
  );
  assert.deepEqual(await nativeInputs(editor, payload), assets, "copied native payload changed");
  assert.equal(
    git(root, ["rev-parse", "HEAD"]).trim(),
    revision,
    "revision changed during native build",
  );
  await writeFile(
    path.join(artifact, "receipt.json"),
    JSON.stringify(
      {
        schema: 1,
        identity,
        sourceSha256,
        sources: inputs,
        assets,
      },
      null,
      2,
    ) + "\n",
    { flag: "wx" },
  );
}
process.stdout.write(
  JSON.stringify({ mode, venue: identity.venue, revision, sourceSha256, artifact }) + "\n",
);
