// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — bounded file-access tests

/**
 * Exercise public evidence access against actual workspace files and directories.
 * Check containment, byte ceilings, exact digests, encoding, and malformed JSON refusals.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  readBoundedJson,
  readBoundedJsonWithDigest,
  resolveWorkspacePath,
  verifyExistingWorkspacePath,
  verifyExistingRegularWorkspacePath,
} from "../../src/fileAccess.js";
import { EvidenceRefusal } from "../../src/contracts.js";

/**
 * Check real file descriptors, bounded byte reads, containment, and authored refusals.
 * @returns Completion after the actual filesystem cases settle through the native test runner.
 */
async function run(): Promise<void> {
  await test("reads bounded workspace JSON and rejects lexical escape", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-files-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const evidence = path.join(root, "report.json");
    await writeFile(evidence, '{"ok":true}\n', "utf8");
    assert.deepEqual(await readBoundedJson(root, evidence, 1024), { ok: true });
    assert.throws(() => resolveWorkspacePath(root, "../outside.json"), /escapes/u);
  });

  await test("rejects a symlinked evidence file", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-files-"));
    const outside = await mkdtemp(path.join(tmpdir(), "rigor-vscode-outside-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    });
    const target = path.join(outside, "report.json");
    const link = path.join(root, "report.json");
    await writeFile(target, "{}\n", "utf8");
    await symlink(target, link);
    await assert.rejects(readBoundedJson(root, link, 1024), /outside|symbolic/u);
  });

  await test("rejects non-UTF-8 evidence bytes instead of replacing them", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-files-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const evidence = path.join(root, "report.json");
    await writeFile(evidence, Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]));
    await assert.rejects(readBoundedJson(root, evidence, 1024), /not valid UTF-8/u);
  });

  await test("resolves contained paths and refuses invalid configured paths", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-paths-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    assert.equal(resolveWorkspacePath(root, "."), root);
    assert.equal(
      resolveWorkspacePath(root, "evidence/report.json"),
      path.join(root, "evidence", "report.json"),
    );
    for (const value of ["", path.join(root, "absolute.json"), "evidence\0.json"]) {
      assert.throws(() => resolveWorkspacePath(root, value), /non-empty and workspace-relative/u);
    }
    assert.throws(() => resolveWorkspacePath(root, ".."), /escapes/u);
  });

  await test("checks canonical containment and requires an actual regular file", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-regular-"));
    const outside = await mkdtemp(path.join(tmpdir(), "rigor-vscode-outside-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    });
    const evidence = path.join(root, "evidence.json");
    await writeFile(evidence, "{}", "utf8");
    assert.equal(await verifyExistingWorkspacePath(root, root), root);
    assert.equal(await verifyExistingRegularWorkspacePath(root, evidence), evidence);
    await assert.rejects(verifyExistingWorkspacePath(root, outside), /outside the workspace/u);
    await assert.rejects(
      verifyExistingRegularWorkspacePath(root, root),
      /non-symlink regular file/u,
    );
    const link = path.join(root, "linked.json");
    await symlink(evidence, link);
    await assert.rejects(
      verifyExistingRegularWorkspacePath(root, link),
      /non-symlink regular file/u,
    );
  });

  await test("rejects invalid byte limits before opening evidence", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-bounds-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const file = path.join(root, "not-created.json");
    for (const limit of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 67_108_865]) {
      await assert.rejects(readBoundedJson(root, file, limit), /integer from 1 through/u);
    }
  });

  await test("preserves exact byte identities and accepts the exact configured limit", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-digest-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const file = path.join(root, "evidence.json");
    const bytes = Buffer.from('{"unicode":"ž"}\n', "utf8");
    await writeFile(file, bytes);
    const evidence = await readBoundedJsonWithDigest(root, file, bytes.length);
    assert.deepEqual(evidence.value, { unicode: "ž" });
    assert.equal(evidence.contentSha256, createHash("sha256").update(bytes).digest("hex"));
    assert.deepEqual(evidence.contentBytes, bytes);
    await assert.rejects(readBoundedJson(root, file, bytes.length - 1), /exceeds the configured/u);
  });

  await test(
    "refuses an actual Windows writer sharing conflict and reads again after release",
    { skip: process.platform !== "win32" },
    async (context) => {
      const { WindowsDirectory } = await import("../../src/windowsResources.js");
      const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-sharing-"));
      context.after(async () => {
        await rm(root, { recursive: true, force: true });
      });
      const directory = WindowsDirectory.open(root);
      const writer = directory.file("evidence.json", true);
      const file = path.join(root, "evidence.json");
      const bytes = Buffer.from('{"available":true}\n', "utf8");
      try {
        writer.write(bytes);
        await assert.rejects(
          readBoundedJsonWithDigest(root, file, 1024),
          (error: unknown): boolean => {
            assert.ok(error instanceof EvidenceRefusal);
            assert.equal(
              error.message,
              "native evidence file could not be read as a stable contained regular file",
            );
            assert.ok(error.cause instanceof Error);
            assert.equal(error.cause.message, "native evidence worker refused its operation");
            const native = error.cause.cause;
            assert.ok(typeof native === "object" && native !== null);
            assert.ok("stderr" in native && Buffer.isBuffer(native.stderr));
            assert.match(
              native.stderr.toString("utf8"),
              /native Windows relative open failed \(32\)/u,
            );
            assert.ok(!error.message.includes(root));
            return true;
          },
        );
      } finally {
        writer.close();
        directory.close();
      }
      const actual = await readBoundedJsonWithDigest(root, file, 1024);
      assert.deepEqual(actual.value, { available: true });
      assert.deepEqual(actual.contentBytes, bytes);
      assert.equal(actual.contentSha256, createHash("sha256").update(bytes).digest("hex"));
    },
  );

  await test("rejects directories and malformed JSON with an authored JSON refusal", async (context) => {
    const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-json-refusal-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const directory = path.join(root, "directory");
    await mkdir(directory);
    await assert.rejects(readBoundedJson(root, directory, 1024), /regular file/u);
    const file = path.join(root, "evidence.json");
    for (const value of ["", "{private-parser-detail}"]) {
      await writeFile(file, value, "utf8");
      await assert.rejects(readBoundedJson(root, file, 1024), (error: unknown): boolean => {
        assert.ok(error instanceof EvidenceRefusal);
        assert.equal(error.message, "evidence file is not valid JSON");
        assert.ok(error.cause instanceof SyntaxError);
        return true;
      });
    }
  });
}

void run();
