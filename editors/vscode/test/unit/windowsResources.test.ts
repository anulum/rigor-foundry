// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — native resource ownership and release contracts

/**
 * Exercise exported resource ownership against actual NTFS files and native API results.
 * Check exact bytes and metadata, failed acquisition, and refusal after owned handles close.
 * @module
 */

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { link, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import type { NativeFileIdentity } from "../../src/windowsResources.js";

void test(
  "preserves native bytes and every identity field across owned file and directory release",
  { skip: process.platform !== "win32" },
  async (context) => {
    const { WindowsDirectory, WindowsFile, bytesDigest, nativePath, requireHandle, sameIdentity } =
      await import("../../src/windowsResources.js");
    const abi = await import("../../src/windowsAbi.js");
    const root = await mkdtemp(path.join(tmpdir(), "rigor-native-resource-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const parent = WindowsDirectory.open(root);
    const parentIdentity = parent.identity();
    try {
      const current = abi.nativePointer(abi.getCurrentProcess());
      assert.ok(current !== null);
      const duplicate: unknown[] = [null];
      assert.equal(abi.duplicateHandle(current, parent.handle, current, duplicate, 0, 0, 2), 1);
      const wrongKind = new WindowsFile(requireHandle(duplicate[0]));
      try {
        assert.throws(() => wrongKind.identity(), /required non-reparse disk object/u);
      } finally {
        wrongKind.close();
      }
      assert.equal(parent.identity().fileId, parentIdentity.fileId);
      const directory = parent.child("owned", true);
      const directoryIdentity = directory.identity();
      try {
        assert.throws(() => parent.child("OWNED"), /native child directory binding changed/u);
        const writer = directory.file("content.bin", true);
        const bytes = Buffer.alloc(1_048_577, 97);
        try {
          assert.equal(requireHandle(writer.handle), writer.handle);
          writer.write(bytes);
          const identity = writer.identity();
          assert.equal(identity.size, BigInt(bytes.length));
          assert.equal(identity.links, 1);
          assert.equal(nativePath(writer.handle), directory.nativePath + "\\content.bin");
          assert.ok(sameIdentity(identity, writer.identity()));
          const comparisons: NativeFileIdentity[] = [
            { ...identity, volume: identity.volume + 1 },
            { ...identity, fileId: identity.fileId + 1n },
            { ...identity, attributes: identity.attributes ^ 1 },
            { ...identity, links: identity.links + 1 },
            { ...identity, size: identity.size + 1n },
            { ...identity, written: identity.written + 1n },
            { ...identity, created: identity.created + 1n },
          ];
          for (const expected of comparisons)
            assert.equal(sameIdentity(identity, expected), false);
          writer.permissions("FR");
          writer.permissions("FA");
        } finally {
          writer.close();
        }
        assert.throws(
          () => directory.file("CONTENT.bin"),
          /native file differs from its retained parent and name/u,
        );
        const reader = directory.file("content.bin");
        try {
          assert.throws(
            () => reader.read(bytes.length - 1),
            /exceeds its type, link or byte bound/u,
          );
          const actual = reader.read(bytes.length);
          assert.deepEqual(actual, bytes);
          assert.equal(bytesDigest(actual), createHash("sha256").update(bytes).digest("hex"));
          assert.throws(() => reader.read(bytes.length), /shortened during its read/u);
          assert.throws(() => {
            reader.write(Buffer.from("write refused"));
          }, /private input write/u);
          assert.throws(() => {
            reader.write(Buffer.alloc(0));
          }, /private input flush/u);
          assert.throws(() => {
            reader.permissions("FR");
          }, /private input DACL/u);
          assert.throws(() => {
            reader.discard();
          }, /owned file discard/u);
          assert.deepEqual(await readFile(path.join(root, "owned", "content.bin")), bytes);
        } finally {
          reader.close();
        }
        const cleanup = directory.file("content.bin", false, true, true);
        try {
          cleanup.discard();
        } finally {
          cleanup.close();
        }
        await assert.rejects(readFile(path.join(root, "owned", "content.bin")), {
          code: "ENOENT",
        });
      } finally {
        directory.close();
      }
      parent.discardChild("owned", directoryIdentity);
      await assert.rejects(stat(path.join(root, "owned")), { code: "ENOENT" });
      assert.equal(parent.identity().fileId, parentIdentity.fileId);
    } finally {
      parent.close();
    }
  },
);

void test(
  "failed real child acquisition leaves the retained parent usable",
  { skip: process.platform !== "win32" },
  async (context) => {
    const { WindowsDirectory, WindowsFile, WindowsResourceError, requireHandle } =
      await import("../../src/windowsResources.js");
    const abi = await import("../../src/windowsAbi.js");
    const root = await mkdtemp(path.join(tmpdir(), "rigor-native-open-failure-"));
    const unused = Array.from(
      { length: 23 },
      (_, index) => String.fromCharCode(90 - index) + ":",
    ).find((drive) => abi.getDriveType(drive + "\\") === 1);
    assert.ok(unused);
    const driveRoot = unused + "\\";
    context.after(async () => {
      assert.equal(abi.getDriveType(driveRoot), 1, "retain fixture while mapping is unresolved");
      await rm(root, { recursive: true, force: true });
    });
    const file = path.join(root, "regular.txt");
    await writeFile(file, "original bytes\n", "utf8");
    await writeFile(path.join(root, "linked.txt"), "owned linked bytes\n", "utf8");
    await link(path.join(root, "linked.txt"), path.join(root, "second-link.txt"));
    await mkdir(path.join(root, "directory"));
    await writeFile(path.join(root, "directory", "retained.txt"), "retained child\n", "utf8");
    await symlink(path.join(root, "directory"), path.join(root, "own-junction"), "junction");
    for (const input of ["relative", "C:relative", "\\\\localhost\\share"])
      assert.throws(() => WindowsDirectory.open(input), /drive-absolute local path/u);
    assert.throws(() => WindowsDirectory.open(driveRoot), /fixed local NTFS volume/u);
    const systemRoot = process.env["SystemRoot"];
    assert.ok(systemRoot);
    const subst = path.join(systemRoot, "System32", "subst.exe");
    const execute = promisify(execFile);
    const fixtureIdentity = await stat(root, { bigint: true });
    for (const scenario of ["complete", "invalid-target", "duplicate-after-mapping"]) {
      const target = scenario === "invalid-target" ? path.join(root, "absent-subst-target") : root;
      const [operation] = await Promise.allSettled([
        (async (): Promise<void> => {
          await execute(subst, [unused, target], { cwd: root, timeout: 10_000, maxBuffer: 65536 });
          assert.equal(abi.getDriveType(driveRoot), 3);
          assert.throws(
            () => WindowsDirectory.open(driveRoot),
            /native root has no supported GUID namespace/u,
          );
          if (scenario === "duplicate-after-mapping")
            await execute(subst, [unused, root], { cwd: root, timeout: 10_000, maxBuffer: 65536 });
        })(),
      ]);
      const [cleanup] = await Promise.allSettled([
        (async (): Promise<void> => {
          const mappedIdentity = await stat(driveRoot, { bigint: true });
          assert.equal(mappedIdentity.dev, fixtureIdentity.dev, "mapping must retain this volume");
          assert.equal(
            mappedIdentity.ino,
            fixtureIdentity.ino,
            "mapping must retain this directory",
          );
          await execute(subst, [unused, "/d"], { cwd: root, timeout: 10_000, maxBuffer: 65536 });
        })(),
      ]);
      const failures = [operation, cleanup].flatMap((outcome): unknown[] =>
        outcome.status === "rejected" ? [outcome.reason as unknown] : [],
      );
      const settled =
        failures.length === 0
          ? Promise.resolve()
          : Promise.reject(
              new AggregateError(failures, "owned SUBST operation and cleanup failures"),
            );
      if (scenario === "complete") await settled;
      else {
        await assert.rejects(settled, (error: unknown): boolean => {
          assert.ok(error instanceof AggregateError);
          assert.deepEqual(error.errors, failures);
          assert.equal(error.errors.length, scenario === "invalid-target" ? 2 : 1);
          const original: unknown = error.errors[0];
          assert.ok(original instanceof Error && "code" in original);
          assert.ok(typeof original.code === "number" && original.code !== 0);
          return true;
        });
      }
      assert.equal(abi.getDriveType(driveRoot), 1);
      context.diagnostic(
        JSON.stringify({
          scenario,
          operation: operation.status,
          cleanup: cleanup.status,
          mappingAbsentAfter: true,
        }),
      );
    }
    const parent = WindowsDirectory.open(root);
    try {
      const before = parent.identity();
      assert.throws(
        () => parent.child("own-junction"),
        /native Windows resource is not the required non-reparse disk object/u,
      );
      await writeFile(path.join(root, "empty.txt"), Buffer.alloc(0));
      for (const [name, message] of [
        ["regular.txt", /native Windows file read failed/u],
        ["empty.txt", /native Windows file end check failed/u],
      ] as const) {
        const restricted = new WindowsFile(
          requireHandle(abi.createFile(path.join(root, name), 0x80, 1, null, 3, 0x2200000, null)),
        );
        try {
          assert.equal(restricted.identity().links, 1);
          assert.throws(() => restricted.read(1024), message);
        } finally {
          restricted.close();
        }
      }
      const linked = parent.file("linked.txt");
      try {
        assert.equal(linked.identity().links, 2);
        assert.throws(() => linked.read(1024), /exceeds its type, link or byte bound/u);
      } finally {
        linked.close();
      }
      const component = path.basename(root);
      assert.notEqual(component.toUpperCase(), component);
      assert.throws(
        () => WindowsDirectory.open(path.join(path.dirname(root), component.toUpperCase())),
        /native directory name differs from its retained parent/u,
      );
      assert.throws(() => parent.child("regular.txt"), WindowsResourceError);
      assert.throws(() => WindowsDirectory.open(file), WindowsResourceError);
      assert.throws(() => parent.file("directory"), WindowsResourceError);
      assert.throws(() => parent.file("not-created.txt"), WindowsResourceError);
      for (const name of [
        "",
        ".",
        "..",
        "trailing.",
        "trailing ",
        "a:b",
        "a/b",
        "a\\b",
        "NUL",
        "COM1.txt",
        "bad\u0001name",
      ]) {
        assert.throws(() => parent.child(name), /ambiguous component/u);
        assert.throws(() => parent.file(name), /ambiguous component/u);
      }
      assert.throws(() => parent.file("x".repeat(32767)), /exceeds the UTF-16 bound/u);
      const nonempty = parent.child("directory");
      const nonemptyIdentity = nonempty.identity();
      nonempty.close();
      assert.throws(() => {
        parent.discardChild("directory", before);
      }, /owned private directory changed before cleanup/u);
      assert.throws(() => {
        parent.discardChild("directory", nonemptyIdentity);
      }, /owned directory discard/u);
      assert.equal(
        await readFile(path.join(root, "directory", "retained.txt"), "utf8"),
        "retained child\n",
      );
      assert.equal(parent.identity().fileId, before.fileId);
      const actual = parent.file("regular.txt");
      try {
        assert.equal(actual.read(1024).toString("utf8"), "original bytes\n");
      } finally {
        actual.close();
      }
    } finally {
      parent.close();
    }
    assert.equal(await readFile(file, "utf8"), "original bytes\n");
  },
);

void test(
  "closed owned handles refuse further use and repeated release is harmless",
  { skip: process.platform !== "win32" },
  async (context) => {
    const { WindowsDirectory, WindowsResourceError } =
      await import("../../src/windowsResources.js");
    const abi = await import("../../src/windowsAbi.js");
    const root = await mkdtemp(path.join(tmpdir(), "rigor-native-release-"));
    context.after(async () => {
      await rm(root, { recursive: true, force: true });
    });
    const parent = WindowsDirectory.open(root);
    try {
      const file = parent.file("closed.txt", true);
      try {
        file.close();
        file.close();
        assert.throws(() => file.identity(), /native Windows file is closed/u);
        assert.throws(() => file.read(1024), /native Windows file is closed/u);
      } finally {
        file.close();
      }
      parent.close();
      parent.close();
      assert.throws(() => parent.identity(), /native Windows directory is closed/u);
      assert.throws(() => parent.child("unused"), /native Windows directory is closed/u);
      assert.throws(() => parent.file("unused"), /native Windows directory is closed/u);
    } finally {
      parent.close();
    }
    const invalidated = WindowsDirectory.open(root);
    assert.equal(abi.closeHandle(invalidated.handle), 1);
    assert.throws(
      () => {
        invalidated.close();
      },
      (error: unknown): boolean => {
        assert.ok(error instanceof AggregateError);
        assert.equal(error.message, "native directory handles did not all close");
        assert.equal(error.errors.length, 1);
        const original: unknown = error.errors[0];
        assert.ok(original instanceof WindowsResourceError);
        assert.equal(original.code, 6);
        assert.equal(original.message, "native Windows directory close failed (6)");
        return true;
      },
    );
  },
);

void test(
  "native failure codes and exported ABI value bounds retain their declared representations",
  { skip: process.platform !== "win32" },
  async () => {
    const {
      WindowsFile,
      WindowsResourceError,
      nativePath,
      requireHandle,
      requireInteger,
      requireRecord,
    } = await import("../../src/windowsResources.js");
    const invalid = new WindowsFile(0n);
    assert.throws(() => invalid.identity(), WindowsResourceError);
    assert.throws(() => {
      invalid.close();
    }, WindowsResourceError);
    assert.throws(
      () => nativePath(0n),
      (error: unknown): boolean => {
        assert.ok(error instanceof WindowsResourceError);
        assert.equal(error.code, 6);
        assert.equal(error.message, "native Windows final path failed (6)");
        return true;
      },
    );
    const saved = new WindowsResourceError("saved operation", 32);
    assert.equal(saved.code, 32);
    assert.equal(saved.message, "native Windows saved operation failed (32)");
    for (const invalid of [null, 0n, -1n, 0xffffffffffffffffn])
      assert.throws(() => requireHandle(invalid), WindowsResourceError);
    const actual = { count: 1, pointer: 1n };
    assert.equal(requireRecord(actual), actual);
    for (const invalid of [null, [], "record", 1, true, undefined])
      assert.throws(() => requireRecord(invalid), /structure has an unsupported representation/u);
    assert.equal(requireInteger(0), 0);
    assert.equal(requireInteger(0xffffffff), 0xffffffff);
    assert.equal(requireInteger(5, 5), 5);
    for (const invalid of ["1", 1n, NaN, Infinity, -1, 0.5, 0x100000000])
      assert.throws(() => requireInteger(invalid), /integer is outside the admitted bound/u);
    assert.throws(() => requireInteger(6, 5), /integer is outside the admitted bound/u);
  },
);
