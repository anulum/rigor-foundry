// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — real native artifact transfer and refusal tests

/**
 * Transfer the retained real Windows image through actual local Git and CLI boundaries.
 * Local receipts remain local; these cases never impersonate a hosted Windows build.
 * @module
 */

import assert from "node:assert/strict";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";
import { artifactMembers, sourceInputs } from "../../scripts/native-artifact-inputs.mjs";

void test("transfers the original native image and refuses stale or altered artifacts before writes", async (context) => {
  const source = path.resolve(__dirname, "../../../../..");
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-native-artifact-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const checkout = path.join(allocation, "checkout");
  const editor = path.join(checkout, "editors/vscode");
  const originalEditor = path.join(source, "editors/vscode");
  const inputs = await sourceInputs(source);
  for (const name of Object.keys(inputs)) {
    const destination = path.join(checkout, name);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, await readFile(path.join(source, name)), { flag: "wx" });
  }
  await runCli("git", ["init", "--quiet", "--initial-branch=main", checkout], {
    cwd: allocation,
    timeoutMilliseconds: 10_000,
  });
  await runCli("git", ["add", "."], { cwd: checkout, timeoutMilliseconds: 10_000 });
  await runCli(
    "git",
    [
      "-c",
      "user.name=Native artifact test",
      "-c",
      "user.email=native-artifact@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "test: bind actual copied editor inputs",
    ],
    {
      cwd: checkout,
      timeoutMilliseconds: 10_000,
    },
  );
  for (const name of artifactMembers) {
    const destination = path.join(editor, name);
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, await readFile(path.join(originalEditor, name)), { flag: "wx" });
  }
  const command = path.join(editor, "scripts/native-artifact.mjs");
  const artifact = path.join(allocation, "artifact");
  const options = { cwd: checkout, timeoutMilliseconds: 15_000 };
  const packed = await runCli(process.execPath, [command, "pack", artifact], options);
  assert.equal(packed.stderr, "");
  const receiptBytes = await readFile(path.join(artifact, "receipt.json"));
  const receipt: unknown = JSON.parse(receiptBytes.toString("utf8"));
  assert.ok(typeof receipt === "object" && receipt !== null && "identity" in receipt);
  assert.ok(
    typeof receipt.identity === "object" &&
      receipt.identity !== null &&
      "venue" in receipt.identity,
  );
  assert.equal(receipt.identity.venue, "local");
  for (const name of artifactMembers)
    assert.deepEqual(
      await readFile(path.join(artifact, "payload", name)),
      await readFile(path.join(originalEditor, name)),
    );
  await rm(path.join(editor, "native/koffi"), { recursive: true });
  await rm(path.join(editor, "LICENSE.txt"));
  const admitted = await runCli(process.execPath, [command, "verify", artifact], options);
  assert.equal(admitted.stderr, "");
  const before = new Map<string, { bytes: Buffer; mtime: bigint }>();
  for (const name of artifactMembers)
    before.set(name, {
      bytes: await readFile(path.join(editor, name)),
      mtime: (await stat(path.join(editor, name), { bigint: true })).mtimeNs,
    });
  await runCli(process.execPath, [command, "verify", artifact], options);
  for (const [name, value] of before) {
    assert.deepEqual(await readFile(path.join(editor, name)), value.bytes);
    assert.equal((await stat(path.join(editor, name), { bigint: true })).mtimeNs, value.mtime);
  }
  /**
   * Invoke the public consumer and require refusal without destination mutation.
   * @param args - Actual child arguments.
   * @param diagnostic - Expected public failure.
   */
  async function refuse(args: string[], diagnostic: RegExp): Promise<void> {
    await assert.rejects(
      runCli(process.execPath, [command, ...args], options),
      (error: unknown): boolean => {
        assert.ok(error instanceof CommandExecutionFailure);
        assert.equal(error.output.stdout, "");
        assert.match(error.output.stderr, diagnostic);
        return true;
      },
    );
    for (const [name, value] of before) {
      assert.deepEqual(await readFile(path.join(editor, name)), value.bytes);
      assert.equal((await stat(path.join(editor, name), { bigint: true })).mtimeNs, value.mtime);
    }
  }
  await context.test("local transport cannot claim a hosted build", async () => {
    await refuse(
      ["pack", path.join(allocation, "false-hosted"), "--github"],
      /local retained payload/u,
    );
    await refuse(
      ["build", path.join(allocation, "false-build")],
      /requires hosted Windows identity/u,
    );
    await refuse(
      ["verify", artifact, "--github"],
      /GitHub execution|invoking revision|clean invoking checkout|identity, source or payload differs/u,
    );
  });
  await context.test(
    "invalid invocation is refused before artifact or destination writes",
    async () => {
      for (const [args, diagnostic] of [
        [["unknown", artifact], /expected pack, build or verify/u],
        [["verify"], /expected artifact path/u],
        [["verify", artifact, "--unknown"], /expected artifact path/u],
        [["pack", editor], /artifact must live outside editor sources/u],
        [
          ["pack", path.join(editor, "native-artifact")],
          /artifact must live outside editor sources/u,
        ],
        [["pack", artifact], /EEXIST/u],
      ] satisfies [string[], RegExp][]) {
        await refuse(args, diagnostic);
      }
      assert.deepEqual(await readFile(path.join(artifact, "receipt.json")), receiptBytes);
    },
  );
  await context.test(
    "noncanonical receipt bytes are rejected without rewriting their representation",
    async () => {
      const filename = path.join(artifact, "receipt.json");
      const changed = Buffer.concat([receiptBytes, Buffer.from("\n")]);
      await writeFile(filename, changed);
      await refuse(["verify", artifact], /ambiguous native receipt/u);
      assert.deepEqual(await readFile(filename), changed);
      await writeFile(filename, receiptBytes);
    },
  );
  await context.test("unexpected native destination members are retained on refusal", async () => {
    const filename = path.join(editor, "native/koffi/unexpected.txt");
    await writeFile(filename, "unregistered native input", { flag: "wx" });
    await refuse(["verify", artifact], /native destination contains unexpected members/u);
    assert.equal(await readFile(filename, "utf8"), "unregistered native input");
    await rm(filename);
  });
  await context.test(
    "aliased and nondirectory native destinations are refused before installation",
    async () => {
      const destination = path.join(editor, "native/koffi");
      const retained = path.join(allocation, "retained-native");
      await rename(destination, retained);
      await symlink(retained, destination, "junction");
      await assert.rejects(
        runCli(process.execPath, [command, "verify", artifact], options),
        (error: unknown): boolean => {
          assert.ok(error instanceof CommandExecutionFailure);
          assert.match(error.output.stderr, /root must be a real directory/u);
          assert.equal(error.output.stdout, "");
          return true;
        },
      );
      for (const [name, value] of before) {
        assert.deepEqual(await readFile(path.join(editor, name)), value.bytes);
        assert.equal((await stat(path.join(editor, name), { bigint: true })).mtimeNs, value.mtime);
      }
      await rm(destination);
      await writeFile(destination, "ordinary file blocks native installation", { flag: "wx" });
      await assert.rejects(
        runCli(process.execPath, [command, "verify", artifact], options),
        (error: unknown): boolean => {
          assert.ok(error instanceof CommandExecutionFailure);
          assert.match(error.output.stderr, /root must be a real directory/u);
          assert.equal(error.output.stdout, "");
          return true;
        },
      );
      assert.equal(
        await readFile(destination, "utf8"),
        "ordinary file blocks native installation",
      );
      await rm(destination);
      await rename(retained, destination);
      for (const [name, value] of before) {
        assert.deepEqual(await readFile(path.join(editor, name)), value.bytes);
        assert.equal((await stat(path.join(editor, name), { bigint: true })).mtimeNs, value.mtime);
      }
    },
  );
  await context.test("changed source refuses the original retained payload", async () => {
    const filename = path.join(editor, "README.md");
    const bytes = await readFile(filename);
    await writeFile(filename, Buffer.concat([bytes, Buffer.from("\n")]));
    await refuse(["verify", artifact], /identity, source or payload differs/u);
    await writeFile(filename, bytes);
  });
  await context.test("changed producer revision refuses before installation", async () => {
    assert.ok(
      "identity" in receipt && typeof receipt.identity === "object" && receipt.identity !== null,
    );
    const changed = { ...receipt, identity: { ...receipt.identity, revision: "0".repeat(40) } };
    await writeFile(path.join(artifact, "receipt.json"), JSON.stringify(changed, null, 2) + "\n");
    await refuse(["verify", artifact], /identity, source or payload differs/u);
    await writeFile(path.join(artifact, "receipt.json"), receiptBytes);
  });
  await context.test("changed real image refuses its original provenance", async () => {
    const filename = path.join(artifact, "payload/native/koffi/build/koffi/win32_x64/koffi.node");
    const bytes = await readFile(filename);
    await writeFile(filename, Buffer.concat([bytes, Buffer.from([0])]));
    await refuse(["verify", artifact], /AssertionError/u);
    await writeFile(filename, bytes);
  });
  await context.test("unexpected artifact files refuse the complete inventory", async () => {
    const filename = path.join(artifact, "payload", "unexpected.txt");
    await writeFile(filename, "unexpected");
    await refuse(["verify", artifact], /member inventory differs/u);
    await rm(filename);
  });
  await context.test("an existing differing destination is never overwritten", async () => {
    const filename = path.join(editor, "LICENSE.txt");
    const original = before.get("LICENSE.txt");
    assert.ok(original);
    await writeFile(filename, "different");
    await assert.rejects(
      runCli(process.execPath, [command, "verify", artifact], options),
      (error: unknown): boolean => {
        assert.ok(error instanceof CommandExecutionFailure);
        assert.match(error.output.stderr, /existing native artifact destination differs/u);
        assert.ok(
          Buffer.byteLength(error.output.stderr) < 4096,
          "conflict diagnostics must not dump the payload",
        );
        return true;
      },
    );
    assert.equal(await readFile(filename, "utf8"), "different");
    await writeFile(filename, original.bytes);
    // Destination repair is test-owned; the consumer did not rewrite the conflict.
    before.set("LICENSE.txt", {
      bytes: original.bytes,
      mtime: (await stat(filename, { bigint: true })).mtimeNs,
    });
  });
  const bad = path.join(allocation, "incomplete");
  await cp(artifact, bad, { recursive: true, errorOnExist: true, force: false });
  await rm(path.join(bad, "payload/native/koffi/notices/KOFFI-MIT.txt"));
  await refuse(["verify", bad], /member inventory differs/u);
  assert.ok("sources" in receipt);
  assert.deepEqual(
    receipt.sources,
    inputs,
    "copied sources must retain their complete origin hashes",
  );
  assert.deepEqual(await readFile(path.join(artifact, "receipt.json")), receiptBytes);
  const evidence = path.join(originalEditor, "out/fixtures", path.basename(allocation));
  await mkdir(evidence, { recursive: true });
  await writeFile(path.join(evidence, "original-local-receipt.json"), receiptBytes, {
    flag: "wx",
  });
  await writeFile(
    path.join(evidence, "source-origin.json"),
    JSON.stringify(
      {
        schema: 1,
        copiedRepository: checkout,
        copiedRepositoryUri: pathToFileURL(checkout + path.sep).href,
        originalRepository: source,
        sources: inputs,
        copies: Object.entries(inputs).map(([name, sha256]) => ({
          url: pathToFileURL(path.join(checkout, name)).href,
          source: name,
          sha256,
        })),
      },
      null,
      2,
    ) + "\n",
    { flag: "wx" },
  );
  await writeFile(path.join(evidence, "pack.stdout"), packed.stdout, { flag: "wx" });
  await writeFile(path.join(evidence, "verify.stdout"), admitted.stdout, { flag: "wx" });
  context.diagnostic("native artifact source and original receipt retained at " + evidence);
  context.diagnostic(
    "retained actual Windows payload transported through local receipt; no fresh hosted/native execution claim",
  );
});
