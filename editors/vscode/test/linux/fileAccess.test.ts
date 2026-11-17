// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — Linux kernel-file evidence refusal contracts

/**
 * Compare a real producer report with actual Linux procfs and sysfs regular-file reads.
 * Reject bytes beyond a declared size and EOF before that size without replacing filesystem calls.
 * @module
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { parseAuditReport } from "../../src/contracts.js";
import { readBoundedJsonWithDigest } from "../../src/fileAccess.js";
import { createEvidenceRepository } from "../support/repository.js";

/**
 * Exercise stable evidence and two genuine Linux regular-file size discrepancies.
 * @returns Completion after all actual filesystem assertions and owned fixture cleanup.
 */
async function run(): Promise<void> {
  assert.equal(process.platform, "linux", "this explicit native filesystem suite requires Linux");
  const fixture = await createEvidenceRepository();
  try {
    await test("Linux filesystem control accepts the exact real CLI report bytes", async () => {
      const bytes = await readFile(fixture.reportPath);
      const loaded = await readBoundedJsonWithDigest(fixture.root, fixture.reportPath, 16_777_216);
      assert.deepEqual(parseAuditReport(loaded.value), fixture.report);
      assert.equal(loaded.contentSha256, createHash("sha256").update(bytes).digest("hex"));
    });

    await test("refuses actual procfs bytes beyond its declared zero-byte regular-file size", async () => {
      const file = "/proc/version";
      const metadata = await lstat(file);
      const bytes = await readFile(file);
      assert.ok(metadata.isFile());
      assert.equal(metadata.size, 0);
      assert.ok(bytes.length > metadata.size);
      await writeFile(
        path.join(fixture.artifactRoot, "procfs-observation.json"),
        JSON.stringify({
          file,
          declaredBytes: metadata.size,
          actualBytes: bytes.length,
          contentSha256: createHash("sha256").update(bytes).digest("hex"),
        }) + "\n",
        "utf8",
      );
      await assert.rejects(readBoundedJsonWithDigest("/proc", file, 65_536), {
        name: "EvidenceRefusal",
        message: "evidence file changed while it was being read",
      });
    });

    await test("refuses actual sysfs EOF before its declared regular-file size", async () => {
      const file = "/sys/devices/system/cpu/online";
      const metadata = await lstat(file);
      const bytes = await readFile(file);
      assert.ok(metadata.isFile());
      assert.ok(metadata.size > bytes.length);
      assert.ok(bytes.length > 0);
      await writeFile(
        path.join(fixture.artifactRoot, "sysfs-observation.json"),
        JSON.stringify({
          file,
          declaredBytes: metadata.size,
          actualBytes: bytes.length,
          contentSha256: createHash("sha256").update(bytes).digest("hex"),
        }) + "\n",
        "utf8",
      );
      await assert.rejects(readBoundedJsonWithDigest("/sys", file, 65_536), {
        name: "EvidenceRefusal",
        message: "evidence file changed while it was being read",
      });
    });
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
}

run().catch((error: unknown): void => {
  process.stderr.write(`Linux native filesystem test setup failed: ${String(error)}\n`);
  process.exitCode = 1;
});
