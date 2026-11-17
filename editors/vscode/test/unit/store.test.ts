// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — evidence store tests

/**
 * Exercise evidence-state transitions with actual CLI-produced report and ledger bytes.
 * Check pair validation, reload invalidation, refused inputs, and preservation of the last accepted state.
 * @module
 */

import assert from "node:assert/strict";
import { copyFile, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { EvidenceStore } from "../../src/store.js";
import { createEvidenceRepository } from "../support/repository.js";

/**
 * Exercise state transitions against real CLI-produced report and ledger bytes.
 * @returns Completion after accepted, changed, and refused evidence has been checked.
 */
async function run(): Promise<void> {
  const repository = await createEvidenceRepository();
  const { root, reportPath, reviewPath } = repository;
  const maximumBytes = 4_194_304;
  const cli = process.env["RIGOR_FOUNDRY_CLI"] ?? "rigor";
  try {
    await test("rejects a snapshot issued by a different evidence store", async () => {
      const store = new EvidenceStore();
      await assert.rejects(
        store.validateReviews(new EvidenceStore().snapshot(), cli, maximumBytes, 60_000),
        /selection changed/u,
      );
      assert.equal(store.snapshot().canonicallyValidated, false);
    });

    await test("rejects a reloaded identical ledger selection before invoking validation", async () => {
      const store = new EvidenceStore();
      await store.loadReport(root, reportPath, maximumBytes);
      await store.loadReviews(root, reviewPath, maximumBytes);
      const before = store.snapshot();
      await store.loadReviews(root, reviewPath, maximumBytes);
      await assert.rejects(
        store.validateReviews(before, cli, maximumBytes, 60_000),
        /selection changed/u,
      );
      assert.deepEqual(store.snapshot(), before);
    });

    await test("concurrent real ledger reads cannot attach an old completion to a new selection", async () => {
      const store = new EvidenceStore();
      await store.loadReport(root, reportPath, maximumBytes);
      const results = await Promise.allSettled([
        store.loadReviews(root, reviewPath, maximumBytes),
        store.loadReviews(root, reviewPath, maximumBytes),
      ]);
      assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
      const refused = results.find((result) => result.status === "rejected");
      assert.ok(refused?.status === "rejected");
      assert.match(String(refused.reason), /selection changed while loading/u);
      await store.validateReviews(store.snapshot(), cli, maximumBytes, 60_000);
      assert.equal(store.snapshot().canonicallyValidated, true);
    });

    for (const file of [reportPath, reviewPath]) {
      await test(`refuses changed loaded bytes before validating ${path.basename(file)}`, async () => {
        const original = await readFile(file);
        const store = new EvidenceStore();
        await store.loadReport(root, reportPath, maximumBytes);
        await store.loadReviews(root, reviewPath, maximumBytes);
        const before = store.snapshot();
        try {
          await writeFile(file, Buffer.concat([original, Buffer.from("\n")]));
          await assert.rejects(
            store.validateReviews(before, cli, maximumBytes, 60_000),
            /evidence files changed/u,
          );
          assert.deepEqual(store.snapshot(), before);
        } finally {
          await writeFile(file, original);
        }
      });
    }

    await test("a genuine CLI start failure leaves the loaded evidence unvalidated", async () => {
      const store = new EvidenceStore();
      await store.loadReport(root, reportPath, maximumBytes);
      await store.loadReviews(root, reviewPath, maximumBytes);
      const before = store.snapshot();
      await assert.rejects(
        store.validateReviews(before, path.join(root, "absent-cli"), maximumBytes, 60_000),
        /could not be started/u,
      );
      assert.deepEqual(store.snapshot(), before);
    });

    await test("empty state has no evidence or canonical validation", async () => {
      const store = new EvidenceStore();
      assert.deepEqual(store.snapshot(), {
        report: undefined,
        workspaceRoot: undefined,
        reviews: new Map(),
        reportPath: undefined,
        reviewPath: undefined,
        canonicallyValidated: false,
      });
      await assert.rejects(
        store.validateReviews(store.snapshot(), cli, maximumBytes, 60_000),
        /report and review ledger/u,
      );
    });

    await test("refuses a ledger until a report is loaded", async () => {
      const store = new EvidenceStore();
      await assert.rejects(
        store.loadReviews(root, reviewPath, maximumBytes),
        /load an audit report/u,
      );
      assert.equal(store.snapshot().report, undefined);
    });

    await test("canonical validation status binds the loaded report and ledger snapshot", async () => {
      const store = new EvidenceStore();
      await store.loadReport(root, reportPath, maximumBytes);
      await assert.rejects(
        store.validateReviews(store.snapshot(), cli, maximumBytes, 60_000),
        /report and review ledger/u,
      );
      await store.loadReviews(root, reviewPath, maximumBytes);
      assert.equal(store.snapshot().canonicallyValidated, false);
      await store.validateReviews(store.snapshot(), cli, maximumBytes, 60_000);
      assert.equal(store.snapshot().canonicallyValidated, true);
      store.clearCanonicalValidation();
      assert.equal(store.snapshot().canonicallyValidated, false);

      await store.loadReport(root, reportPath, maximumBytes);
      assert.equal(store.snapshot().canonicallyValidated, false);
      assert.equal(store.snapshot().reviewPath, undefined);
    });

    await test("retains actual candidate-to-review records and both source paths", async () => {
      const store = new EvidenceStore();
      const report = await store.loadReport(root, reportPath, maximumBytes);
      const ledger = await store.loadReviews(root, reviewPath, maximumBytes);
      const snapshot = store.snapshot();
      assert.equal(snapshot.report, report);
      assert.equal(snapshot.reportPath, reportPath);
      assert.equal(snapshot.reviewPath, reviewPath);
      assert.equal(snapshot.reviews.size, ledger.reviews.length);
      for (const review of ledger.reviews) {
        assert.equal(snapshot.reviews.get(review.candidate_id), review);
      }
    });

    await test("loading new ledger bytes clears the earlier exact-byte validation binding", async () => {
      const store = new EvidenceStore();
      await store.loadReport(root, reportPath, maximumBytes);
      await store.loadReviews(root, reviewPath, maximumBytes);
      await store.validateReviews(store.snapshot(), cli, maximumBytes, 60_000);
      assert.equal(store.snapshot().canonicallyValidated, true);
      const changed = path.join(root, ".rigor", "reformatted-reviews.json");
      await writeFile(changed, `${await readFile(reviewPath, "utf8")}\n`, "utf8");
      await store.loadReviews(root, changed, maximumBytes);
      assert.equal(store.snapshot().canonicallyValidated, false);
      assert.equal(store.snapshot().reviewPath, changed);
    });

    await test("refuses a report naming a different existing repository without replacing state", async () => {
      const store = new EvidenceStore();
      await store.loadReport(root, reportPath, maximumBytes);
      await store.loadReviews(root, reviewPath, maximumBytes);
      await store.validateReviews(store.snapshot(), cli, maximumBytes, 60_000);
      const before = store.snapshot();
      const other = path.join(root, "other-repository");
      await mkdir(other);
      const value: unknown = JSON.parse(await readFile(reportPath, "utf8"));
      assert.ok(typeof value === "object" && value !== null && !Array.isArray(value));
      const changed = path.join(root, ".rigor", "wrong-root-report.json");
      await writeFile(changed, JSON.stringify({ ...value, repository_root: other }), "utf8");
      await assert.rejects(store.loadReport(root, changed, maximumBytes), /does not match/u);
      assert.deepEqual(store.snapshot(), before);
    });

    await test("a refused ledger leaves the loaded pair and its validation binding intact", async () => {
      const store = new EvidenceStore();
      await store.loadReport(root, reportPath, maximumBytes);
      await store.loadReviews(root, reviewPath, maximumBytes);
      await store.validateReviews(store.snapshot(), cli, maximumBytes, 60_000);
      const before = store.snapshot();
      await assert.rejects(
        store.loadReviews(root, reportPath, maximumBytes),
        /reviews.schema_version/u,
      );
      assert.deepEqual(store.snapshot(), before);
    });

    await test("binds the canonical report owner and refuses a copied real ledger from another root", async () => {
      const other = await createEvidenceRepository();
      try {
        const store = new EvidenceStore();
        await store.loadReport(root + path.sep + ".", reportPath, maximumBytes);
        await store.loadReviews(root, reviewPath, maximumBytes);
        await store.validateReviews(store.snapshot(), cli, maximumBytes, 60_000);
        assert.equal(store.snapshot().workspaceRoot, await realpath(root));
        const before = store.snapshot();
        const copied = path.join(other.root, ".rigor", "copied-original-ledger.json");
        await copyFile(reviewPath, copied);
        await assert.rejects(
          store.loadReviews(other.root, copied, maximumBytes),
          /review ledger workspace does not match the loaded report/u,
        );
        assert.deepEqual(store.snapshot(), before);
        await store.loadReport(other.root, other.reportPath, maximumBytes);
        assert.equal(store.snapshot().workspaceRoot, await realpath(other.root));
        assert.equal(store.snapshot().reviewPath, undefined);
        assert.equal(store.snapshot().canonicallyValidated, false);
        await store.loadReviews(other.root, other.reviewPath, maximumBytes);
      } finally {
        await rm(other.root, { recursive: true, force: true });
      }
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

run().catch((error: unknown): void => {
  process.stderr.write(`Evidence store test setup failed: ${String(error)}\n`);
  process.exitCode = 1;
});
