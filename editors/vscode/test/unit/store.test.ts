// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — evidence store tests

import assert from "node:assert/strict";
import {mkdtemp, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import path from "node:path";
import test from "node:test";
import {EvidenceStore} from "../../src/store.js";

test("canonical validation status binds the loaded report and ledger snapshot", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "rigor-vscode-store-"));
  context.after(async () => await rm(root, {recursive: true, force: true}));
  const reportPath = path.join(root, "report.json");
  const reviewPath = path.join(root, "reviews.json");
  await writeFile(reportPath, `${JSON.stringify({
    schema_version: "1.3",
    scanner_version: "0.3.0",
    rule_pack_version: "rigor-foundry/1.11.0",
    rule_pack_digest: "a".repeat(64),
    report_digest: "b".repeat(64),
    repository_root: root,
    head: "c".repeat(40),
    branch: "main",
    candidates: [],
  })}\n`, "utf8");
  await writeFile(reviewPath, '{"schema_version":"1.0","reviews":[]}\n', "utf8");

  const store = new EvidenceStore();
  await store.loadReport(root, reportPath, 4096);
  await store.loadReviews(root, reviewPath, 4096);
  assert.equal(store.snapshot().canonicallyValidated, false);
  store.markCanonicallyValidated();
  assert.equal(store.snapshot().canonicallyValidated, true);
  store.clearCanonicalValidation();
  assert.equal(store.snapshot().canonicallyValidated, false);

  await store.loadReport(root, reportPath, 4096);
  assert.equal(store.snapshot().canonicallyValidated, false);
  assert.equal(store.snapshot().reviewPath, undefined);
});
