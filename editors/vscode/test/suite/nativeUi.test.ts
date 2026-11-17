// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — real native UI observation deadlines

/**
 * Observe actual output and visible workbench state until their original deadlines.
 * Refuse absent observations while preserving the accepted evidence and screenshots.
 * @module
 */

import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import type { RigorFoundryApi } from "../../src/extension.js";
import {
  captureEvidenceView,
  readEvidenceOutput,
  waitForEvidenceOutput,
} from "../support/nativeUi.js";

/**
 * Require real missing-output and missing-category refusals in the running host.
 * @param api - Actual activated extension retaining its accepted report and ledger.
 * @param fixture - Actual adopter whose profile, channel and screenshots already exist.
 * @returns Completion after both original deadlines refuse without replacing evidence.
 */
export async function testNativeUiDeadlines(api: RigorFoundryApi, fixture: string): Promise<void> {
  const snapshot = api.getSnapshot();
  assert.ok(snapshot.report);
  const output = await readEvidenceOutput(fixture);
  const unissuedExplanation = "Unissued review command " + randomUUID();
  assert.ok(!output.includes(unissuedExplanation));
  const outputStarted = performance.now();
  await assert.rejects(waitForEvidenceOutput(fixture, output, unissuedExplanation), {
    message: "actual command explanation was not persisted before its deadline",
  });
  const outputElapsed = performance.now() - outputStarted;
  assert.ok((await readEvidenceOutput(fixture)).startsWith(output));
  assert.deepEqual(api.getSnapshot(), snapshot);

  const absentCategory = "Absent audit category " + randomUUID();
  assert.ok(
    snapshot.report.candidates.every((candidate) => candidate.category !== absentCategory),
  );
  const directory = path.join(fixture, ".rigor", "ui");
  const screenshot = await readFile(path.join(directory, "evidence-tree.png"));
  const geometry = await readFile(path.join(directory, "evidence-tree-geometry.json"));
  const viewStarted = performance.now();
  await assert.rejects(captureEvidenceView(fixture, absentCategory), {
    message: "actual workbench control did not reach its required state",
  });
  const viewElapsed = performance.now() - viewStarted;
  assert.deepEqual(await readFile(path.join(directory, "evidence-tree.png")), screenshot);
  assert.deepEqual(await readFile(path.join(directory, "evidence-tree-geometry.json")), geometry);
  assert.deepEqual(api.getSnapshot(), snapshot);
  await writeFile(
    path.join(fixture, ".rigor", "native-ui-deadlines.json"),
    JSON.stringify({
      unissuedExplanation,
      actualOutputDeadlineMilliseconds: outputElapsed,
      absentCategory,
      actualViewDeadlineMilliseconds: viewElapsed,
      screenshotSha256: createHash("sha256").update(screenshot).digest("hex"),
      geometrySha256: createHash("sha256").update(geometry).digest("hex"),
      acceptedSnapshotPreserved: true,
      previousScreenshotAndGeometryPreserved: true,
    }) + "\n",
    "utf8",
  );
}
