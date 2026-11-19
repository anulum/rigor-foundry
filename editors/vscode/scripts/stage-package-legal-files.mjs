// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — canonical VSIX licence and notice staging

/**
 * Stage the repository licence and notice before VSCE collects extension files.
 * Preserve an identical licence already admitted with the Windows native artifact.
 * @module
 */

import assert from "node:assert/strict";
import { constants } from "node:fs";
import { copyFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readMember } from "./native-artifact-inputs.mjs";

const editor = fileURLToPath(new URL("../", import.meta.url));
const repository = path.resolve(editor, "../..");

const legalFiles = { LICENSE: "LICENSE.txt", NOTICE: "NOTICE" };
for (const [source, destination] of Object.entries(legalFiles)) {
  const expected = await readMember(repository, source);
  await copyFile(
    path.join(repository, source),
    path.join(editor, destination),
    constants.COPYFILE_EXCL,
  ).catch(async () => {
    assert.ok(
      (await readMember(editor, destination)).equals(expected),
      `existing VSIX ${destination} differs from repository ${source}`,
    );
  });
}
