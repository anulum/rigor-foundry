// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — Linux VSIX platform file selection

/**
 * Build the Linux VSIX with the shared exclusion rules and without the staged Windows binding.
 * Give each package command its own temporary VSCE ignore file.
 * @module
 */

import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const editor = fileURLToPath(new URL("../", import.meta.url));
const rules = await readFile(path.join(editor, ".vscodeignore"), "utf8");
const temporary = await mkdtemp(path.join(tmpdir(), "rigor-vsix-linux-"));
try {
  const ignoreFile = path.join(temporary, ".vscodeignore");
  await writeFile(ignoreFile, rules + "\nnative/koffi\n", { flag: "wx" });
  execFileSync(
    process.execPath,
    [
      path.join(editor, "node_modules", "@vscode", "vsce", "vsce"),
      "package",
      "--no-dependencies",
      "--out",
      "rigor-foundry-vscode.vsix",
      ...process.argv.slice(2),
      "--target",
      "linux-x64",
      "--ignoreFile",
      ignoreFile,
    ],
    { cwd: editor, stdio: "inherit" },
  );
} finally {
  await rm(temporary, { recursive: true });
}
