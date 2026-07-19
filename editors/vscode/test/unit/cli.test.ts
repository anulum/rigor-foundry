// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — shell-free process tests

import assert from "node:assert/strict";
import test from "node:test";
import {runCli} from "../../src/cli.js";

test("passes metacharacters as literal arguments without a shell", async () => {
  const result = await runCli(
    process.execPath,
    ["-e", "process.stdout.write(process.argv[1])", "$(touch should-not-run)"],
    {cwd: process.cwd(), timeoutMilliseconds: 5000},
  );
  assert.equal(result.stdout, "$(touch should-not-run)");
});

test("rejects non-zero commands with bounded diagnostics", async () => {
  await assert.rejects(
    runCli(process.execPath, ["-e", "process.stderr.write('failure'); process.exit(7)"], {
      cwd: process.cwd(),
      timeoutMilliseconds: 5000,
    }),
    /exit code 7: failure/u,
  );
});
