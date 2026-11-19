// SPDX-License-Identifier: Apache-2.0
// Apache License 2.0; see ../../../../LICENSE.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// RigorFoundry — complete VSIX payload and build diagnostic exclusions

/**
 * Package the actual extension after producing genuine V8 diagnostics in a new build directory.
 * Require the VSIX to contain every current runtime module and exclude all other build output.
 * @module
 */

import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { runCli } from "../../src/cli.js";

void test(
  "packages only current runtime JavaScript from the build tree despite real extra diagnostics",
  { timeout: 120_000 },
  async () => {
    const extension = path.resolve(__dirname, "../../..");
    const fixtures = path.join(extension, "out", "fixtures");
    await mkdir(fixtures, { recursive: true });
    const allocation = await mkdtemp(path.join(fixtures, "rigor-package-"));
    const diagnostics = await mkdtemp(path.join(extension, "out", "package-diagnostics-"));
    await runCli(process.execPath, ["-p", "process.version"], {
      cwd: extension,
      timeoutMilliseconds: 10_000,
      environment: { ...process.env, NODE_V8_COVERAGE: diagnostics },
    });
    const profiles = (await readdir(diagnostics)).filter((name) => name.endsWith(".json"));
    assert.ok(profiles.length > 0);
    for (const name of profiles) {
      const profile: unknown = JSON.parse(await readFile(path.join(diagnostics, name), "utf8"));
      assert.ok(typeof profile === "object" && profile !== null && "result" in profile);
      assert.ok(Array.isArray(profile.result) && profile.result.length > 0);
    }
    const vsix = path.join(allocation, "rigor-foundry.vsix");
    const packaged = await runCli(
      process.execPath,
      [
        path.join(extension, "node_modules", "@vscode", "vsce", "vsce"),
        "package",
        "--no-dependencies",
        "--target",
        "win32-x64",
        "--out",
        vsix,
      ],
      { cwd: extension, timeoutMilliseconds: 60_000 },
    );
    await writeFile(path.join(allocation, "package.stdout"), packaged.stdout, "utf8");
    await writeFile(path.join(allocation, "package.stderr"), packaged.stderr, "utf8");
    const python = process.env["RIGOR_FOUNDRY_TEST_PYTHON"] ?? "python";
    const inspected = await runCli(
      python,
      [
        "-c",
        [
          "from pathlib import Path",
          "import hashlib, json, sys, zipfile",
          "root = Path(sys.argv[1])",
          "with zipfile.ZipFile(sys.argv[2]) as archive:",
          "    names = archive.namelist()",
          "    assert len(names) == len(set(names))",
          "    expected = {'extension/out/src/' + p.name for p in (root / 'out/src').glob('*.js')}",
          "    assert expected",
          "    actual = {n for n in names if n.startswith('extension/out/')}",
          "    assert actual == expected, sorted(actual ^ expected)",
          "    assert 'extension/native/editor-hosts.json' not in names",
          "    assert 'extension/native/editor-hosts.json.license' not in names",
          "    for name in expected:",
          "        assert archive.read(name) == (root / name.removeprefix('extension/')).read_bytes()",
          "    native = root / 'native/koffi'",
          "    build = json.loads((native / 'provenance.json').read_text())",
          "    binding = json.loads((native / 'binding-provenance.json').read_text())",
          "    packaged_build = json.loads(archive.read('extension/native/koffi/provenance.json'))",
          "    assert 'buildAllocation' not in packaged_build, 'temporary allocation belongs in build diagnostics'",
          "    for relative in [*build['members'], *binding['members'], 'provenance.json', 'binding-provenance.json', 'binding-provenance.json.license']:",
          "        assert archive.read('extension/native/koffi/' + relative) == (native / relative).read_bytes()",
          "    assert 'TargetPlatform=\"win32-x64\"' in archive.read('extension.vsixmanifest').decode('utf8')",
          "    print(json.dumps({'runtimeMembers': sorted(actual), 'allCurrentRuntimeBytesMatch': True, 'buildDiagnosticsExcluded': True, 'vsixSha256': hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest()}))",
        ].join("\n"),
        extension,
        vsix,
      ],
      { cwd: extension, timeoutMilliseconds: 10_000 },
    );
    const observation: unknown = JSON.parse(inspected.stdout);
    assert.ok(typeof observation === "object" && observation !== null);
    assert.ok(
      "allCurrentRuntimeBytesMatch" in observation &&
        observation.allCurrentRuntimeBytesMatch === true,
    );
    assert.ok(
      "buildDiagnosticsExcluded" in observation && observation.buildDiagnosticsExcluded === true,
    );
    await writeFile(path.join(allocation, "payload-observation.json"), inspected.stdout, "utf8");
  },
);
