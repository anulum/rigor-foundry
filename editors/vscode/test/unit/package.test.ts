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
import { createHash } from "node:crypto";
import {
  copyFile,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { CommandExecutionFailure, runCli } from "../../src/cli.js";

void test(
  "packages the current runtime and selects the binding for the archive platform",
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
    const linux = path.join(allocation, "rigor-foundry-linux.vsix");
    const packageLinux = path.join(extension, "scripts", "package-linux.mjs");
    const packageTemp = path.join(allocation, "package-temp");
    await mkdir(packageTemp);
    const packageOptions = {
      cwd: extension,
      timeoutMilliseconds: 60_000,
      environment: { ...process.env, TMPDIR: packageTemp, TMP: packageTemp, TEMP: packageTemp },
    };
    await runCli(process.execPath, [packageLinux, "--out", linux], packageOptions);
    assert.deepEqual(
      (await readdir(packageTemp)).filter((name) => name.startsWith("rigor-vsix-linux-")),
      [],
    );
    const blockedOutput = path.join(allocation, "blocked-output");
    await writeFile(blockedOutput, "existing file where a directory is required\n", "utf8");
    await assert.rejects(
      runCli(
        process.execPath,
        [packageLinux, "--out", path.join(blockedOutput, "failed.vsix")],
        packageOptions,
      ),
      (error: unknown) => {
        assert.ok(error instanceof CommandExecutionFailure);
        assert.match(error.output.stderr, /E(?:NOENT|NOTDIR)/u);
        assert.match(error.output.stderr, /blocked-output/u);
        return true;
      },
    );
    assert.deepEqual(
      (await readdir(packageTemp)).filter((name) => name.startsWith("rigor-vsix-linux-")),
      [],
    );
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
          "    repository = root.parent.parent",
          "    assert archive.read('extension/LICENSE.txt') == (repository / 'LICENSE').read_bytes()",
          "    assert archive.read('extension/NOTICE') == (repository / 'NOTICE').read_bytes()",
          "    native = root / 'native/koffi'",
          "    build = json.loads((native / 'provenance.json').read_text())",
          "    binding = json.loads((native / 'binding-provenance.json').read_text())",
          "    packaged_build = json.loads(archive.read('extension/native/koffi/provenance.json'))",
          "    assert 'buildAllocation' not in packaged_build, 'temporary allocation belongs in build diagnostics'",
          "    for relative in [*build['members'], *binding['members'], 'provenance.json', 'binding-provenance.json', 'binding-provenance.json.license']:",
          "        assert archive.read('extension/native/koffi/' + relative) == (native / relative).read_bytes()",
          "    assert 'TargetPlatform=\"win32-x64\"' in archive.read('extension.vsixmanifest').decode('utf8')",
          "    with zipfile.ZipFile(sys.argv[3]) as linux:",
          "        linux_names = linux.namelist()",
          "        assert len(linux_names) == len(set(linux_names))",
          "        shared = {n for n in names if not n.startswith('extension/native/koffi/')}",
          "        assert set(linux_names) == shared, sorted(set(linux_names) ^ shared)",
          "        assert 'TargetPlatform=\"linux-x64\"' in linux.read('extension.vsixmanifest').decode('utf8')",
          "        for name in shared - {'extension.vsixmanifest', '[Content_Types].xml'}:",
          "            assert linux.read(name) == archive.read(name), name",
          "    print(json.dumps({'runtimeMembers': sorted(actual), 'allCurrentRuntimeBytesMatch': True, 'buildDiagnosticsExcluded': True, 'vsixSha256': hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest()}))",
        ].join("\n"),
        extension,
        vsix,
        linux,
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

void test("packages the canonical legal files from a clean Linux extension tree", async (context) => {
  const extension = path.resolve(__dirname, "../../..");
  const repository = path.resolve(extension, "../..");
  const allocation = await mkdtemp(path.join(tmpdir(), "rigor-legal-package-"));
  context.after(async () => {
    await rm(allocation, { recursive: true, force: true });
  });
  const evidence = path.join(
    extension,
    "out",
    "fixtures",
    "rigor-editor-metadata-" + path.basename(allocation),
  );
  await mkdir(evidence, { recursive: true });
  const checkout = path.join(allocation, "checkout");
  const editor = path.join(checkout, "editors", "vscode");
  const scripts = ["scripts/stage-package-legal-files.mjs", "scripts/native-artifact-inputs.mjs"];
  const copies = [];
  for (const relative of scripts) {
    const target = path.join(editor, relative);
    const original = await readFile(path.join(extension, relative));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, original);
    copies.push({
      source: "editors/vscode/" + relative,
      url: pathToFileURL(target).href,
      sha256: createHash("sha256").update(original).digest("hex"),
    });
  }
  await writeFile(
    path.join(evidence, "source-origin.json"),
    JSON.stringify({ schema: 1, copies }),
  );
  for (const source of ["LICENSE", "NOTICE"]) {
    await copyFile(path.join(repository, source), path.join(checkout, source));
  }
  for (const relative of [".vscodeignore", "README.md", "package.json", "media", "out/src"]) {
    await cp(path.join(extension, relative), path.join(editor, relative), { recursive: true });
  }
  const args = [
    path.join(extension, "node_modules", "@vscode", "vsce", "vsce"),
    "package",
    "--no-dependencies",
    "--target",
    "linux-x64",
    "--out",
  ];
  const options = { cwd: editor, timeoutMilliseconds: 45_000 };
  const vsix = path.join(allocation, "linux.vsix");
  await runCli(process.execPath, [...args, vsix], options);
  const python = process.env["RIGOR_FOUNDRY_TEST_PYTHON"] ?? "python";
  await runCli(
    python,
    [
      "-c",
      [
        "from pathlib import Path",
        "import sys, zipfile",
        "root = Path(sys.argv[1])",
        "with zipfile.ZipFile(sys.argv[2]) as archive:",
        "    for source, member in [('LICENSE', 'LICENSE.txt'), ('NOTICE', 'NOTICE')]:",
        "        assert archive.namelist().count('extension/' + member) == 1",
        "        assert archive.read('extension/' + member) == (root / source).read_bytes()",
      ].join("\n"),
      repository,
      vsix,
    ],
    options,
  );
  const stale = Buffer.from("stale staged distribution notice\n");
  const notice = path.join(editor, "NOTICE");
  await writeFile(notice, stale);
  const rejected = path.join(allocation, "rejected.vsix");
  await assert.rejects(
    runCli(process.execPath, [...args, rejected], options),
    (error: unknown) => {
      assert.ok(error instanceof CommandExecutionFailure);
      assert.match(error.output.stderr, /existing VSIX NOTICE differs from repository NOTICE/u);
      return true;
    },
  );
  assert.deepEqual(await readFile(notice), stale);
  await assert.rejects(stat(rejected), { code: "ENOENT" });
});

void test("keeps local-only inputs out of the VSIX file selection", async () => {
  const extension = path.resolve(__dirname, "../../..");
  const fixtures = path.join(extension, "out", "fixtures");
  await mkdir(fixtures, { recursive: true });
  const checkout = await mkdtemp(path.join(fixtures, "rigor-private-package-"));
  for (const relative of [".vscodeignore", "package.json", "out/src/extension.js"]) {
    const target = path.join(checkout, relative);
    await mkdir(path.dirname(target), { recursive: true });
    await copyFile(path.join(extension, relative), target);
  }
  const privateFiles = [
    ".env.local",
    "nested/AGENTS.md",
    "nested/.coordination/note.txt",
    "nested/.rigor/evidence.json",
    "nested/.rigor-native-primary/receipt.json",
    "nested/docs/internal/notes.md",
    "nested/agentic_project_memory/memory_index.md",
    "nested/tools/.internal/hygiene/check.txt",
  ];
  for (const relative of privateFiles) {
    const target = path.join(checkout, relative);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, "synthetic private package boundary control\n", "utf8");
  }
  const listed = await runCli(
    process.execPath,
    [path.join(extension, "node_modules", "@vscode", "vsce", "vsce"), "ls", "--no-dependencies"],
    { cwd: checkout, timeoutMilliseconds: 20_000 },
  );
  const paths = new Set(listed.stdout.trim().split(/\r?\n/u));
  assert.ok(paths.has("out/src/extension.js"));
  for (const relative of privateFiles) {
    assert.ok(!paths.has(relative), `private package path: ${relative}`);
  }
});
