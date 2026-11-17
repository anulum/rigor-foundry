# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Windows public bootstrap contracts
"""Exercise native bootstrap ownership and path contracts against real Git worktrees."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from rigor_foundry.bootstrap import BootstrapResult, bootstrap_repository
from rigor_foundry.git_provenance import GitRunner


@unittest.skipUnless(sys.platform == "win32", "requires native Windows NTFS and Git")
class WindowsBootstrapTests(unittest.TestCase):
    """Keep actual fixture bytes while exercising the public bootstrap operation."""

    def setUp(self) -> None:
        """Allocate an independent real NTFS adopter repository for each contract."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-bootstrap-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for name in ("src", "tests", ".rigor"):
            (self.root / name).mkdir()
        (self.root / ".gitignore").write_text(".rigor/\n", encoding="utf-8")
        self.git = GitRunner()
        self.git.run(self.root, "init", "--initial-branch=main")

    def bootstrap(
        self,
        *,
        root: Path | None = None,
        policy: Path = Path("rigor-foundry-policy.json"),
        todo: Path = Path(".rigor/TODO.md"),
        ledger: Path = Path(".rigor/reviews.json"),
        sources: tuple[Path, ...] = (Path("src"),),
        tests: tuple[Path, ...] = (Path("tests"),),
    ) -> BootstrapResult:
        """Invoke the supported public operation with actual repository inputs."""
        return bootstrap_repository(
            self.root if root is None else root,
            policy_path=policy,
            todo_path=todo,
            review_ledger_path=ledger,
            source_roots=sources,
            test_roots=tests,
        )

    def test_success_creates_policy_and_todo_without_a_review_ledger(self) -> None:
        """Materialize actual UTF-8 files and return their canonical policy identity."""
        result = self.bootstrap()
        policy = json.loads(result.policy_path.read_text(encoding="utf-8"))
        self.assertEqual(result.policy_path, self.root / "rigor-foundry-policy.json")
        self.assertEqual(result.todo_path, self.root / ".rigor/TODO.md")
        self.assertEqual(len(result.policy_digest), 64)
        self.assertEqual(policy["source_roots"], ["src"])
        self.assertEqual(policy["test_roots"], ["tests"])
        self.assertIn("TODO", result.todo_path.read_text(encoding="utf-8"))
        self.assertFalse((self.root / ".rigor/reviews.json").exists())

    def test_relative_drive_and_rooted_spellings_are_refused(self) -> None:
        """Reject Windows drive-relative and rooted paths before allocating outputs."""
        for policy in (Path("D:policy.json"), Path("\\policy.json")):
            with self.subTest(policy=policy), self.assertRaisesRegex(ValueError, "drive|rooted"):
                self.bootstrap(policy=policy)

    def test_distinct_output_paths_are_required(self) -> None:
        """Reject two roles assigned the same actual output pathname."""
        with self.assertRaisesRegex(ValueError, "distinct"):
            self.bootstrap(ledger=Path(".rigor/TODO.md"))

    def test_source_and_test_roots_must_be_nonempty(self) -> None:
        """Require explicit existing source and test roots independently."""
        with self.assertRaisesRegex(ValueError, "at least one source root"):
            self.bootstrap(sources=())
        with self.assertRaisesRegex(ValueError, "at least one test root"):
            self.bootstrap(tests=())

    def test_duplicate_roots_are_refused(self) -> None:
        """Reject repeated source and test roots through the public configuration."""
        with self.assertRaisesRegex(ValueError, "unique"):
            self.bootstrap(sources=(Path("src"), Path("src")))
        with self.assertRaisesRegex(ValueError, "unique"):
            self.bootstrap(tests=(Path("tests"), Path("tests")))

    def test_non_directory_and_nested_git_roots_are_refused(self) -> None:
        """Require an actual directory at the exact worktree root."""
        with self.assertRaisesRegex(ValueError, "real directory"):
            self.bootstrap(root=self.root / ".gitignore")
        with self.assertRaisesRegex(ValueError, "exact Git worktree root"):
            self.bootstrap(
                root=self.root / "src", todo=Path("TODO.md"), ledger=Path("reviews.json")
            )

    def test_existing_outputs_are_never_adopted(self) -> None:
        """Preserve existing policy, TODO and ledger bytes in three separate invocations."""
        for relative in ("rigor-foundry-policy.json", ".rigor/TODO.md", ".rigor/reviews.json"):
            target = self.root / relative
            target.write_bytes(b"preexisting owner bytes\r\n")
            with (
                self.subTest(relative=relative),
                self.assertRaisesRegex(ValueError, "never overwrites"),
            ):
                self.bootstrap()
            self.assertEqual(target.read_bytes(), b"preexisting owner bytes\r\n")
            target.unlink()

    def test_tracked_policy_is_preserved(self) -> None:
        """Refuse an already tracked policy before any output creation."""
        target = self.root / "rigor-foundry-policy.json"
        target.write_bytes(b"tracked policy")
        self.git.run(self.root, "add", target.name)
        with self.assertRaisesRegex(ValueError, "already tracked"):
            self.bootstrap()
        self.assertEqual(target.read_bytes(), b"tracked policy")

    def test_policy_must_remain_trackable(self) -> None:
        """Refuse a policy assigned to a path ignored by actual Git rules."""
        with self.assertRaisesRegex(ValueError, "policy path must be trackable"):
            self.bootstrap(policy=Path(".rigor/policy.json"))

    def test_tracked_private_records_are_preserved(self) -> None:
        """Refuse tracked TODO and ledger records without changing their bytes."""
        for relative in (".rigor/TODO.md", ".rigor/reviews.json"):
            target = self.root / relative
            target.write_bytes(b"tracked private record")
            self.git.run(self.root, "add", "--force", relative)
            with (
                self.subTest(relative=relative),
                self.assertRaisesRegex(ValueError, "must not be tracked"),
            ):
                self.bootstrap()
            self.assertEqual(target.read_bytes(), b"tracked private record")
            self.git.run(self.root, "rm", "--cached", "--force", relative)
            target.unlink()

    def test_private_records_must_be_ignored(self) -> None:
        """Refuse each unignored private role using actual Git ignore evaluation."""
        with self.assertRaisesRegex(ValueError, "TODO path must be covered"):
            self.bootstrap(todo=Path("TODO.md"))
        with self.assertRaisesRegex(ValueError, "review-ledger path must be covered"):
            self.bootstrap(ledger=Path("reviews.json"))


if __name__ == "__main__":
    unittest.main()
