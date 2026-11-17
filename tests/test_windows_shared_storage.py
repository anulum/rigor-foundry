# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real shared storage platform and output contracts
"""Exercise actual filesystem identities and the native storage capability boundary."""

from __future__ import annotations

import errno
import os
import sys
import tempfile
import unittest
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from typing import TextIO, cast
from unittest.mock import patch

from rigor_foundry import internal_storage
from rigor_foundry.safe_output import write_new_output


class RegularFileIdentityTests(unittest.TestCase):
    """Compare public identity results with actual stat data and static owned file kinds."""

    def setUp(self) -> None:
        """Allocate a real temporary input owned by this test."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-storage-identity-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / "record.txt"
        self.path.write_bytes(b"record")

    def test_regular_identity_matches_actual_stat(self) -> None:
        """Return the actual device and inode without modifying the file."""
        before = self.path.stat()
        self.assertEqual(
            internal_storage.regular_file_identity(self.path, label="record"),
            (before.st_dev, before.st_ino),
        )
        self.assertEqual(self.path.read_bytes(), b"record")

    def test_missing_and_directory_inputs_are_refused(self) -> None:
        """Preserve the real missing-file cause and reject the actual directory kind."""
        with self.assertRaisesRegex(ValueError, "existing regular") as failure:
            internal_storage.regular_file_identity(self.root / "missing", label="record")
        self.assertIsInstance(failure.exception.__cause__, FileNotFoundError)
        with self.assertRaisesRegex(ValueError, "existing regular"):
            internal_storage.regular_file_identity(self.root, label="record")

    def test_static_multiple_links_are_refused(self) -> None:
        """Enforce the declared single-link policy on static real links, without concurrent mutations."""
        os.link(self.path, self.root / "second.txt")
        with self.assertRaisesRegex(ValueError, "exactly one link"):
            internal_storage.regular_file_identity(self.path, label="record")
        self.assertEqual(self.path.read_bytes(), b"record")


@unittest.skipUnless(
    sys.platform == "win32", "requires actual Windows unsupported POSIX storage boundary"
)
class WindowsStorageBoundaryTests(unittest.TestCase):
    """Reject unsupported journal mutations while retaining the supported native output surface."""

    def setUp(self) -> None:
        """Allocate only an owned native temporary directory and one existing record."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-storage-platform-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / "existing.txt"
        self.path.write_bytes(b"preserved")
        self.before = self.path.stat()

    def test_unsupported_record_mutators_refuse_before_creating_or_changing_files(self) -> None:
        """Call every public unsupported mutation factory against actual Windows."""
        fresh = self.root / "fresh.txt"
        with self.assertRaisesRegex(RuntimeError, "require POSIX"):
            internal_storage.fsync_directory(self.root)
        with self.assertRaisesRegex(RuntimeError, "require POSIX"):
            internal_storage.write_new_text(fresh, "new")
        with self.assertRaisesRegex(RuntimeError, "require POSIX"):
            internal_storage.atomic_replace_text(self.path, "replacement")
        with ExitStack() as contexts, self.assertRaisesRegex(RuntimeError, "require POSIX"):
            contexts.enter_context(
                internal_storage.open_verified_text_for_append(
                    self.path, (self.before.st_dev, self.before.st_ino), label="record"
                )
            )
        with ExitStack() as contexts, self.assertRaisesRegex(RuntimeError, "require POSIX"):
            contexts.enter_context(internal_storage.exclusive_lock(self.root / "lock"))
        self.assertEqual(self.path.read_bytes(), b"preserved")
        self.assertEqual(self.path.stat().st_mtime_ns, self.before.st_mtime_ns)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["existing.txt"])

    def test_public_explicit_output_uses_real_native_writer(self) -> None:
        """Write exact Unicode bytes through the supported shared public output API."""
        target = self.root / "output.txt"
        text = "výstup\r\npresné bajty\n"
        write_new_output(target, text)
        self.assertEqual(target.read_bytes(), text.encode())
        with self.assertRaisesRegex(ValueError, "already exists"):
            write_new_output(target, "replacement")
        self.assertEqual(target.read_bytes(), text.encode())
        self.assertEqual(self.path.read_bytes(), b"preserved")


@unittest.skipIf(os.name == "nt", "requires actual POSIX record descriptors")
class PosixStorageFailureTests(unittest.TestCase):
    """Preserve genuine descriptor and write errors at the public storage boundary."""

    def setUp(self) -> None:
        """Allocate one existing record and no shared or external resources."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-storage-descriptor-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / "existing.txt"
        self.path.write_bytes(b"preserved")

    def assert_descriptor_closed(self, descriptor: int) -> None:
        """Check the original descriptor with a real kernel fstat call after settlement."""
        with self.assertRaises(OSError) as failure:
            os.fstat(descriptor)
        self.assertEqual(failure.exception.errno, 9)

    def exercise_real_fdopen_failure(
        self, writer: Callable[[Path, str], None], path: Path
    ) -> None:
        """Ask real fdopen for an invalid mode and retain its original exception and descriptor."""
        original = os.fdopen
        descriptors: list[int] = []

        def invalid_mode(descriptor: int, mode: str, *, encoding: str, newline: str) -> TextIO:
            """Change one actual API argument without fabricating a return value or exception."""
            self.assertEqual(mode, "w")
            descriptors.append(descriptor)
            return cast(
                TextIO, original(descriptor, "invalid", encoding=encoding, newline=newline)
            )

        with (
            patch.object(os, "fdopen", invalid_mode),
            self.assertRaisesRegex(ValueError, "invalid mode"),
        ):
            writer(path, "replacement")
        self.assertEqual(len(descriptors), 1)
        self.assert_descriptor_closed(descriptors[0])
        self.assertEqual(self.path.read_bytes(), b"preserved")

    def test_immutable_record_fdopen_failure_closes_created_descriptor(self) -> None:
        """Keep the actual empty failed record and release its untransferred descriptor."""
        target = self.root / "fresh.txt"
        self.exercise_real_fdopen_failure(internal_storage.write_new_text, target)
        self.assertEqual(target.read_bytes(), b"")
        self.assertEqual(
            sorted(p.name for p in self.root.iterdir()), ["existing.txt", "fresh.txt"]
        )

    def test_atomic_record_fdopen_failure_preserves_original_and_removes_temporary(self) -> None:
        """Close the real mkstemp descriptor and discard only that failed replacement allocation."""
        self.exercise_real_fdopen_failure(internal_storage.atomic_replace_text, self.path)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["existing.txt"])

    def test_explicit_output_refuses_actual_missing_filename_and_invalid_parents(self) -> None:
        """Exercise ordinary caller path errors without altering any file metadata or identity."""
        for target, message in [
            (Path("."), "no filename"),
            (self.root / "missing" / "out.txt", "parent does not exist"),
            (self.path / "out.txt", "not a no-follow directory"),
        ]:
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, message):
                write_new_output(target, "output")
        self.assertEqual(self.path.read_bytes(), b"preserved")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["existing.txt"])

    def exercise_real_write_failure(self, payload: bytes, message: str) -> None:
        """Preserve the failed output and release its real descriptor after write refusal."""
        original = os.write
        descriptors: list[int] = []

        def write_actual_buffer(descriptor: int, supplied: bytes) -> int:
            """Issue a real zero-length write; no write result or file identity is manufactured."""
            self.assertEqual(supplied, b"output")
            descriptors.append(descriptor)
            return original(descriptor, payload)

        target = self.root / "failed-output.txt"
        with (
            patch.object(os, "write", write_actual_buffer),
            self.assertRaisesRegex(ValueError, message) as failure,
        ):
            write_new_output(target, "output")
        self.assertIsInstance(failure.exception.__cause__, OSError)
        self.assertEqual(len(descriptors), 1)
        self.assert_descriptor_closed(descriptors[0])
        self.assertEqual(target.read_bytes(), payload)
        self.assertEqual(self.path.read_bytes(), b"preserved")

    def test_actual_zero_byte_write_preserves_failed_explicit_output(self) -> None:
        """Refuse real no-progress writes, close the descriptor and preserve the output."""
        self.exercise_real_write_failure(b"", "cannot create output safely")

    def test_verified_append_refuses_static_wrong_kind_links_and_identity(self) -> None:
        """Reject real unsafe append targets and retain the original bytes and usable locks."""
        before = self.path.stat()
        identity = before.st_dev, before.st_ino
        missing = self.root / "missing.txt"
        with (
            ExitStack() as contexts,
            self.assertRaisesRegex(ValueError, "existing regular") as failure,
        ):
            contexts.enter_context(
                internal_storage.open_verified_text_for_append(missing, identity, label="record")
            )
        self.assertIsInstance(failure.exception.__cause__, FileNotFoundError)

        with ExitStack() as contexts, self.assertRaises(IsADirectoryError):
            contexts.enter_context(
                internal_storage.open_verified_text_for_append(self.root, identity, label="record")
            )

        alias = self.root / "alias.txt"
        alias.symlink_to(self.path)
        with (
            ExitStack() as contexts,
            self.assertRaisesRegex(ValueError, "existing regular") as failure,
        ):
            contexts.enter_context(
                internal_storage.open_verified_text_for_append(alias, identity, label="record")
            )
        self.assertEqual(cast(OSError, failure.exception.__cause__).errno, errno.ELOOP)

        with (
            ExitStack() as contexts,
            self.assertRaisesRegex(ValueError, "changed after path validation"),
        ):
            contexts.enter_context(
                internal_storage.open_verified_text_for_append(
                    self.path, (before.st_dev, before.st_ino + 1), label="record"
                )
            )

        fifo = self.root / "record.fifo"
        os.mkfifo(fifo)
        with ExitStack() as contexts, self.assertRaisesRegex(ValueError, "exactly one link"):
            contexts.enter_context(
                internal_storage.open_verified_text_for_append(fifo, identity, label="record")
            )

        second = self.root / "second.txt"
        os.link(self.path, second)
        try:
            with ExitStack() as contexts, self.assertRaisesRegex(ValueError, "exactly one link"):
                contexts.enter_context(
                    internal_storage.open_verified_text_for_append(
                        self.path, identity, label="record"
                    )
                )
        finally:
            second.unlink()
        self.assertEqual(self.path.read_bytes(), b"preserved")
        self.assertEqual(self.path.stat().st_mtime_ns, before.st_mtime_ns)
        with internal_storage.open_verified_text_for_append(
            self.path, identity, label="record"
        ) as handle:
            self.assertEqual(handle.read(), "preserved")
        self.assertEqual(self.path.read_bytes(), b"preserved")

    def test_exclusive_lock_refuses_static_unsafe_paths_and_releases_parent(self) -> None:
        """Retain real OS refusal causes, then acquire a fresh lock below the same parent."""
        before = self.path.stat()
        directory = self.root / "directory"
        directory.mkdir()
        for target, error in [
            (self.root / "missing" / "lock", FileNotFoundError),
            (self.path / "lock", NotADirectoryError),
            (directory, IsADirectoryError),
        ]:
            with (
                ExitStack() as contexts,
                self.subTest(target=target),
                self.assertRaises(error),
            ):
                contexts.enter_context(internal_storage.exclusive_lock(target))

        alias = self.root / "alias.txt"
        alias.symlink_to(self.path)
        with (
            ExitStack() as contexts,
            self.assertRaisesRegex(ValueError, "must not be a symbolic link") as failure,
        ):
            contexts.enter_context(internal_storage.exclusive_lock(alias))
        self.assertEqual(cast(OSError, failure.exception.__cause__).errno, errno.ELOOP)

        second = self.root / "second.txt"
        os.link(self.path, second)
        try:
            with ExitStack() as contexts, self.assertRaisesRegex(ValueError, "exactly one link"):
                contexts.enter_context(internal_storage.exclusive_lock(self.path))
        finally:
            second.unlink()
        with internal_storage.exclusive_lock(self.root / "recovered.lock"):
            self.assertEqual(self.path.read_bytes(), b"preserved")
        self.assertEqual(self.path.stat().st_mtime_ns, before.st_mtime_ns)


if __name__ == "__main__":
    unittest.main()
