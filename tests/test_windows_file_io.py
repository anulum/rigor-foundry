# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native regular file public contracts
"""Exercise real native file reads, bounded payloads and exclusive UTF-8 creation."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

from rigor_foundry.git_inventory import StableReadError
from rigor_foundry.windows_file_io import read_regular_file, write_new_file, write_new_file_at
from rigor_foundry.windows_handles import WindowsDirectory


class NativeReadArgumentTests(unittest.TestCase):
    """Reject invalid explicit read bounds before attempting native filesystem access."""

    def test_invalid_read_bounds_are_rejected(self) -> None:
        """Reject boolean and negative limits through the actual public callable."""
        path = Path.cwd() / "unused-bound-input"
        for limit in (True, -1):
            with (
                self.subTest(buffer_limit=limit),
                self.assertRaisesRegex(ValueError, "buffer_limit"),
            ):
                read_regular_file(path, buffer_limit=limit)
            with (
                self.subTest(maximum_bytes=limit),
                self.assertRaisesRegex(ValueError, "maximum_bytes"),
            ):
                read_regular_file(path, maximum_bytes=limit)

    def test_unknown_blob_algorithm_is_rejected(self) -> None:
        """Use the actual hashlib boundary rather than a replacement digest implementation."""
        with self.assertRaises(ValueError):
            read_regular_file(
                Path.cwd() / "unused-algorithm-input", object_format="unknown-rigor-hash"
            )

    def test_relative_path_is_refused_by_the_public_regular_file_contract(self) -> None:
        """Preserve the path validation cause without attempting a native relative open."""
        with self.assertRaises(StableReadError) as failure:
            read_regular_file(Path("relative-input.txt"))
        self.assertEqual(failure.exception.reason, "not-regular-file")
        self.assertIsInstance(failure.exception.__cause__, ValueError)


@unittest.skipUnless(sys.platform == "win32", "requires actual Windows NTFS file ownership")
class WindowsFileIOTests(unittest.TestCase):
    """Compare native public results with independently read and hashed actual bytes."""

    def setUp(self) -> None:
        """Allocate a temporary directory owned by this test only."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-native-file-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_exact_bytes_and_git_blob_hashes(self) -> None:
        """Read the same real file with both supported Git object formats and no blob request."""
        path = self.root / "source.txt"
        payload = "prvý riadok\r\ndruhý\n".encode()
        path.write_bytes(payload)
        for algorithm in (None, "sha1", "sha256"):
            with self.subTest(algorithm=algorithm):
                result = read_regular_file(
                    path, object_format=algorithm, maximum_bytes=len(payload)
                )
                self.assertEqual(result.byte_size, len(payload))
                self.assertEqual(result.payload, payload)
                self.assertEqual(result.content_digest, hashlib.sha256(payload).hexdigest())
                expected = None
                if algorithm is not None:
                    expected = hashlib.new(
                        algorithm, f"blob {len(payload)}\0".encode() + payload
                    ).hexdigest()
                self.assertEqual(result.git_blob_id, expected)

    def test_unbuffered_empty_and_multichunk_content(self) -> None:
        """Keep exact streaming digests when the payload exceeds the retained buffer."""
        path = self.root / "stream.bin"
        payload = bytes(range(256)) * 8193
        path.write_bytes(payload)
        result = read_regular_file(path, buffer_limit=0)
        self.assertIsNone(result.payload)
        self.assertEqual(result.byte_size, len(payload))
        self.assertEqual(result.content_digest, hashlib.sha256(payload).hexdigest())
        empty = self.root / "empty.bin"
        empty.write_bytes(b"")
        result = read_regular_file(empty, buffer_limit=0, maximum_bytes=0)
        self.assertEqual(result.payload, b"")
        self.assertEqual(result.byte_size, 0)
        self.assertEqual(result.content_digest, hashlib.sha256(b"").hexdigest())

    def test_borrowed_parent_must_match_requested_file(self) -> None:
        """Read through a retained directory and refuse a handle for a different path."""
        path = self.root / "source.bin"
        path.write_bytes(b"native sample")
        other = self.root / "other"
        other.mkdir()
        other_file = other / path.name
        other_file.write_bytes(b"separate sample")
        with WindowsDirectory(self.root) as parent:
            identity = parent.inspect_child(path.name).identity
            result = read_regular_file(path, retained_parent=parent, expected_identity=identity)
            self.assertEqual(result.payload, b"native sample")
            with self.assertRaises(StableReadError) as failure:
                read_regular_file(other_file, retained_parent=parent, expected_identity=identity)
            self.assertEqual(failure.exception.reason, "changed-while-read")
            self.assertEqual(parent.inspect_child(path.name).identity, identity)
        self.assertEqual(other_file.read_bytes(), b"separate sample")

    def test_static_size_and_link_policies(self) -> None:
        """Exercise declared size and hard-link policies on static owned inputs."""
        path = self.root / "bounded.bin"
        path.write_bytes(b"bounded")
        with self.assertRaises(StableReadError) as failure:
            read_regular_file(path, maximum_bytes=2)
        self.assertEqual(failure.exception.reason, "limit-exceeded")
        os.link(path, self.root / "second-name.bin")
        with self.assertRaises(StableReadError) as failure:
            read_regular_file(path)
        self.assertEqual(failure.exception.reason, "multiple-links")
        self.assertEqual(read_regular_file(path, require_single_link=False).payload, b"bounded")

    def test_missing_file_preserves_actual_native_error(self) -> None:
        """Report an inaccessible regular file while preserving its real OS error cause."""
        with self.assertRaises(StableReadError) as failure:
            read_regular_file(self.root / "missing.txt")
        self.assertEqual(failure.exception.reason, "inaccessible")
        self.assertIsInstance(failure.exception.__cause__, OSError)

    def test_exclusive_unicode_and_empty_creation(self) -> None:
        """Compare actual flushed output bytes and refuse an existing output without overwriting it."""
        path = self.root / "output.txt"
        text = "výstup\r\npresne\n"
        write_new_file(path, text)
        self.assertEqual(path.read_bytes(), text.encode())
        with self.assertRaisesRegex(ValueError, "already exists"):
            write_new_file(path, "replacement")
        self.assertEqual(path.read_bytes(), text.encode())
        with WindowsDirectory(self.root) as directory:
            identity = write_new_file_at(directory, "empty.txt", "", private=False)
            with directory.open_file("empty.txt") as opened:
                current = opened.identity()
                self.assertEqual(identity, (current.volume, current.file_id))
        self.assertEqual((self.root / "empty.txt").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
