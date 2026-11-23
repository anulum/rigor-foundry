# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — documented macOS Git trust limitation on actual macOS
"""Pin the documented macOS Git trust limitation on an actual macOS host.

On macOS the default trust policy searches ``/usr/bin`` first, where the system
places a multi-link developer-tools Git stub, and the single-link rule refuses it.
This test records that limitation; it does not claim that Git provenance
verification works on macOS.
"""

from __future__ import annotations

import sys
import unittest

from rigor_foundry.git_provenance import GitRunner, _portable_roots


@unittest.skipUnless(sys.platform == "darwin", "requires actual macOS")
class DarwinGitTrustTests(unittest.TestCase):
    """Record the macOS default roots and the refusal of the developer-tools stub."""

    def test_default_policy_refuses_the_developer_tools_git_stub(self) -> None:
        """The default roots start at /usr/bin, and its hard-linked Git is refused."""
        self.assertEqual(_portable_roots(), ("/usr/bin", "/opt/homebrew/bin", "/usr/local/bin"))
        with self.assertRaisesRegex(RuntimeError, r"single-link executable .*: /usr/bin/git$"):
            GitRunner()
