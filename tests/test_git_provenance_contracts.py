# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — portable Git provenance contract tests
"""Verify strict host-independent policy and provenance parsing."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.git_provenance import GitExecutableProvenance, GitTrustPolicy


def test_policy_and_provenance_parsers_reject_malformed_contracts(tmp_path: Path) -> None:
    """Malformed versions, paths, digests, shapes, and schema revisions are rejected."""
    root = str(tmp_path / "trusted")
    invalid_policies: tuple[tuple[dict[str, object], str], ...] = (
        ({"executable": ""}, "non-empty"),
        ({"executable": "bin/git"}, "basename"),
        ({"executable": str(Path(root) / ".." / "git")}, "normalised"),
        ({"minimum_version": "2.35"}, "three-part"),
        (
            {
                "minimum_version": "2.35.2",
                "maximum_version_exclusive": "2.35.2",
            },
            "non-empty",
        ),
    )
    for changes, message in invalid_policies:
        with pytest.raises(ValueError, match=message):
            GitTrustPolicy(trusted_roots=(root,), **changes)

    encoded_policy = GitTrustPolicy(trusted_roots=(root,)).to_dict()
    with pytest.raises(ValueError, match="schema"):
        GitTrustPolicy.from_dict({**encoded_policy, "schema_version": "2.0"})
    with pytest.raises(ValueError, match="string array"):
        GitTrustPolicy.from_dict({**encoded_policy, "trusted_roots": {}})
    with pytest.raises(ValueError, match="must not be empty"):
        GitTrustPolicy.from_dict({**encoded_policy, "trusted_roots": []})
    with pytest.raises(ValueError, match="normalised canonical"):
        GitTrustPolicy(trusted_roots=("/usr//bin",))

    base = {
        "resolved_path": "/usr/bin/git",
        "trusted_root": "/usr/bin",
        "version": "2.43.0",
        "executable_digest": "1" * 64,
        "trust_policy": GitTrustPolicy(trusted_roots=("/usr/bin",)),
    }
    cases: tuple[tuple[dict[str, object], str], ...] = (
        ({"resolved_path": "relative/git"}, "absolute"),
        ({"resolved_path": "C:/Git/git.exe"}, "same path format"),
        ({"trusted_root": "/opt/git"}, "outside"),
        ({"resolved_path": "/usr//bin/git"}, "normalised"),
        (
            {"trust_policy": GitTrustPolicy(trusted_roots=("/opt/git",))},
            "not declared",
        ),
        (
            {
                "trust_policy": GitTrustPolicy(
                    executable="/usr/bin/other",
                    trusted_roots=("/usr/bin",),
                )
            },
            "differs",
        ),
        (
            {
                "trust_policy": GitTrustPolicy(
                    executable="other",
                    trusted_roots=("/usr/bin",),
                )
            },
            "differs",
        ),
        (
            {
                "trust_policy": GitTrustPolicy(
                    trusted_roots=("/usr/bin",),
                    minimum_version="2.44.0",
                )
            },
            "outside its trust policy interval",
        ),
        ({"version": "two"}, "three-part"),
        ({"executable_digest": "invalid"}, "SHA-256"),
    )
    for changes, message in cases:
        with pytest.raises(ValueError, match=message):
            GitExecutableProvenance.build(**{**base, **changes})
    valid = GitExecutableProvenance.build(**base).to_dict()
    with pytest.raises(ValueError, match="schema"):
        GitExecutableProvenance.from_dict({**valid, "schema_version": "2.0"})
    changed_policy = dict(valid)
    policy_value = dict(cast(dict[str, object], changed_policy["trust_policy"]))
    policy_value["minimum_version"] = "2.40.0"
    changed_policy["trust_policy"] = policy_value
    with pytest.raises(ValueError, match="trust-policy digest"):
        GitExecutableProvenance.from_dict(changed_policy)
