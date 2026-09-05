# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — deployment profile validation command
"""Check explicit private profile data without authorising a deployment."""

from __future__ import annotations

import argparse
from pathlib import Path

from rigor_foundry.deployment_profile import DEPLOYMENT_PROFILE_MAX_BYTES, DeploymentProfile
from rigor_foundry.project_memory_store import _read_private_file


def main(argv: list[str] | None = None) -> int:
    """Validate a bounded private profile and selected lexical parent bindings.

    Parameters
    ----------
    argv:
        Explicit arguments, or None for process arguments. No apply is supported.

    Returns
    -------
    int
        Zero for consistent data and one for refusal. Argparse exits with two
        for invalid arguments. Output omits profile content and derived paths.

    Notes
    -----
    No filesystem target, membership, admission or deployment is certified.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--group", required=True)
    parser.add_argument("--project", required=True)
    args = parser.parse_args(argv)
    try:
        profile = DeploymentProfile.from_bytes(
            _read_private_file(
                args.profile,
                label="deployment profile",
                maximum=DEPLOYMENT_PROFILE_MAX_BYTES,
            )
        )
        profile.parent_paths(
            expected_sha256=args.sha256, group_id=args.group, project_id=args.project
        )
    except (ValueError, RuntimeError, OSError):
        print("deployment-profile: FAIL")
        return 1
    print("deployment-profile: VALIDATED_NOT_AUTHORISED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
