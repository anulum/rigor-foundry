# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — versioned protocol field-contract tests
"""Keep exact parser field contracts aligned with public serialization."""

from __future__ import annotations

from test_project_profile import intent, profile
from test_standard_pack import control
from test_work_models import task

from rigor_foundry.protocol_fields import (
    CONTROL_DEFINITION_FIELDS,
    EVIDENCE_CONTRACT_FIELDS,
    PROJECT_INTENT_FIELDS,
    PROJECT_PROFILE_FIELDS,
    WORK_TASK_FIELDS,
)


def test_field_contracts_match_public_serialized_records() -> None:
    """Each exact parser contract names every field emitted by its public model."""
    expected_control = control()
    records = (
        (PROJECT_INTENT_FIELDS, intent().to_dict()),
        (PROJECT_PROFILE_FIELDS, profile().to_dict()),
        (EVIDENCE_CONTRACT_FIELDS, expected_control.evidence.to_dict()),
        (CONTROL_DEFINITION_FIELDS, expected_control.to_dict()),
        (WORK_TASK_FIELDS, task().to_dict()),
    )
    for expected_fields, record in records:
        assert frozenset(record) == expected_fields
