# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact qualitative evidence subject tests
"""Bind real interpreter output and complete custody identities before proof metadata."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from test_freshness_proof import declared_proof, freshness_policy, freshness_proof
from test_policy_model_inputs import budget
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_owner_proof import OwnerProof1
from rigor_foundry.control_assessment import Classification, EvidenceReference
from rigor_foundry.effective_profile import AdapterLock
from rigor_foundry.evidence_contract_v2 import EvidenceRequirement1
from rigor_foundry.evidence_reference_v2 import (
    EvidenceReference2,
    EvidenceResult,
    evidence_subject_digest,
)
from rigor_foundry.freshness_proof import FreshnessProof1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.source_component_reader import PolicyComponent1
from rigor_foundry.typed_object_reference import TypedObjectRef1

_ENVIRONMENT = {"LANG": "C.UTF-8", "TMPDIR": tempfile.gettempdir()}
_CONFIGURATION = b'{"arguments":["--version"],"output":"stdout"}\n'


def runtime_adapter() -> PolicyComponent1:
    """Retain the actual executable, exact command/environment and complete fixture configuration."""
    executable = Path(sys.executable).resolve(strict=True)
    return PolicyComponent1(
        AdapterLock.build(
            adapter_id="observed-python-runtime",
            version=".".join(str(value) for value in sys.version_info[:3]),
            executable_digest=sha256(executable.read_bytes()).hexdigest(),
            config_digest=sha256(_CONFIGURATION).hexdigest(),
            command_digest=canonical_digest([str(executable), "--version"]),
            environment_digest=canonical_digest(_ENVIRONMENT),
            domains=("operations-and-observability",),
        ),
        budget(),
    )


@lru_cache(maxsize=1)
def observed_artifact() -> tuple[bytes, str]:
    """Observe a real bounded serial interpreter invocation under the adapter's exact environment."""
    result = subprocess.run(
        [str(Path(sys.executable).resolve(strict=True)), "--version"],
        env=_ENVIRONMENT,
        capture_output=True,
        timeout=5,
        check=True,
    )
    assert result.stdout.startswith(b"Python ") and not result.stderr
    return result.stdout, datetime.now(UTC).isoformat().replace("+00:00", "Z")


def evidence_record(
    *, result: EvidenceResult = "pass", classification: Classification = "internal"
) -> EvidenceReference2:
    """Build exact observed artifact metadata; included declared proofs grant no installed authority."""
    adapter = runtime_adapter()
    actual = adapter.record
    assert isinstance(actual, AdapterLock)
    sources = (adapter.reference(),)
    artifact, observed_at = observed_artifact()
    cohort = canonical_digest([ref.to_dict() for ref in sources])
    subject = evidence_subject_digest(
        adapter=adapter.reference(),
        artifact_digest=sha256(artifact).hexdigest(),
        artifact_size=len(artifact),
        configuration_digest=actual.config_digest,
        toolchain_digest=actual.executable_digest,
        cohort_digest=cohort,
        source_objects=sources,
        budget=budget(),
    )
    return EvidenceReference2.build(
        evidence_id="actual-runtime-version",
        evidence_type="runtime-version",
        adapter=adapter.reference(),
        artifact_digest=sha256(artifact).hexdigest(),
        artifact_size=len(artifact),
        classification=classification,
        reference="artifact:runtime-version",
        observed_at=observed_at,
        subject_digest=subject,
        configuration_digest=actual.config_digest,
        toolchain_digest=actual.executable_digest,
        cohort_digest=cohort,
        source_objects=sources,
        result=result,
        producer_proof=declared_proof(subject, "producer-snapshot"),
        freshness=freshness_proof(subject=subject),
        budget=budget(),
    )


def runtime_requirement() -> EvidenceRequirement1:
    """Bind the actual observed adapter and unchanged original qualitative subject/freshness policy."""
    return EvidenceRequirement1.build(
        evidence_type="runtime-version",
        adapter=runtime_adapter().reference(),
        subject_class="source",
        freshness_policy=PolicyComponent1(freshness_policy(), budget()).reference(),
        budget=budget(),
    )


@pytest.mark.parametrize("result", ["pass", "fail", "unavailable", "refused"])
@pytest.mark.parametrize("classification", ["public", "internal", "confidential", "secret"])
def test_actual_artifact_and_independent_subject_round_trip_preserve_result_declarations(
    result: EvidenceResult, classification: Classification
) -> None:
    """Every explicit result/classification remains structural metadata, including nonpassing results."""
    value = evidence_record(result=result, classification=classification)
    data = value.to_dict(budget=budget())
    assert EvidenceReference2.from_dict(data, budget=budget()) == value
    value.verify_requirement_binding(runtime_requirement(), freshness_policy(), budget=budget())
    assert value.artifact_digest == sha256(observed_artifact()[0]).hexdigest()
    assert value.artifact_size == len(observed_artifact()[0])
    assert (
        value.producer_proof.subject_digest
        == value.freshness.subject_digest
        == value.subject_digest
    )
    assert value.producer_proof.snapshot_id != value.freshness.snapshot_id
    assert value.subject_digest not in {
        value.evidence_digest,
        value.producer_proof.proof_digest,
        value.freshness.proof_digest,
    }
    assert data.pop("evidence_digest") == canonical_digest(data)
    assert data["result"] == result and data["classification"] == classification
    assert not {
        "expires_at",
        "freshness_seconds",
        "accepted",
        "guard_admissible",
        "artifact_bytes",
    }.intersection(data)
    ref = value.object_reference(budget=budget())
    assert (ref.kind, ref.format_version, ref.object_id, ref.object_digest) == (
        "evidence-reference",
        "2.0",
        value.evidence_id,
        value.evidence_digest,
    )


def test_subject_is_exact_closed_preproof_body_and_every_scope_identity_changes_it() -> None:
    """Artifact, size, configuration, toolchain, cohort and original source identities all bind independently."""
    value = evidence_record()
    body: dict[str, object] = {
        "schema_version": "1.0",
        "object_kind": "evidence-subject",
        "adapter": value.adapter.to_dict(),
        "artifact_digest": value.artifact_digest,
        "artifact_size": value.artifact_size,
        "configuration_digest": value.configuration_digest,
        "toolchain_digest": value.toolchain_digest,
        "cohort_digest": value.cohort_digest,
        "source_objects": [ref.to_dict() for ref in value.source_objects],
    }
    assert canonical_digest(body) == value.subject_digest
    for field in ["artifact_digest", "configuration_digest", "toolchain_digest", "cohort_digest"]:
        changed = {**body, field: "0" * 64}
        assert canonical_digest(changed) != value.subject_digest
    assert (
        canonical_digest({**body, "artifact_size": value.artifact_size + 1})
        != value.subject_digest
    )
    assert canonical_digest({**body, "source_objects": []}) != value.subject_digest
    assert not {"producer_proof", "freshness", "subject_digest", "evidence_digest"}.intersection(
        body
    )


def test_real_file_input_retains_actual_artifact_identity_and_old_evidence_remains_separate(
    tmp_path: Path,
) -> None:
    """Actual artifact/file bytes and duplicate-key refusals exercise real public reader boundaries."""
    value = evidence_record()
    artifact = tmp_path / "runtime-version.txt"
    artifact.write_bytes(observed_artifact()[0])
    assert sha256(artifact.read_bytes()).hexdigest() == value.artifact_digest
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(value.to_dict(budget=budget())), encoding="utf-8")
    assert (
        EvidenceReference2.from_dict(read_policy_document(path, budget=budget()), budget=budget())
        == value
    )
    path.write_text('{"result":"pass","result":"fail"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        read_policy_document(path, budget=budget())
    original = EvidenceReference.build(
        evidence_id="old-evidence",
        evidence_type=value.evidence_type,
        adapter_id=value.adapter.object_id,
        adapter_digest=value.adapter.object_digest,
        artifact_digest=value.artifact_digest,
        artifact_size=value.artifact_size,
        classification=value.classification,
        reference=value.reference,
        observed_at=value.observed_at,
        expires_at=(
            datetime.fromisoformat(value.observed_at.replace("Z", "+00:00")) + timedelta(hours=1)
        )
        .isoformat()
        .replace("+00:00", "Z"),
    )
    assert EvidenceReference.from_dict(original.to_dict()) == original
    with pytest.raises(ValueError):
        EvidenceReference2.from_dict(original.to_dict(), budget=budget())
    with pytest.raises(ValueError):
        EvidenceReference.from_dict(value.to_dict(budget=budget()))


@pytest.mark.parametrize(
    "field,bad",
    [
        ("schema_version", "1.0"),
        ("object_kind", "other"),
        ("evidence_id", "bad identity"),
        ("evidence_type", ""),
        ("adapter", reference().to_dict()),
        ("artifact_size", True),
        ("artifact_size", -1),
        ("artifact_digest", "0" * 64),
        ("configuration_digest", "0" * 64),
        ("toolchain_digest", "0" * 64),
        ("cohort_digest", "0" * 64),
        ("subject_digest", "0" * 64),
        ("classification", "open"),
        ("reference", "raw source bytes"),
        ("observed_at", "2026-10-28T12:00:00"),
        ("source_objects", []),
        ("source_objects", {}),
        ("source_objects", [{}]),
        ("result", True),
        ("result", "accepted"),
        ("producer_proof", {}),
        ("freshness", {}),
        ("evidence_digest", "0" * 64),
    ],
)
def test_rehashed_foreign_scope_and_malformed_evidence_refuse(field: str, bad: object) -> None:
    """A fresh enclosing hash cannot retarget either independent included proof or the observed artifact scope."""
    data = evidence_record().to_dict(budget=budget())
    data.pop("evidence_digest")
    data[field] = bad
    digest = "0" * 64 if field == "evidence_digest" else canonical_digest(data)
    with pytest.raises(ValueError):
        EvidenceReference2.from_dict({**data, "evidence_digest": digest}, budget=budget())


def test_foreign_proof_subjects_and_canonical_timestamp_alias_cannot_rewrite_input() -> None:
    """Individually valid original proof metadata must bind the independently computed evidence subject."""
    value = evidence_record()
    for changed in [
        replace(value, producer_proof=declared_proof("0" * 64)),
        replace(value, freshness=freshness_proof(subject="0" * 64)),
    ]:
        with pytest.raises(ValueError, match="independent evidence subject"):
            changed.to_dict(budget=budget())
    data = value.to_dict(budget=budget())
    data["observed_at"] = value.observed_at.replace("Z", "+00:00")
    with pytest.raises(ValueError, match="wire must remain unchanged"):
        EvidenceReference2.from_dict(data, budget=budget())


def test_requirement_binding_checks_actual_adapter_type_subject_and_original_policy() -> None:
    """Structural requirements cannot be supplied by other classes or silently reassigned to another evidence type."""
    value = evidence_record()
    requirement = runtime_requirement()
    with pytest.raises(ValueError, match="actual requirement"):
        value.verify_requirement_binding({}, freshness_policy(), budget=budget())
    with pytest.raises(ValueError, match="actual requirement"):
        value.verify_requirement_binding(requirement, {}, budget=budget())
    for field, changed in [
        ("evidence_type", "other-result"),
        ("subject_class", "other-subject"),
        ("adapter", reference("adapter-lock", "1.0", "other-adapter").to_dict()),
        (
            "freshness_policy",
            PolicyComponent1(freshness_policy(mode="immutable-object"), budget())
            .reference()
            .to_dict(),
        ),
    ]:
        data = requirement.to_dict(budget=budget())
        data[field] = changed
        data.pop("requirement_digest")
        data["requirement_digest"] = canonical_digest(data)
        wrong = EvidenceRequirement1.from_dict(data, budget=budget())
        with pytest.raises(ValueError, match="exact requirement"):
            value.verify_requirement_binding(wrong, freshness_policy(), budget=budget())


def test_complete_aggregate_source_and_original_proof_budgets_apply_before_children() -> None:
    """One source plus the complete clear-proof chain consumes exactly10 reference allocations."""
    value = evidence_record()
    data = value.to_dict(budget=budget())
    assert value.to_dict(budget=budget(references=10)) == data
    assert EvidenceReference2.from_dict(data, budget=budget(references=10)) == value
    for maximum in [5, 9]:
        with pytest.raises(ValueError, match="reference budget"):
            value.to_dict(budget=budget(references=maximum))
        with pytest.raises(ValueError, match=r"bounded array|reference budget"):
            EvidenceReference2.from_dict(data, budget=budget(references=maximum))
    for changed in [
        replace(value, source_objects=cast(tuple[TypedObjectRef1, ...], [])),
        replace(value, freshness=cast(FreshnessProof1, {})),
        replace(value, producer_proof=cast(OwnerProof1, {})),
    ]:
        with pytest.raises(ValueError):
            changed.to_dict(budget=budget())
    refs = (value.adapter, reference("adapter-lock", "1.0", "z-other"))
    for sources in [
        (value.adapter, value.adapter),
        tuple(reversed(refs)),
        cast(tuple[TypedObjectRef1, ...], ({},)),
        tuple(value.adapter for _ in range(129)),
    ]:
        with pytest.raises(ValueError):
            replace(value, source_objects=sources).to_dict(budget=budget())
    limits = budget().to_dict()
    limits["max_sources"] = 1
    limits.pop("budget_digest")
    limits["budget_digest"] = canonical_digest(limits)
    small = PolicyReadBudget1.from_dict(limits)
    with pytest.raises(ValueError, match="source budget"):
        replace(value, source_objects=refs).to_dict(budget=small)
    data["source_objects"] = [ref.to_dict() for ref in refs]
    with pytest.raises(ValueError, match="source budget"):
        EvidenceReference2.from_dict(data, budget=small)


def test_closed_fields_direct_digest_and_proof_mutations_are_rechecked() -> None:
    """No direct mutation or ignored extension can bypass the exact complete evidence envelope."""
    value = evidence_record()
    data = value.to_dict(budget=budget())
    with pytest.raises(ValueError, match="evidence digest"):
        replace(value, evidence_digest="0" * 64).to_dict(budget=budget())
    for changed in [
        {**data, "accepted": True},
        {k: v for k, v in data.items() if k != "producer_proof"},
    ]:
        with pytest.raises(ValueError):
            EvidenceReference2.from_dict(changed, budget=budget())
    object.__setattr__(value.producer_proof, "proof_digest", "0" * 64)
    with pytest.raises(ValueError, match="owner proof digest"):
        value.to_dict(budget=budget())
