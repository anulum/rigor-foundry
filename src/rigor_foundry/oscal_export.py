# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — deterministic OSCAL assessment-results export
"""Export per-control assessments as candidate OSCAL observations, never an attestation."""

from __future__ import annotations

import json
from uuid import NAMESPACE_URL, uuid5

from .compliance_maps import NON_CERTIFICATION_NOTICE, ComplianceMapTemplate, DomainMapping
from .control_assessment import ControlAssessment
from .effective_profile import EffectiveControl, EffectiveProfileLock
from .model_primitives import require_utc_timestamp
from .models import canonical_digest
from .version import __version__

OSCAL_VERSION = "1.1.3"
_OSCAL_NAMESPACE = uuid5(NAMESPACE_URL, "https://github.com/anulum/RIGOR-FOUNDRY/ns/oscal")
_PROP_NAMESPACE = "https://github.com/anulum/RIGOR-FOUNDRY/ns/oscal"
_DOCUMENTATION_ROOT = "https://github.com/anulum/RIGOR-FOUNDRY"
_UNSUPPORTED_FIELDS = (
    "import-ap references a self-describing boundary, not an authored OSCAL assessment plan",
    "findings are omitted; RigorFoundry emits candidate observations, not attested findings",
    "risks are omitted; RigorFoundry does not compute residual risk",
)


def _uuid(*parts: str) -> str:
    """Return one deterministic RFC-4122 UUID for a stable object key."""
    return str(uuid5(_OSCAL_NAMESPACE, "\x1f".join(parts)))


def _prop(name: str, value: str, *, prop_class: str | None = None) -> dict[str, object]:
    """Return one namespaced OSCAL property."""
    prop: dict[str, object] = {"name": name, "value": value, "ns": _PROP_NAMESPACE}
    if prop_class is not None:
        prop["class"] = prop_class
    return prop


def _control_by_effective_digest(lock: EffectiveProfileLock) -> dict[str, EffectiveControl]:
    """Index the lock's effective controls by their effective digest."""
    return {control.effective_digest: control for control in lock.controls}


def _reference_props(mapping: DomainMapping, template_id: str) -> list[dict[str, object]]:
    """Return one related-control property for every mapped external reference."""
    return [
        _prop(
            "related-control",
            reference.reference,
            prop_class=template_id,
        )
        for reference in mapping.references
    ]


def _observation(
    assessment: ControlAssessment,
    control: EffectiveControl,
    template: ComplianceMapTemplate,
    collected: str,
) -> dict[str, object]:
    """Build one deterministic OSCAL observation for a per-control assessment."""
    domain = control.control.domain
    mapping = template.mapping_for(domain)
    props: list[dict[str, object]] = [
        _prop("rigor-foundry-status", assessment.status),
        _prop("rigor-foundry-control", assessment.control_id),
        _prop("rigor-foundry-domain", domain),
        _prop("rigor-foundry-assessment-digest", assessment.assessment_digest),
    ]
    props.extend(_reference_props(mapping, template.template_id))
    remarks = (
        mapping.unsupported_reason
        if not mapping.supported
        else f"{len(mapping.references)} external control reference(s) mapped for triage."
    )
    return {
        "uuid": _uuid("observation", assessment.assessment_digest),
        "title": f"{assessment.control_id} ({assessment.status})",
        "description": (
            f"Static RigorFoundry assessment of control {assessment.control_id} "
            f"in domain {domain} with status {assessment.status}."
        ),
        "methods": ["EXAMINE"],
        "types": ["control-objective"],
        "props": props,
        "collected": collected,
        "remarks": remarks,
    }


def _metadata(
    lock: EffectiveProfileLock,
    template: ComplianceMapTemplate,
    generated_at: str,
) -> dict[str, object]:
    """Build the OSCAL metadata block with an explicit non-attestation boundary."""
    props = [
        _prop("rigor-foundry-lock-digest", lock.lock_digest),
        _prop("rigor-foundry-template", template.template_id),
        _prop("rigor-foundry-template-digest", template.template_digest),
        _prop("rigor-foundry-standard", template.standard.standard_id),
        _prop("rigor-foundry-standard-version", template.standard.version),
        _prop("rigor-foundry-tool-version", __version__),
    ]
    props.extend(_prop("unsupported-field", note) for note in _UNSUPPORTED_FIELDS)
    return {
        "title": f"RigorFoundry candidate evidence — {template.standard.title}",
        "last-modified": generated_at,
        "version": template.template_version,
        "oscal-version": OSCAL_VERSION,
        "props": props,
        "remarks": NON_CERTIFICATION_NOTICE,
    }


def _oscal_document(
    lock: EffectiveProfileLock,
    assessments: tuple[ControlAssessment, ...],
    template: ComplianceMapTemplate,
    generated_at: str,
) -> dict[str, object]:
    """Build a deterministic OSCAL 1.1.3 assessment-results document.

    Parameters
    ----------
    lock:
        Effective profile lock whose controls the assessments cover.
    assessments:
        Per-control assessments to export as candidate observations.
    template:
        Compliance evidence-map template naming the external standard.
    generated_at:
        UTC timestamp used for deterministic metadata and collection times.

    Returns
    -------
    dict[str, object]
        Schema-shaped OSCAL assessment-results document.

    Raises
    ------
    ValueError
        If an assessment does not bind the lock or a control repeats.
    """
    instant = require_utc_timestamp(generated_at, "oscal.generated_at")
    index = _control_by_effective_digest(lock)
    seen: set[str] = set()
    observations: list[dict[str, object]] = []
    for assessment in assessments:
        if assessment.lock_digest != lock.lock_digest:
            raise ValueError("assessment lock digest does not match the export lock")
        control = index.get(assessment.effective_control_digest)
        if control is None:
            raise ValueError("assessment references a control absent from the lock")
        if assessment.effective_control_digest in seen:
            raise ValueError("assessment control is duplicated in the export")
        seen.add(assessment.effective_control_digest)
        observations.append(_observation(assessment, control, template, instant))
    result: dict[str, object] = {
        "uuid": _uuid("result", lock.lock_digest, template.template_digest),
        "title": "RigorFoundry candidate evidence result",
        "description": (
            "Static candidate observations mapped to named external controls. "
            "Not a compliance attestation."
        ),
        "start": instant,
        "observations": observations,
    }
    return {
        "assessment-results": {
            "uuid": _uuid(
                "assessment-results", lock.lock_digest, template.template_digest, instant
            ),
            "metadata": _metadata(lock, template, instant),
            "import-ap": {
                "href": f"{_DOCUMENTATION_ROOT}/blob/main/docs/compliance-maps.md#export-boundary",
                "remarks": "RigorFoundry does not author an OSCAL assessment plan; this boundary is self-describing.",
            },
            "results": [result],
        }
    }


def export_digest(
    lock: EffectiveProfileLock,
    assessments: tuple[ControlAssessment, ...],
    template: ComplianceMapTemplate,
    generated_at: str,
) -> str:
    """Return the canonical digest of one OSCAL export for integrity binding."""
    return canonical_digest(_oscal_document(lock, assessments, template, generated_at))


def report_oscal(
    lock: EffectiveProfileLock,
    assessments: tuple[ControlAssessment, ...],
    template: ComplianceMapTemplate,
    generated_at: str,
) -> str:
    """Render deterministic OSCAL 1.1.3 assessment-results JSON with a trailing newline.

    Parameters
    ----------
    lock:
        Effective profile lock whose controls the assessments cover.
    assessments:
        Per-control assessments to export as candidate observations.
    template:
        Compliance evidence-map template naming the external standard.
    generated_at:
        UTC timestamp used for deterministic metadata and collection times.

    Returns
    -------
    str
        Human-readable, stable-key-order OSCAL JSON.
    """
    return (
        json.dumps(
            _oscal_document(lock, assessments, template, generated_at),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


__all__ = [
    "OSCAL_VERSION",
    "export_digest",
    "report_oscal",
]
