# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — import of one declared producer's SARIF file into an import report
"""Import one declared producer's SARIF file into an import report, never into a verdict.

The file is refused as a whole when a whole-file limit, the producer declaration or the
commit binding refuses it. Otherwise each result becomes an anchored ``unreviewed``
candidate, an observation or a skip with its reason, and nothing changes the rule registry,
the rule-pack digest or any audit report. The provenance of such an import is ``declared``:
the producer identity is the file's own claim, recorded as such.
"""

from __future__ import annotations

import dataclasses
import hashlib

from .git_inventory import GitInventory
from .sarif_import_binding import ExecutedSarifBinding, bind_executed_sarif
from .sarif_import_document import parse_sarif_document
from .sarif_import_execution import ImportRun
from .sarif_import_locations import LocationRoots, RunLocations, route_result
from .sarif_import_producers import bind_head, identify_producer
from .sarif_import_records import ImportedCandidate, ImportObservation, ImportSkip
from .sarif_import_report import ImportReport
from .sarif_import_rules import RunRules, ToolComponent


def import_sarif(
    payload: bytes,
    producer_id: str,
    inventory: GitInventory,
    *,
    head: str | None = None,
    checkout_root: str | None = None,
) -> ImportReport:
    """Import one SARIF file of a declared producer against one verified inventory.

    Parameters
    ----------
    payload : bytes
        The exact bytes of the SARIF file.
    producer_id : str
        The declared producer of the file.
    inventory : GitInventory
        The verified inventory of the commit the file describes.
    head : str | None
        The commit the operator names, required when any run states no ``revisionId``.
    checkout_root : str | None
        The absolute path at which the producer saw the checkout, if it differs from the
        inventory's root. Absolute ``file:`` URIs resolve only below it.

    Returns
    -------
    ImportReport
        The ``declared`` import report, with candidates sorted by id.

    Raises
    ------
    SarifImportRefused
        When a whole-file limit, the producer declaration or the commit binding refuses
        the file.
    """
    document = parse_sarif_document(payload)
    identity = identify_producer(document, producer_id)
    bound = bind_head(document, inventory.head, head)
    roots = LocationRoots(
        checkout_root or inventory.root.as_posix(), identity.producer.root_base_ids
    )
    candidates: dict[str, ImportedCandidate] = {}
    observations: list[ImportObservation] = []
    skipped: list[ImportSkip] = []
    for run_index, run in enumerate(document.runs):
        rules = RunRules.build(producer_id, run)
        locations = RunLocations.build(run, inventory, roots)
        for result_index, result in enumerate(run.get("results", [])):
            if not isinstance(result, dict):
                skipped.append(ImportSkip(run_index, result_index, "malformed-result"))
                continue
            outcome = route_result(
                producer_id,
                result,
                rules,
                locations,
                run_index=run_index,
                result_index=result_index,
            )
            if isinstance(outcome, ImportObservation):
                observations.append(outcome)
            elif isinstance(outcome, ImportSkip):
                skipped.append(outcome)
            elif outcome.candidate_id in candidates:
                skipped.append(ImportSkip(run_index, result_index, "duplicate-candidate"))
            else:
                candidates[outcome.candidate_id] = outcome
    return ImportReport(
        head=bound,
        head_tree=inventory.head_tree,
        tracked_content_digest=inventory.tracked_content_digest,
        producer_id=producer_id,
        producer_declaration_digest=identity.producer.declaration_digest,
        driver=ToolComponent(identity.driver_name, identity.driver_version),
        provenance="declared",
        profile_evidence_digest=None,
        sarif_sha256=hashlib.sha256(payload).hexdigest(),
        imported_candidates=tuple(candidates[key] for key in sorted(candidates)),
        observations=tuple(observations),
        skipped=tuple(skipped),
    )


def import_executed_sarif(
    run: ImportRun,
    *,
    inventory: GitInventory,
    head: str,
) -> tuple[ImportReport, ExecutedSarifBinding]:
    """Import the SARIF second output of one complete import-profile run as ``executed``.

    Parameters
    ----------
    run : ImportRun
        The complete import-profile run.
    inventory : GitInventory
        The verified inventory the SARIF is anchored against; the run must have scanned
        its tracked content.
    head : str
        The checkout's HEAD, since the second output states no revision.

    Returns
    -------
    tuple[ImportReport, ExecutedSarifBinding]
        The ``executed`` import report, which cites the binding's digest, and the binding.

    Raises
    ------
    SarifImportRefused
        When the import or the binding is refused.
    """
    declared = import_sarif(run.sarif, run.profile.producer_id, inventory, head=head)
    binding = bind_executed_sarif(run, report=declared)
    executed = dataclasses.replace(
        declared, provenance="executed", profile_evidence_digest=binding.binding_digest
    )
    return executed, binding
