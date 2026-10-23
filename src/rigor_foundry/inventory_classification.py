# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — configured repository input classifications
"""Apply exact retained-domain classifications without filtering observed paths."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from types import MappingProxyType

from .inventory_domain import InventoryDomain1
from .model_primitives import require_identifier
from .policy_read_budget import PolicyReadBudget1
from .repository_file_inputs import RepositoryFileInputs
from .repository_git_inputs import RepositoryGitInputs
from .repository_inventory_rows import RepositoryFileRow, repository_file_rows_digest


def _language(path: str, exact: Mapping[str, str], suffixes: Mapping[str, str]) -> str | None:
    """Select an exact path, then the longest declared lowercase suffix."""
    if path in exact:
        return exact[path]
    name = PurePosixPath(path).name.lower()
    for index, char in enumerate(name):
        if char == "." and (value := suffixes.get(name[index:])) is not None:
            return value
    return None


def _role(path: str, exact: Mapping[str, str], prefixes: Mapping[str, str]) -> str | None:
    """Select an exact path, then the longest whole-component declared prefix."""
    if path in exact:
        return exact[path]
    parts = PurePosixPath(path).parts
    for width in range(len(parts), 0, -1):
        if (value := prefixes.get("/".join(parts[:width]))) is not None:
            return value
    return None


@dataclass(frozen=True)
class InventoryFileClassifier:
    """Compile one complete declared domain once for repeated actual row groups.

    Immutable maps preserve the declaration's literal path rules. Compilation
    does not authenticate a source, inspect bytes or grant owner/admission proof.
    """

    domain: InventoryDomain1
    budget: PolicyReadBudget1
    _roots: frozenset[str] = field(init=False, repr=False)
    _rules: Mapping[tuple[str, str, str], Mapping[str, str]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate the complete declaration and freeze every compiled rule map."""
        if type(self.budget) is not PolicyReadBudget1 or type(self.domain) is not InventoryDomain1:
            raise ValueError("actual inventory domain and policy read budget are required")
        limits = PolicyReadBudget1.from_dict(self.budget.to_dict())
        checked = InventoryDomain1.from_dict(self.domain.to_dict(), budget=limits)
        mappings: dict[tuple[str, str, str], dict[str, str]] = {}
        for rule in checked.rules:
            mappings.setdefault((rule.root_id, rule.field, rule.selector_kind), {})[
                rule.selector
            ] = rule.value
        object.__setattr__(self, "domain", checked)
        object.__setattr__(self, "budget", limits)
        object.__setattr__(self, "_roots", frozenset(root.root_id for root in checked.roots))
        object.__setattr__(
            self,
            "_rules",
            MappingProxyType({key: MappingProxyType(value) for key, value in mappings.items()}),
        )

    def classify(
        self, rows: tuple[RepositoryFileRow, ...], *, root_id: str
    ) -> tuple[RepositoryFileRow, ...]:
        """Classify one complete row group without re-parsing the domain.

        Parameters
        ----------
        rows:
            Ordered immutable actual file observations, retaining unknown kinds.
        root_id:
            Exact declared root that owns these root-relative paths.

        Returns
        -------
        tuple of RepositoryFileRow
            Every original row, replacing only declared language/role labels.
        """
        selected = require_identifier(root_id, "inventory classification root")
        if selected not in self._roots:
            raise ValueError("classification root is absent from the selected inventory domain")
        repository_file_rows_digest(rows, budget=self.budget)
        if len(rows) > self.budget.max_sources:
            raise ValueError("classified inventory exceeds the source count budget")
        empty: Mapping[str, str] = MappingProxyType({})
        language_exact = self._rules.get((selected, "language", "exact"), empty)
        language_suffixes = self._rules.get((selected, "language", "suffix"), empty)
        role_exact = self._rules.get((selected, "role", "exact"), empty)
        role_prefixes = self._rules.get((selected, "role", "prefix"), empty)
        return tuple(
            replace(row, language=None, role=None)
            if row.kind in {"unsupported", "gitlink"}
            else replace(
                row,
                language=_language(row.relative_path, language_exact, language_suffixes),
                role=_role(row.relative_path, role_exact, role_prefixes),
            )
            for row in rows
        )


def classify_inventory_file_rows(
    rows: tuple[RepositoryFileRow, ...],
    *,
    root_id: str,
    domain: InventoryDomain1,
    budget: PolicyReadBudget1,
) -> tuple[RepositoryFileRow, ...]:
    """Classify complete actual Git or directory rows without changing their bytes.

    Parameters
    ----------
    rows:
        Ordered immutable file observations, including explicit unknown kinds.
    root_id:
        Exact declared root that owns these root-relative paths.
    domain:
        Complete configured declaration; no row or root filter is inferred.
    budget:
        Explicit original row, rule and root ceilings, supplying no authority.

    Returns
    -------
    tuple of RepositoryFileRow
        Every original row with only its declared path language/role replaced.
        Unmatched, unsupported and gitlink classifications remain unknown.
    """
    return InventoryFileClassifier(domain, budget).classify(rows, root_id=root_id)


def classify_repository_file_inputs(
    inputs: RepositoryFileInputs,
    *,
    root_id: str,
    domain: InventoryDomain1,
    budget: PolicyReadBudget1,
) -> RepositoryFileInputs:
    """Classify every retained Git-domain row using one explicit domain declaration.

    Parameters
    ----------
    inputs:
        Complete baseline/current file observations. No new filesystem read occurs.
    root_id:
        Exact declared root whose rules apply to these inline rows.
    domain:
        Complete configured declaration, revalidated before selecting its rules.
    budget:
        Explicit row, rule and root ceilings. These supply no access authority.

    Returns
    -------
    RepositoryFileInputs
        All original rows and Git state, with declared language/role labels.
        Unmatched fields and unsupported/gitlink rows remain explicitly unknown.

    Notes
    -----
    These are path classifications, not content-language verification, required
    root completeness, source authentication or installed context admission.
    The owning consumer must verify the actual selected domain and physical root.
    """
    if type(inputs) is not RepositoryFileInputs or type(inputs.git) is not RepositoryGitInputs:
        raise ValueError("actual repository file and Git inputs are required")
    classifier = InventoryFileClassifier(domain, budget)
    return replace(
        inputs,
        baseline_files=classifier.classify(inputs.baseline_files, root_id=root_id),
        current_files=classifier.classify(inputs.current_files, root_id=root_id),
    )
