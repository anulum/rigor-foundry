# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — concrete clause selector tests
"""Exercise v2 matching against the reviewed table's real public surface."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_selected_clause_semantics_host_v2 import _state

from rigor_foundry.clause_scope_registry_expansion_v2 import expand_clause_scope_v2
from rigor_foundry.clause_selector_match_v2 import match_clause_selector_v2
from rigor_foundry.effect_target_table_v2 import EffectTargetTableV2
from rigor_foundry.selected_clause_semantics_host_v2 import HostSelectedClauseSemanticsVerifierV2

_PROJECT = "PROJECT-A"


def _matches(
    selector: str,
    *,
    effect_class: str = "local-file-write",
    target_kind: str = "filesystem-path",
    target_form: str = "path",
    target_value: str = "/srv/repo/file.py",
    subject: str = "admit",
    exclusion: bool = False,
    target_table: EffectTargetTableV2 | None = None,
) -> bool:
    """Pass one adapter-like extracted target through the public matcher."""
    return match_clause_selector_v2(
        selector=selector,
        subject=subject,
        exclusion=exclusion,
        effect_class=effect_class,
        project_id=_PROJECT,
        target_kind=target_kind,
        target_form=target_form,
        target_value=target_value,
        target_table=EffectTargetTableV2.build() if target_table is None else target_table,
    )


def test_path_and_repo_cover_component_subtrees_only() -> None:
    """A repository path covers descendants but never a sibling prefix."""
    assert _matches("repo:/srv/repo")
    assert _matches("path:/srv/repo")
    assert _matches("path:/")
    assert _matches("path:/srv/repo/file.py")
    assert not _matches("repo:/srv/repo2")
    assert not _matches("path:/srv/repo/file.py/child")
    assert not _matches(
        "repo:/srv/repo",
        effect_class="git-push-or-publication",
        target_kind="repository",
        target_form="remote",
        target_value="https://example.test/repo",
    )


def test_glob_exclusion_covers_matched_subtree() -> None:
    """A star matches one component and then the entire descendant tree."""
    assert _matches(
        "path-glob:/srv/*/WORKING",
        subject="rate",
        exclusion=True,
        target_value="/srv/repo/WORKING/deep/file.py",
    )
    assert not _matches(
        "path-glob:/srv/*/WORKING",
        subject="rate",
        exclusion=True,
        target_value="/srv/repo/OTHER/file.py",
    )
    assert not _matches(
        "path-glob:/srv/*/WORKING",
        subject="rate",
        exclusion=True,
        target_value="/srv/repo",
    )
    with pytest.raises(ValueError, match="forbidden wildcard"):
        _matches("path-glob:/srv/r?po/WORKING", subject="rate", exclusion=True)


@pytest.mark.parametrize(
    ("selector", "effect_class", "kind", "form", "value", "expected"),
    [
        (
            "any-remote",
            "git-push-or-publication",
            "repository",
            "remote",
            "https://x.test/r",
            True,
        ),
        ("any-endpoint", "external-send", "send-channel", "endpoint", "smtp:owner", True),
        (
            "any-send-channel",
            "external-send",
            "send-channel",
            "remote",
            "https://x.test/send",
            True,
        ),
        (
            "any-cloud-resource",
            "cloud-resource",
            "cloud-resource",
            "remote",
            "https://x.test/c",
            True,
        ),
        (
            "any-repository",
            "repo-visibility-change",
            "repository",
            "remote",
            "https://x.test/r",
            True,
        ),
        (
            "any-repository",
            "external-send",
            "send-channel",
            "remote",
            "https://x.test/send",
            False,
        ),
        ("any-endpoint", "external-send", "send-channel", "remote", "https://x.test/send", False),
    ],
)
def test_kind_wide_vetoes_match_only_declared_kind_or_form(
    selector: str, effect_class: str, kind: str, form: str, value: str, expected: bool
) -> None:
    """The table permits a form, while a veto may cover just a subset."""
    assert (
        _matches(
            selector,
            subject="veto",
            effect_class=effect_class,
            target_kind=kind,
            target_form=form,
            target_value=value,
        )
        is expected
    )


def test_exact_remote_endpoint_and_host() -> None:
    """Exact selectors compare canonical values with their distinct kinds."""
    assert _matches(
        "remote:https://x.test/r",
        effect_class="git-push-or-publication",
        target_kind="repository",
        target_form="remote",
        target_value="https://x.test/r",
    )
    assert not _matches(
        "remote:https://x.test/r",
        effect_class="git-push-or-publication",
        target_kind="repository",
        target_form="remote",
        target_value="https://x.test/other",
    )
    assert _matches(
        "endpoint:smtp:owner",
        effect_class="external-send",
        target_kind="send-channel",
        target_form="endpoint",
        target_value="smtp:owner",
    )
    assert _matches(
        "host:ml350",
        effect_class="compute-job",
        target_kind="compute-host",
        target_form="endpoint",
        target_value="host:ml350",
    )
    assert not _matches(
        "host:ml350",
        effect_class="compute-job",
        target_kind="compute-host",
        target_form="endpoint",
        target_value="host:other",
    )


def test_invalid_table_target_and_unexpanded_selector_refuse() -> None:
    """No caller string can silently supply a new kind, form or template."""
    forged = replace(EffectTargetTableV2.build(), table_digest="0" * 64)
    with pytest.raises(PermissionError, match="selected exact body"):
        _matches("path:/srv", target_table=forged)
    with pytest.raises(PermissionError, match="not in the selected table"):
        _matches("path:/srv", target_form="remote")
    with pytest.raises(ValueError, match="canonical"):
        _matches("path:/srv", target_value="/srv/../escape")
    with pytest.raises(ValueError, match="template reached"):
        _matches("project-root:PROJECT-A")
    with pytest.raises(ValueError, match="endpoint is malformed"):
        _matches(
            "endpoint:host:ml350",
            effect_class="compute-job",
            target_kind="compute-host",
            target_form="endpoint",
            target_value="host:ml350",
        )
    with pytest.raises(ValueError, match="host id is malformed"):
        _matches(
            "host:ML350",
            effect_class="compute-job",
            target_kind="compute-host",
            target_form="endpoint",
            target_value="host:ml350",
        )
    with pytest.raises(ValueError, match="must use host form"):
        _matches(
            "host:ml350",
            effect_class="compute-job",
            target_kind="compute-host",
            target_form="endpoint",
            target_value="smtp:owner",
        )
    with pytest.raises(ValueError, match="wrong kind"):
        _matches(
            "endpoint:smtp:owner",
            effect_class="external-send",
            target_kind="send-channel",
            target_form="endpoint",
            target_value="host:ml350",
        )


def test_signed_selected_scope_reaches_concrete_matcher(tmp_path: Path) -> None:
    """An exact signed fixture chain supplies a scope that matches an action path."""
    with _state(tmp_path) as selected:
        verifier = HostSelectedClauseSemanticsVerifierV2(lambda: nullcontext(selected))
        with verifier.verified_lease() as (state, proof):
            body = state.signed.body.to_dict()
            entries = cast(list[dict[str, object]], body["entries"])
            project_id = cast(str, body["project_id"])
            entry = entries[0]
            assert entry["clause_digest"] in proof.binding.active_admit_clause_digests
            expanded = expand_clause_scope_v2(
                scope=cast(dict[str, object], entry["scope"]),
                subject=cast(str, entry["subject"]),
                effect_class=cast(str, entry["effect_class"]),
                project_id=project_id,
                registry=state.registry,
                expected_registry_sha256=state.expected_registry_sha256,
                monorepo_root=state.monorepo_root,
                resolver_version=state.expected_resolver_version,
            )
            assert any(
                match_clause_selector_v2(
                    selector=selector,
                    subject="admit",
                    exclusion=False,
                    effect_class="local-file-write",
                    project_id=project_id,
                    target_kind="filesystem-path",
                    target_form="path",
                    target_value="/tmp/rigor/file.py",
                    target_table=EffectTargetTableV2.build(),
                )
                for selector in expanded.targets
            )
