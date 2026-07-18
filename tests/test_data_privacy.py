# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — data-and-privacy scanner tests
"""Verify bounded, precise data-and-privacy candidates over tracked Python."""

from __future__ import annotations

import collections
from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.data_privacy import (
    _is_credential_name,
    _is_secret_literal,
    _line_evidence,
    scan_data_privacy,
)
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy, Candidate

# Split with runtime concatenation so this test file embeds no full PEM header of
# its own (which would self-trigger DP002); the written fixture still carries one.
_PEM_LEAK = "-----BEGIN RSA PRIVATE KEY" + "-----\\nabc\\n-----END RSA PRIVATE KEY-----"

# Five credential-named literal assignments and one embedded PEM private key.
_VULNERABLE = (
    'PASSWORD = "hunter2xyz"\n'
    'api_key = "sk-live-abc123"\n'
    'CLIENT_SECRET = "s3cr3tvalue"\n'
    'apiKey = "camelsecret123"\n'
    'auth_token: str = "tok-abc"\n'
    f'LEAK = "{_PEM_LEAK}"\n'
)

# Descriptor names, placeholders, templates, and non-literal values are all ignored.
_SAFE = (
    "import os\n\n"
    'password_field = "password"\n'
    'token_type = "Bearer"\n'
    'secretary = "Jane Doe"\n'
    'db_password = ""\n'
    'api_key_name = "X-API-KEY"\n'
    'config_secret = "${SECRET_ENV}"\n'
    'weak_password = "changeme"\n'
    'API_KEY = os.environ["API_KEY"]\n'
    "count = 5\n\n\n"
    "def helper() -> str:\n"
    '    return "somelongvalue"\n'
)


def _scan(repository: GitRepository, policy_path: Path) -> tuple[Candidate, ...]:
    return scan_data_privacy(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )


def test_scanner_flags_credentials_and_keys_and_ignores_safe(tmp_path: Path) -> None:
    """Every declared privacy defect is a candidate; safe and placeholder code is not."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/creds.py", _VULNERABLE)
    repository.write_text("src/pkg/safe.py", _SAFE)
    policy_path = repository.write_policy()
    repository.commit()

    candidates = _scan(repository, policy_path)
    by_rule = collections.Counter(item.rule_id for item in candidates)
    assert by_rule == {
        "DP001-hardcoded-credential": 5,
        "DP002-embedded-private-key": 1,
    }
    assert not [item for item in candidates if item.anchor.path == "src/pkg/safe.py"]

    credential = next(item for item in candidates if item.rule_id == "DP001-hardcoded-credential")
    assert credential.category == "data-privacy"
    assert credential.confidence == "medium"
    assert credential.symbol == "assignment"
    assert isinstance(credential.anchor, TrackedBlobAnchor)
    assert credential.evidence.startswith("file_sha256=")

    key = next(item for item in candidates if item.rule_id == "DP002-embedded-private-key")
    assert key.category == "data-privacy"
    assert key.confidence == "high"
    assert key.symbol == "private-key"
    assert key.anchor.line_start == 6


def test_scanner_orders_findings_by_line_then_rule(tmp_path: Path) -> None:
    """Candidates from one file are deterministically ordered by line then rule."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/creds.py", _VULNERABLE)
    policy_path = repository.write_policy()
    repository.commit()

    ordered = [
        (item.anchor.line_start, item.rule_id)
        for item in _scan(repository, policy_path)
        if isinstance(item.anchor, TrackedBlobAnchor)
    ]
    assert ordered == sorted(ordered)


def test_scanner_skips_non_python_unparseable_and_binary(tmp_path: Path) -> None:
    """Non-Python, syntactically broken, and undecodable files yield no candidates."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("docs/notes.txt", 'password = "leaked-value-1"\n')
    repository.write_text("src/pkg/broken.py", 'password = "x"\ndef f(:\n')
    repository.write_bytes("src/pkg/binary.py", b'\xff\xfe password = "x"\x00')
    policy_path = repository.write_policy()
    repository.commit()

    assert _scan(repository, policy_path) == ()


def test_credential_name_and_secret_literal_helpers() -> None:
    """The name classifier and literal filter draw precise boundaries."""
    assert _is_credential_name("password") is True
    assert _is_credential_name("api_key") is True
    assert _is_credential_name("apiKey") is True
    assert _is_credential_name("client_secret") is True
    # A concept-naming descriptor suffix is metadata, not the secret value.
    assert _is_credential_name("password_hash") is False
    assert _is_credential_name("api_key_name") is False
    # 'secretary' contains 'secret' but is not a credential component.
    assert _is_credential_name("secretary") is False
    assert _is_credential_name("total_count") is False

    assert _is_secret_literal("a-real-looking-secret") is True
    assert _is_secret_literal("changeme") is False
    assert _is_secret_literal("") is False
    assert _is_secret_literal("${SECRET_ENV}") is False
    assert _is_secret_literal("{{ vault_secret }}") is False


def test_line_evidence_is_bounded_beyond_the_file(tmp_path: Path) -> None:
    """Evidence for a line past the end of the file stays content-addressed."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    item = next(
        item for item in load_git_inventory(repository.root).files if item.text is not None
    )
    assert _line_evidence(item, 9999).startswith("file_sha256=")
