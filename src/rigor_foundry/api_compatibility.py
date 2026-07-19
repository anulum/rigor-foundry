# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — declared Python API manifest scanner
"""Compare literal Python public surfaces with one tracked pinned manifest."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from pathlib import PurePosixPath

from .audit_primitives import canonical_digest, require_mapping, require_string
from .candidate_anchor import RepositoryTreeAnchor, TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .language_capabilities import repository_path_under_roots
from .models import AuditPolicy, Candidate

API_MANIFEST_PATH = "rigor-public-api.json"
API_MANIFEST_SCHEMA_VERSION = "1.0"
_MANIFEST_FIELDS = frozenset({"schema_version", "surfaces"})
_SURFACE_FIELDS = frozenset({"path", "exports"})
_MUTATING_SEQUENCE_METHODS = frozenset(
    {"append", "clear", "extend", "insert", "pop", "remove", "reverse", "sort"}
)


@dataclass(frozen=True)
class _DeclaredSurface:
    """One module-level ``__all__`` declaration and its static resolution."""

    item: TrackedFile
    line_start: int
    line_end: int
    exports: tuple[str, ...] | None

    @property
    def digest(self) -> str:
        """Return the canonical declared-surface identity."""
        return _surface_digest(self.item.path, self.exports or ())


@dataclass(frozen=True)
class _ManifestSurface:
    """One strict pinned public-surface record."""

    path: str
    exports: tuple[str, ...]

    @property
    def digest(self) -> str:
        """Return the canonical manifest-surface identity."""
        return _surface_digest(self.path, self.exports)


def _surface_digest(path: str, exports: tuple[str, ...]) -> str:
    """Bind a source path to its sorted unique public names."""
    return canonical_digest({"path": path, "exports": list(exports)})


def _line_digest(item: TrackedFile, line: int) -> str:
    """Return the SHA-256 of one exact declaration line."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _root_name(expression: ast.expr) -> str | None:
    """Return the base name of one attribute or subscript expression."""
    current = expression
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


class _PublicDeclarationMutation(ast.NodeVisitor):
    """Detect direct ``__all__`` writes without descending into nested scopes."""

    def __init__(self) -> None:
        self.detected = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Do not treat a nested synchronous function body as module execution."""

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Do not treat a nested asynchronous function body as module execution."""

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Do not treat a class namespace as a module public declaration."""

    def visit_Lambda(self, node: ast.Lambda) -> None:
        """Do not treat a deferred lambda body as module execution."""

    def visit_Name(self, node: ast.Name) -> None:
        """Recognise direct assignment, deletion, loops, and named expressions."""
        if node.id == "__all__" and isinstance(node.ctx, (ast.Store, ast.Del)):
            self.detected = True

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Recognise writes through one ``__all__``-rooted attribute."""
        if isinstance(node.ctx, (ast.Store, ast.Del)) and _root_name(node) == "__all__":
            self.detected = True
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Recognise writes through one ``__all__``-rooted subscript."""
        if isinstance(node.ctx, (ast.Store, ast.Del)) and _root_name(node) == "__all__":
            self.detected = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Recognise direct calls to builtin mutable-sequence operations."""
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _MUTATING_SEQUENCE_METHODS
            and _root_name(node.func.value) == "__all__"
        ):
            self.detected = True
        self.generic_visit(node)


def _writes_public_declaration(statement: ast.stmt) -> bool:
    """Return whether one module-level statement directly mutates ``__all__``."""
    detector = _PublicDeclarationMutation()
    detector.visit(statement)
    return detector.detected


def _literal_exports(statement: ast.stmt) -> tuple[str, ...] | None:
    """Resolve one direct literal ``__all__`` assignment or return ``None``."""
    value: ast.expr | None = None
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == "__all__"
    ) or (
        isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and statement.target.id == "__all__"
    ):
        value = statement.value
    if not isinstance(value, (ast.List, ast.Tuple)):
        return None
    exports = tuple(
        element.value
        for element in value.elts
        if isinstance(element, ast.Constant) and isinstance(element.value, str)
    )
    if len(exports) != len(value.elts):
        return None
    if len(exports) != len(set(exports)) or any(not name.isidentifier() for name in exports):
        return None
    return tuple(sorted(exports))


def _declared_surface(item: TrackedFile, policy: AuditPolicy) -> _DeclaredSurface | None:
    """Return one source-root public declaration when it is present."""
    if (
        item.text is None
        or not item.path.endswith(".py")
        or not repository_path_under_roots(item.path, policy.source_roots)
    ):
        return None
    try:
        tree = ast.parse(item.text, filename=item.path)
    except SyntaxError:
        return None
    statements = tuple(
        statement for statement in tree.body if _writes_public_declaration(statement)
    )
    if not statements:
        return None
    first = statements[0]
    last = statements[-1]
    exports = _literal_exports(first) if len(statements) == 1 else None
    return _DeclaredSurface(
        item=item,
        line_start=first.lineno,
        line_end=max(first.lineno, getattr(last, "end_lineno", last.lineno)),
        exports=exports,
    )


def _manifest_path(value: object) -> str:
    """Return one canonical repository-relative Python source path."""
    path = require_string(value, "public_api_manifest.surfaces.path")
    pure = PurePosixPath(path)
    if (
        "\\" in path
        or pure.is_absolute()
        or str(pure) != path
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.suffix != ".py"
    ):
        raise ValueError("public API surface path must be canonical repository-relative Python")
    return path


def _manifest_exports(value: object) -> tuple[str, ...]:
    """Return one sorted unique array of Python public names."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("public API surface exports must be a string array")
    exports = tuple(value)
    if exports != tuple(sorted(exports)) or len(exports) != len(set(exports)):
        raise ValueError("public API surface exports must be sorted and unique")
    if any(not name.isidentifier() for name in exports):
        raise ValueError("public API surface exports must be Python identifiers")
    return exports


def _parse_manifest(text: str) -> tuple[_ManifestSurface, ...]:
    """Parse one strict root public-API manifest."""
    data = require_mapping(json.loads(text), "public_api_manifest")
    if frozenset(data) != _MANIFEST_FIELDS:
        raise ValueError("public API manifest fields do not match the schema")
    if data.get("schema_version") != API_MANIFEST_SCHEMA_VERSION:
        raise ValueError("unsupported public API manifest schema version")
    raw_surfaces = data.get("surfaces")
    if not isinstance(raw_surfaces, list):
        raise ValueError("public API manifest surfaces must be an array")
    surfaces: list[_ManifestSurface] = []
    for raw_surface in raw_surfaces:
        surface = require_mapping(raw_surface, "public_api_manifest.surfaces")
        if frozenset(surface) != _SURFACE_FIELDS:
            raise ValueError("public API surface fields do not match the schema")
        surfaces.append(
            _ManifestSurface(
                path=_manifest_path(surface.get("path")),
                exports=_manifest_exports(surface.get("exports")),
            )
        )
    paths = tuple(surface.path for surface in surfaces)
    if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
        raise ValueError("public API manifest surface paths must be sorted and unique")
    return tuple(surfaces)


def _candidate(
    surface: _DeclaredSurface,
    *,
    state: str,
    manifest: TrackedFile | None,
    manifest_surface: _ManifestSurface | None = None,
) -> Candidate:
    """Build one digest-only declaration-binding candidate."""
    fields = {
        "declaration_line_sha256": _line_digest(surface.item, surface.line_start),
        "declared_count": str(len(surface.exports or ())),
        "declared_surface_sha256": surface.digest,
        "file_sha256": surface.item.content_digest,
        "manifest_sha256": manifest.content_digest if manifest is not None else "absent",
        "manifest_state": state,
    }
    if manifest_surface is not None:
        fields["manifest_count"] = str(len(manifest_surface.exports))
        fields["manifest_surface_sha256"] = manifest_surface.digest
    return Candidate.build(
        category="api-compatibility",
        rule_id="AA001-unbound-api-manifest",
        anchor=TrackedBlobAnchor.build(
            surface.item,
            line_start=surface.line_start,
            line_end=surface.line_end,
        ),
        symbol=surface.item.path,
        evidence="; ".join(f"{name}={value}" for name, value in sorted(fields.items())),
        confidence="high",
        rationale=(
            "A declared Python public surface is not bound exactly by the tracked API manifest, "
            "so compatibility review cannot distinguish an intentional API edit from drift."
        ),
        verification=(
            "Review the declared names and downstream compatibility contract, then update "
            "rigor-public-api.json only when the exact public-surface change is intentional; "
            "do not infer a breaking change from unrelated source edits."
        ),
    )


def _manifest_candidate(
    inventory: GitInventory,
    manifest: TrackedFile,
    *,
    state: str,
    surface: _ManifestSurface | None = None,
) -> Candidate:
    """Build one manifest-owned schema or stale-record candidate."""
    anchor = (
        TrackedBlobAnchor.build(manifest, line_start=1)
        if manifest.scanned_blob_id is not None
        else RepositoryTreeAnchor.build(inventory, path=manifest.path)
    )
    fields = {
        "manifest_sha256": manifest.content_digest,
        "manifest_state": state,
    }
    symbol = API_MANIFEST_PATH
    if surface is not None:
        fields["manifest_count"] = str(len(surface.exports))
        fields["manifest_surface_sha256"] = surface.digest
        symbol = surface.path
    return Candidate.build(
        category="api-compatibility",
        rule_id="AA001-unbound-api-manifest",
        anchor=anchor,
        symbol=symbol,
        evidence="; ".join(f"{name}={value}" for name, value in sorted(fields.items())),
        confidence="high",
        rationale=(
            "The tracked public API manifest is malformed or retains a surface with no matching "
            "literal declaration, so it cannot bind the repository's declared API state."
        ),
        verification=(
            "Validate the versioned manifest schema and compare every recorded path with its exact "
            "module-level __all__; remove or update a row only after compatibility review."
        ),
    )


def scan_api_compatibility(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return public API manifest binding candidates.

    Parameters
    ----------
    inventory:
        Read-only tracked-content inventory of the repository.
    policy:
        Repository policy defining exact production source roots.

    Returns
    -------
    tuple[Candidate, ...]
        Deterministic missing, stale, malformed, or dynamic manifest bindings.
    """
    declarations = tuple(
        surface
        for item in inventory.files
        if (surface := _declared_surface(item, policy)) is not None
    )
    manifest = next((item for item in inventory.files if item.path == API_MANIFEST_PATH), None)
    if manifest is None:
        return tuple(
            _candidate(surface, state="missing", manifest=None) for surface in declarations
        )
    if manifest.text is None:
        return (_manifest_candidate(inventory, manifest, state="non-text"),)
    try:
        manifest_surfaces = _parse_manifest(manifest.text)
    except (ValueError, json.JSONDecodeError):
        return (_manifest_candidate(inventory, manifest, state="invalid"),)
    by_path = {surface.path: surface for surface in manifest_surfaces}
    candidates: list[Candidate] = []
    for declaration in declarations:
        recorded = by_path.get(declaration.item.path)
        if declaration.exports is None:
            candidates.append(
                _candidate(
                    declaration, state="dynamic", manifest=manifest, manifest_surface=recorded
                )
            )
        elif recorded is None:
            candidates.append(_candidate(declaration, state="unrecorded", manifest=manifest))
        elif declaration.exports != recorded.exports:
            candidates.append(
                _candidate(
                    declaration, state="mismatch", manifest=manifest, manifest_surface=recorded
                )
            )
    declared_paths = {surface.item.path for surface in declarations}
    candidates.extend(
        _manifest_candidate(inventory, manifest, state="stale", surface=surface)
        for surface in manifest_surfaces
        if surface.path not in declared_paths
    )
    return tuple(candidates)
