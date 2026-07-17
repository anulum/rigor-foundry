# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protocol model primitives
"""Provide strict, digest-safe primitives shared by protocol records."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, TypeAlias, cast

from .audit_primitives import canonical_digest, require_mapping, require_string

JsonScalar: TypeAlias = str | int | float | bool | None
"""Scalar values accepted by deterministic policy records."""

VariableValue: TypeAlias = str | int | float | bool | tuple[str, ...]
"""Typed non-secret project-variable value."""

VariableType = Literal["string", "integer", "number", "boolean", "string-list"]
VariableScope = Literal["project", "environment", "control"]
Sensitivity = Literal["public", "internal", "secret"]

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,191}\Z")
_SEMANTIC_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def require_identifier(value: object, field: str) -> str:
    """Return one portable, bounded protocol identifier."""
    text = require_string(value, field)
    if _IDENTIFIER.fullmatch(text) is None:
        raise ValueError(f"{field} must be a portable identifier")
    return text


def require_semantic_version(value: object, field: str) -> str:
    """Return one semantic version without an implicit latest tag."""
    text = require_string(value, field)
    match = _SEMANTIC_VERSION.fullmatch(text)
    prerelease = match.group("prerelease") if match is not None else None
    if match is None or (
        prerelease is not None
        and any(
            len(identifier) > 1 and identifier.startswith("0") and identifier.isdigit()
            for identifier in prerelease.split(".")
        )
    ):
        raise ValueError(f"{field} must be a semantic version")
    return text


def require_digest(value: object, field: str) -> str:
    """Return one lowercase SHA-256 digest."""
    text = require_string(value, field)
    if _HEX_DIGEST.fullmatch(text) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return text


def require_git_object(value: object, field: str) -> str:
    """Return one full hexadecimal Git object identifier."""
    text = require_string(value, field)
    if _GIT_OBJECT.fullmatch(text) is None:
        raise ValueError(f"{field} must be a full lowercase Git object identifier")
    return text


def parse_utc_timestamp(value: object, field: str) -> datetime:
    """Parse one ISO-8601 timestamp that denotes UTC exactly."""
    text = require_string(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{field} must use UTC")
    return parsed.astimezone(UTC)


def require_utc_timestamp(value: object, field: str) -> str:
    """Return one canonical UTC timestamp ending in ``Z``."""
    parsed = parse_utc_timestamp(value, field)
    return parsed.isoformat().replace("+00:00", "Z")


def require_boolean(value: object, field: str) -> bool:
    """Return a boolean without accepting integer lookalikes."""
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be boolean")
    return value


def require_number(value: object, field: str) -> int | float:
    """Return one finite JSON number without accepting booleans."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a number")
    if not math.isfinite(value):
        raise ValueError(f"{field} must be finite")
    return value


def require_json_scalar(value: object, field: str) -> JsonScalar:
    """Return a deterministic JSON scalar and reject non-finite numbers."""
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, (int, float)):
        return require_number(value, field)
    raise ValueError(f"{field} must be a JSON scalar")


def require_nonempty_strings(
    value: object,
    field: str,
    *,
    minimum: int = 0,
) -> tuple[str, ...]:
    """Return a string array whose items are non-empty."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a string array")
    items = tuple(cast(list[object], value))
    if len(items) < minimum:
        raise ValueError(f"{field} must contain at least {minimum} item(s)")
    if not all(isinstance(item, str) and item.strip() for item in items):
        raise ValueError(f"{field} items must be non-empty strings")
    return cast(tuple[str, ...], items)


def require_unique_strings(
    value: object,
    field: str,
    *,
    minimum: int = 0,
) -> tuple[str, ...]:
    """Return a non-empty-item string array with stable unique membership."""
    strings = require_nonempty_strings(value, field, minimum=minimum)
    if len(strings) != len(set(strings)):
        raise ValueError(f"{field} items must be unique")
    return strings


def validate_unique_strings(
    value: tuple[str, ...],
    field: str,
    *,
    minimum: int = 0,
) -> tuple[str, ...]:
    """Validate an already typed string tuple used by a builder."""
    return require_unique_strings(list(value), field, minimum=minimum)


def require_optional_string(value: object, field: str) -> str:
    """Return an optional string without coercion."""
    return require_string(value, field, allow_empty=True)


def require_variable_type(value: object, field: str) -> VariableType:
    """Return one supported project-variable type."""
    text = require_string(value, field)
    supported = {"string", "integer", "number", "boolean", "string-list"}
    if text not in supported:
        raise ValueError(f"{field} is unsupported")
    return cast(VariableType, text)


def require_variable_value(
    value: object,
    value_type: VariableType,
    field: str,
) -> VariableValue:
    """Validate and canonicalise one non-secret variable value."""
    if value_type == "string":
        return require_string(value, field)
    if value_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{field} must be an integer")
        return value
    if value_type == "number":
        return require_number(value, field)
    if value_type == "boolean":
        return require_boolean(value, field)
    if isinstance(value, tuple):
        value = list(value)
    return require_unique_strings(value, field)


def serialise_variable_value(value: VariableValue | None) -> object:
    """Return a JSON-compatible variable value."""
    return list(value) if isinstance(value, tuple) else value


@dataclass(frozen=True)
class SecretReference:
    """Opaque provider reference for a secret value; never the secret bytes."""

    provider: str
    reference: str
    version: str
    reference_digest: str

    @classmethod
    def build(cls, *, provider: str, reference: str, version: str) -> SecretReference:
        """Build one digest-bound opaque secret reference."""
        validated_provider = require_identifier(provider, "secret.provider")
        validated_reference = require_string(reference, "secret.reference")
        if any(character.isspace() for character in validated_reference):
            raise ValueError("secret.reference must not contain whitespace")
        validated_version = require_string(version, "secret.version")
        fields = {
            "provider": validated_provider,
            "reference": validated_reference,
            "version": validated_version,
        }
        return cls(
            provider=validated_provider,
            reference=validated_reference,
            version=validated_version,
            reference_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise only the opaque provider reference."""
        return {
            "provider": self.provider,
            "reference": self.reference,
            "version": self.version,
            "reference_digest": self.reference_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> SecretReference:
        """Parse and integrity-check one opaque secret reference."""
        data = require_mapping(value, "secret_reference")
        reference = cls.build(
            provider=require_identifier(data.get("provider"), "secret.provider"),
            reference=require_string(data.get("reference"), "secret.reference"),
            version=require_string(data.get("version"), "secret.version"),
        )
        recorded = require_digest(data.get("reference_digest"), "secret.reference_digest")
        if recorded != reference.reference_digest:
            raise ValueError("secret-reference digest does not match its content")
        return reference


@dataclass(frozen=True)
class VariableConstraints:
    """Type-aware bounds for one project variable."""

    allowed_values: tuple[JsonScalar, ...]
    pattern: str
    minimum: int | float | None
    maximum: int | float | None
    minimum_items: int | None
    maximum_items: int | None

    @classmethod
    def build(
        cls,
        *,
        allowed_values: tuple[JsonScalar, ...] = (),
        pattern: str = "",
        minimum: int | float | None = None,
        maximum: int | float | None = None,
        minimum_items: int | None = None,
        maximum_items: int | None = None,
    ) -> VariableConstraints:
        """Build constraints while rejecting contradictory bounds."""
        for index, item in enumerate(allowed_values):
            require_json_scalar(item, f"constraints.allowed_values[{index}]")
        if len(allowed_values) != len(set(allowed_values)):
            raise ValueError("constraints.allowed_values must be unique")
        if pattern:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError("constraints.pattern must be a valid regular expression") from exc
        validated_minimum = (
            None if minimum is None else require_number(minimum, "constraints.minimum")
        )
        validated_maximum = (
            None if maximum is None else require_number(maximum, "constraints.maximum")
        )
        if (
            validated_minimum is not None
            and validated_maximum is not None
            and validated_minimum > validated_maximum
        ):
            raise ValueError("constraints.minimum must not exceed maximum")
        for item, field in (
            (minimum_items, "constraints.minimum_items"),
            (maximum_items, "constraints.maximum_items"),
        ):
            if item is not None and (
                isinstance(item, bool) or not isinstance(item, int) or item < 0
            ):
                raise ValueError(f"{field} must be an integer >= 0")
        if (
            minimum_items is not None
            and maximum_items is not None
            and minimum_items > maximum_items
        ):
            raise ValueError("constraints.minimum_items must not exceed maximum_items")
        return cls(
            allowed_values=allowed_values,
            pattern=pattern,
            minimum=validated_minimum,
            maximum=validated_maximum,
            minimum_items=minimum_items,
            maximum_items=maximum_items,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise type-aware constraints."""
        return {
            "allowed_values": list(self.allowed_values),
            "pattern": self.pattern,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "minimum_items": self.minimum_items,
            "maximum_items": self.maximum_items,
        }

    @classmethod
    def from_dict(cls, value: object) -> VariableConstraints:
        """Parse one variable-constraint object."""
        data = require_mapping(value, "constraints")
        raw_allowed = data.get("allowed_values", [])
        if not isinstance(raw_allowed, list):
            raise ValueError("constraints.allowed_values must be an array")
        return cls.build(
            allowed_values=tuple(
                require_json_scalar(item, f"constraints.allowed_values[{index}]")
                for index, item in enumerate(cast(list[object], raw_allowed))
            ),
            pattern=require_string(
                data.get("pattern", ""),
                "constraints.pattern",
                allow_empty=True,
            ),
            minimum=(
                None
                if data.get("minimum") is None
                else require_number(data.get("minimum"), "constraints.minimum")
            ),
            maximum=(
                None
                if data.get("maximum") is None
                else require_number(data.get("maximum"), "constraints.maximum")
            ),
            minimum_items=cast(int | None, data.get("minimum_items")),
            maximum_items=cast(int | None, data.get("maximum_items")),
        )

    def validate(self, value: VariableValue, value_type: VariableType) -> None:
        """Validate a typed value against these constraints."""
        normalised = require_variable_value(value, value_type, "variable.value")
        if self.allowed_values and normalised not in self.allowed_values:
            raise ValueError("variable.value is not in constraints.allowed_values")
        if self.pattern and (
            not isinstance(normalised, str) or re.fullmatch(self.pattern, normalised) is None
        ):
            raise ValueError("variable.value does not match constraints.pattern")
        if self.minimum is not None or self.maximum is not None:
            number = require_number(normalised, "variable.value")
            if self.minimum is not None and number < self.minimum:
                raise ValueError("variable.value is below constraints.minimum")
            if self.maximum is not None and number > self.maximum:
                raise ValueError("variable.value exceeds constraints.maximum")
        if self.minimum_items is not None or self.maximum_items is not None:
            if not isinstance(normalised, tuple):
                raise ValueError("item-count constraints require string-list variables")
            if self.minimum_items is not None and len(normalised) < self.minimum_items:
                raise ValueError("variable.value has too few items")
            if self.maximum_items is not None and len(normalised) > self.maximum_items:
                raise ValueError("variable.value has too many items")


@dataclass(frozen=True)
class VariableDefinition:
    """Typed, scoped, sensitivity-labelled variable contract."""

    variable_id: str
    value_type: VariableType
    scope: VariableScope
    sensitivity: Sensitivity
    required: bool
    constraints: VariableConstraints
    default_value: VariableValue | None
    default_secret_ref: SecretReference | None
    source: str
    definition_digest: str

    @classmethod
    def build(
        cls,
        *,
        variable_id: str,
        value_type: VariableType,
        scope: VariableScope,
        sensitivity: Sensitivity,
        required: bool,
        constraints: VariableConstraints,
        default_value: VariableValue | None,
        default_secret_ref: SecretReference | None,
        source: str,
    ) -> VariableDefinition:
        """Build one variable definition without raw secret values."""
        require_variable_type(value_type, "variable.value_type")
        if scope not in {"project", "environment", "control"}:
            raise ValueError("variable.scope is unsupported")
        if sensitivity not in {"public", "internal", "secret"}:
            raise ValueError("variable.sensitivity is unsupported")
        if sensitivity == "secret":
            if default_value is not None:
                raise ValueError("secret variables cannot carry raw default values")
        elif default_secret_ref is not None:
            raise ValueError("non-secret variables cannot carry secret references")
        normalised_default = (
            None
            if default_value is None
            else require_variable_value(default_value, value_type, "variable.default_value")
        )
        if normalised_default is not None:
            constraints.validate(normalised_default, value_type)
        fields: dict[str, object] = {
            "schema_version": "1.0",
            "variable_id": require_identifier(variable_id, "variable.variable_id"),
            "value_type": value_type,
            "scope": scope,
            "sensitivity": sensitivity,
            "required": require_boolean(required, "variable.required"),
            "constraints": constraints.to_dict(),
            "default_value": serialise_variable_value(normalised_default),
            "default_secret_ref": (
                default_secret_ref.to_dict() if default_secret_ref is not None else None
            ),
            "source": require_string(source, "variable.source"),
        }
        return cls(
            variable_id=cast(str, fields["variable_id"]),
            value_type=value_type,
            scope=scope,
            sensitivity=sensitivity,
            required=required,
            constraints=constraints,
            default_value=normalised_default,
            default_secret_ref=default_secret_ref,
            source=cast(str, fields["source"]),
            definition_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one digest-bound variable definition."""
        return {
            "schema_version": "1.0",
            "variable_id": self.variable_id,
            "value_type": self.value_type,
            "scope": self.scope,
            "sensitivity": self.sensitivity,
            "required": self.required,
            "constraints": self.constraints.to_dict(),
            "default_value": serialise_variable_value(self.default_value),
            "default_secret_ref": (
                self.default_secret_ref.to_dict() if self.default_secret_ref else None
            ),
            "source": self.source,
            "definition_digest": self.definition_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> VariableDefinition:
        """Parse and integrity-check one variable definition."""
        data = require_mapping(value, "variable")
        if data.get("schema_version") != "1.0":
            raise ValueError("unsupported variable-definition schema version")
        value_type = require_variable_type(data.get("value_type"), "variable.value_type")
        scope = require_string(data.get("scope"), "variable.scope")
        sensitivity = require_string(data.get("sensitivity"), "variable.sensitivity")
        raw_default = data.get("default_value")
        if value_type == "string-list" and isinstance(raw_default, list):
            raw_default = tuple(cast(list[str], raw_default))
        raw_secret = data.get("default_secret_ref")
        definition = cls.build(
            variable_id=require_identifier(data.get("variable_id"), "variable.variable_id"),
            value_type=value_type,
            scope=cast(VariableScope, scope),
            sensitivity=cast(Sensitivity, sensitivity),
            required=require_boolean(data.get("required"), "variable.required"),
            constraints=VariableConstraints.from_dict(data.get("constraints")),
            default_value=(
                None
                if raw_default is None
                else require_variable_value(raw_default, value_type, "variable.default_value")
            ),
            default_secret_ref=(
                None if raw_secret is None else SecretReference.from_dict(raw_secret)
            ),
            source=require_string(data.get("source"), "variable.source"),
        )
        recorded = require_digest(data.get("definition_digest"), "variable.definition_digest")
        if recorded != definition.definition_digest:
            raise ValueError("variable-definition digest does not match its content")
        return definition


@dataclass(frozen=True)
class VariableAssignment:
    """One validated non-secret value or opaque secret provider reference."""

    variable_id: str
    value: VariableValue | None
    secret_ref: SecretReference | None
    source: str
    assignment_digest: str

    @classmethod
    def build(
        cls,
        definition: VariableDefinition,
        *,
        value: VariableValue | None,
        secret_ref: SecretReference | None,
        source: str,
    ) -> VariableAssignment:
        """Bind an assignment to its exact variable definition."""
        if definition.sensitivity == "secret":
            if value is not None or secret_ref is None:
                raise ValueError("secret assignments require only an opaque secret reference")
            normalised = None
        else:
            if value is None or secret_ref is not None:
                raise ValueError("non-secret assignments require one typed value")
            normalised = require_variable_value(
                value,
                definition.value_type,
                "assignment.value",
            )
            definition.constraints.validate(normalised, definition.value_type)
        fields: dict[str, object] = {
            "schema_version": "1.0",
            "variable_id": definition.variable_id,
            "definition_digest": definition.definition_digest,
            "value": serialise_variable_value(normalised),
            "secret_ref": secret_ref.to_dict() if secret_ref is not None else None,
            "source": require_string(source, "assignment.source"),
        }
        return cls(
            variable_id=definition.variable_id,
            value=normalised,
            secret_ref=secret_ref,
            source=cast(str, fields["source"]),
            assignment_digest=canonical_digest(fields),
        )

    def to_dict(self, definition_digest: str) -> dict[str, object]:
        """Serialise one assignment with the definition digest it binds."""
        return {
            "schema_version": "1.0",
            "variable_id": self.variable_id,
            "definition_digest": definition_digest,
            "value": serialise_variable_value(self.value),
            "secret_ref": self.secret_ref.to_dict() if self.secret_ref else None,
            "source": self.source,
            "assignment_digest": self.assignment_digest,
        }

    @classmethod
    def from_dict(
        cls,
        value: object,
        definition: VariableDefinition,
    ) -> VariableAssignment:
        """Parse an assignment and verify its exact definition binding."""
        data = require_mapping(value, "assignment")
        if data.get("schema_version") != "1.0":
            raise ValueError("unsupported variable-assignment schema version")
        if data.get("variable_id") != definition.variable_id:
            raise ValueError("assignment references the wrong variable")
        if data.get("definition_digest") != definition.definition_digest:
            raise ValueError("assignment definition digest does not match")
        raw_value = data.get("value")
        if definition.value_type == "string-list" and isinstance(raw_value, list):
            raw_value = tuple(cast(list[str], raw_value))
        raw_secret = data.get("secret_ref")
        assignment = cls.build(
            definition,
            value=(
                None
                if raw_value is None
                else require_variable_value(
                    raw_value,
                    definition.value_type,
                    "assignment.value",
                )
            ),
            secret_ref=(None if raw_secret is None else SecretReference.from_dict(raw_secret)),
            source=require_string(data.get("source"), "assignment.source"),
        )
        recorded = require_digest(data.get("assignment_digest"), "assignment.assignment_digest")
        if recorded != assignment.assignment_digest:
            raise ValueError("variable-assignment digest does not match its content")
        return assignment


@dataclass(frozen=True)
class WorkEvidence:
    """One bounded, reproducible command or artefact observation.

    Parameters
    ----------
    description:
        Factual statement of what the evidence establishes.
    command:
        Exact argv or source-inspection operation; never a shell string.
    exit_code:
        Observed process exit code, including negative signal values.
    output_digest:
        SHA-256 of the complete output or inspected content.
    artefact_digest:
        Optional SHA-256 of a durable referenced artefact.

    """

    description: str
    command: tuple[str, ...]
    exit_code: int
    output_digest: str
    artefact_digest: str = ""

    def __post_init__(self) -> None:
        """Reject malformed evidence even when constructed directly."""
        require_string(self.description, "evidence.description")
        require_nonempty_strings(list(self.command), "evidence.command", minimum=1)
        if any("\x00" in item for item in self.command):
            raise ValueError("evidence.command must not contain NUL bytes")
        if isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int):
            raise ValueError("evidence.exit_code must be an integer")
        require_digest(self.output_digest, "evidence.output_digest")
        if self.artefact_digest:
            require_digest(self.artefact_digest, "evidence.artefact_digest")

    def to_dict(self) -> dict[str, object]:
        """Serialise one evidence record."""
        return {
            "description": self.description,
            "command": list(self.command),
            "exit_code": self.exit_code,
            "output_digest": self.output_digest,
            "artefact_digest": self.artefact_digest,
        }

    @classmethod
    def from_dict(cls, value: object, index: int = 0) -> WorkEvidence:
        """Parse one evidence record without discarding signal exit codes."""
        field = f"evidence[{index}]"
        data = require_mapping(value, field)
        exit_code = data.get("exit_code")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise ValueError(f"{field}.exit_code must be an integer")
        return cls(
            description=require_string(data.get("description"), f"{field}.description"),
            command=require_nonempty_strings(data.get("command"), f"{field}.command", minimum=1),
            exit_code=exit_code,
            output_digest=require_digest(data.get("output_digest"), f"{field}.output_digest"),
            artefact_digest=require_optional_string(
                data.get("artefact_digest", ""),
                f"{field}.artefact_digest",
            ),
        )
