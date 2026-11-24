# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — imported SARIF rules per tool component, in a separate namespace
"""Record a producer's rules per tool component under ``ext:<producer>:``, never in RULES.

A SARIF run's rules live in its driver and in each of its tool extensions. CodeQL, for
example, keeps every rule in query-pack extensions and none in its driver. Rules are kept
per component, the driver first and then each extension in order, and every record names
its component by name and version, never by its position alone. Imported rule ids never
enter the RigorFoundry rule registry or its rule-pack digest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final, cast

from .audit_primitives import canonical_digest
from .sarif_import_bounds import ResultSkipped, bounded_text

MAX_SHORT_DESCRIPTION_BYTES: Final = 1024
MAX_TAGS: Final = 32
MAX_TAG_BYTES: Final = 64
_PRODUCER_ID: Final = re.compile(r"[a-z][a-z0-9-]{0,31}")


def require_producer_id(value: object) -> str:
    """Return one valid producer slug, the namespace of its imported rules.

    Parameters
    ----------
    value : object
        Candidate producer identifier.

    Returns
    -------
    str
        A lower-case slug such as ``codeql``.

    Raises
    ------
    ValueError
        If the value is not a lower-case slug of at most 32 characters.
    """
    if not isinstance(value, str) or _PRODUCER_ID.fullmatch(value) is None:
        raise ValueError("producer id must be a lower-case slug of at most 32 characters")
    return value


def imported_rule_id(producer_id: str, source_rule_id: str) -> str:
    """Return the separate-namespace id of one imported rule, never a RigorFoundry rule id.

    Parameters
    ----------
    producer_id : str
        The declared producer slug.
    source_rule_id : str
        The producer's own non-empty rule id.

    Returns
    -------
    str
        ``ext:<producer_id>:<source_rule_id>``.
    """
    if not source_rule_id:
        raise ValueError("an imported rule id needs the producer's rule id")
    return f"ext:{require_producer_id(producer_id)}:{source_rule_id}"


@dataclass(frozen=True)
class ToolComponent:
    """The identity of a run's driver or of one extension: its name and version."""

    name: str
    version: str | None

    @classmethod
    def from_object(cls, component: dict[str, Any]) -> ToolComponent:
        """Return the identity of one ``tool.driver`` or ``tool.extensions[]`` object.

        Parameters
        ----------
        component : dict[str, Any]
            A component of a document that ``parse_sarif_document`` accepted, so its name
            is a string and its versions are strings when present.

        Returns
        -------
        ToolComponent
            The name, and ``semanticVersion`` when given, else ``version``, else None.
        """
        semantic = component.get("semanticVersion")
        return cls(
            component["name"], semantic if semantic is not None else component.get("version")
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the component identity."""
        return {"name": self.name, "version": self.version}


@dataclass(frozen=True)
class ImportedRule:
    """Bounded metadata of one producer rule, with a digest of the whole rule object."""

    rule_id: str
    rule_index: int
    tool_component_index: int | None
    tool_component: ToolComponent
    name: str | None
    short_description: str | None
    short_description_truncated: bool
    help_uri: str | None
    help_uri_dropped: bool
    default_level: str | None
    tags: tuple[str, ...]
    tags_truncated: bool
    rule_object_sha256: str

    @classmethod
    def build(
        cls,
        producer_id: str,
        rule: dict[str, Any],
        rule_index: int,
        *,
        tool_component: ToolComponent,
        tool_component_index: int | None = None,
    ) -> ImportedRule:
        """Record one rule object of a producer's driver or of one of its tool extensions.

        Parameters
        ----------
        producer_id : str
            The declared producer slug.
        rule : dict[str, Any]
            One ``rules`` entry of the driver or of an extension, verbatim.
        rule_index : int
            Its position in that component's rules.
        tool_component : ToolComponent
            The name and version of the component holding the rule.
        tool_component_index : int | None
            The extension's position in ``tool.extensions``, or None for the driver.

        Returns
        -------
        ImportedRule
            The bounded record.

        Raises
        ------
        ResultSkipped
            With ``rule-without-id`` if the rule has no string id.
        """
        source = rule.get("id")
        if not isinstance(source, str) or not source:
            raise ResultSkipped("rule-without-id")
        name = rule.get("name") if isinstance(rule.get("name"), str) else None
        short = rule.get("shortDescription")
        text = short.get("text") if isinstance(short, dict) else None
        description, cut = (
            bounded_text(text, MAX_SHORT_DESCRIPTION_BYTES)
            if isinstance(text, str)
            else (None, False)
        )
        uri = rule.get("helpUri")
        https = isinstance(uri, str) and uri.startswith("https://")
        configuration = rule.get("defaultConfiguration")
        level = configuration.get("level") if isinstance(configuration, dict) else None
        properties = rule.get("properties")
        raw_tags = properties.get("tags") if isinstance(properties, dict) else None
        offered = raw_tags if isinstance(raw_tags, list) else []
        malformed = raw_tags is not None and not isinstance(raw_tags, list)
        kept = tuple(
            tag
            for tag in offered[:MAX_TAGS]
            if isinstance(tag, str) and len(tag.encode("utf-8")) <= MAX_TAG_BYTES
        )
        return cls(
            rule_id=imported_rule_id(producer_id, source),
            rule_index=rule_index,
            tool_component_index=tool_component_index,
            tool_component=tool_component,
            name=name,
            short_description=description,
            short_description_truncated=cut,
            help_uri=cast(str, uri) if https else None,
            help_uri_dropped=uri is not None and not https,
            default_level=level if isinstance(level, str) else None,
            tags=kept,
            tags_truncated=malformed or len(kept) != len(offered),
            rule_object_sha256=canonical_digest(rule),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the rule record."""
        return {
            "rule_id": self.rule_id,
            "rule_index": self.rule_index,
            "tool_component_index": self.tool_component_index,
            "tool_component": self.tool_component.to_dict(),
            "name": self.name,
            "short_description": self.short_description,
            "short_description_truncated": self.short_description_truncated,
            "help_uri": self.help_uri,
            "help_uri_dropped": self.help_uri_dropped,
            "default_level": self.default_level,
            "tags": list(self.tags),
            "tags_truncated": self.tags_truncated,
            "rule_object_sha256": self.rule_object_sha256,
        }


@dataclass(frozen=True)
class ComponentRules:
    """One tool component's identity and its rules in order, None marking an entry without id."""

    component: ToolComponent
    rules: tuple[ImportedRule | None, ...]

    @classmethod
    def build(
        cls, producer_id: str, component: dict[str, Any], position: int | None
    ) -> ComponentRules:
        """Record one component's rules, keeping an entry that names no rule id as a gap.

        Parameters
        ----------
        producer_id : str
            The declared producer slug.
        component : dict[str, Any]
            One accepted ``tool.driver`` or ``tool.extensions[]`` object.
        position : int | None
            The extension's position, or None for the driver.

        Returns
        -------
        ComponentRules
            The identity and the recorded rules.
        """
        identity = ToolComponent.from_object(component)
        recorded: list[ImportedRule | None] = []
        for index, rule in enumerate(component.get("rules", [])):
            try:
                recorded.append(
                    ImportedRule.build(
                        producer_id,
                        rule,
                        index,
                        tool_component=identity,
                        tool_component_index=position,
                    )
                    if isinstance(rule, dict)
                    else None
                )
            except ResultSkipped:
                recorded.append(None)
        return cls(identity, tuple(recorded))


@dataclass(frozen=True)
class RunRules:
    """One run's imported rules per tool component: the driver's, then each extension's."""

    driver: ComponentRules
    extensions: tuple[ComponentRules, ...]

    @classmethod
    def build(cls, producer_id: str, run: dict[str, Any]) -> RunRules:
        """Record every rule of one strictly parsed run, per tool component.

        Parameters
        ----------
        producer_id : str
            The declared producer slug.
        run : dict[str, Any]
            One run of a document that ``parse_sarif_document`` accepted.

        Returns
        -------
        RunRules
            The driver's rules and each extension's rules, in tool order.
        """
        tool = run["tool"]
        return cls(
            driver=ComponentRules.build(producer_id, tool["driver"], None),
            extensions=tuple(
                ComponentRules.build(producer_id, extension, position)
                for position, extension in enumerate(tool.get("extensions", []))
            ),
        )

    def component(self, position: int | None) -> ComponentRules:
        """Return the driver, or the extension at one position of ``tool.extensions``.

        Parameters
        ----------
        position : int | None
            The extension's position, or None for the driver.

        Returns
        -------
        ComponentRules
            That component's identity and rules.

        Raises
        ------
        ResultSkipped
            With ``tool-component-out-of-range`` when no extension has that position.
        """
        if position is None:
            return self.driver
        if not 0 <= position < len(self.extensions):
            raise ResultSkipped("tool-component-out-of-range")
        return self.extensions[position]

    def resolve(self, position: int | None, index: int) -> ImportedRule:
        """Return the rule at one index of the driver or of one extension.

        Parameters
        ----------
        position : int | None
            The extension's position in ``tool.extensions``, or None for the driver.
        index : int
            The rule's position in that component.

        Returns
        -------
        ImportedRule
            The recorded rule.

        Raises
        ------
        ResultSkipped
            With ``tool-component-out-of-range``, ``rule-index-out-of-range`` or
            ``rule-without-id`` when the reference names no recorded rule.
        """
        rules = self.component(position).rules
        if not 0 <= index < len(rules):
            raise ResultSkipped("rule-index-out-of-range")
        rule = rules[index]
        if rule is None:
            raise ResultSkipped("rule-without-id")
        return rule
