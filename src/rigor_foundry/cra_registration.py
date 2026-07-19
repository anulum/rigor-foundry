# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA product registration records
"""Define operator-declared product context without compliance adjudication."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .audit_primitives import canonical_digest, require_exact_fields
from .cra_protocol import (
    CRA_SCHEMA_VERSION,
    MEMBER_STATE_PATTERN,
    EstablishmentBasis,
    JsonObject,
    json_text,
    optional_string,
    record_fields,
    require_cra_timestamp,
    require_enum,
)
from .model_primitives import require_digest, require_identifier
from .models import require_integer, require_mapping, require_string

_FIELDS = frozenset(
    {
        "schema_version",
        "product_key",
        "product_name",
        "manufacturer_name",
        "operator_role",
        "main_establishment_ms",
        "establishment_basis",
        "csirt_endpoint_id",
        "user_notice_channel",
        "support_period_months",
        "expected_use_months",
        "expected_use_evidence_ref",
        "registered_at",
        "registration_digest",
    }
)
_BASES = frozenset({"decisions", "employees", "auth-rep", "importer", "distributor", "users"})


@dataclass(frozen=True)
class ProductRegistration:
    """Store one operator-declared manufacturer and product context."""

    product_key: str
    product_name: str
    manufacturer_name: str
    operator_role: Literal["manufacturer"]
    main_establishment_ms: str
    establishment_basis: EstablishmentBasis
    csirt_endpoint_id: str
    user_notice_channel: str
    support_period_months: int
    expected_use_months: int | None
    expected_use_evidence_ref: str | None
    registered_at: str
    registration_digest: str

    @classmethod
    def build(
        cls,
        *,
        product_key: str,
        product_name: str,
        manufacturer_name: str,
        main_establishment_ms: str,
        establishment_basis: EstablishmentBasis,
        csirt_endpoint_id: str,
        user_notice_channel: str,
        support_period_months: int,
        expected_use_months: int | None,
        expected_use_evidence_ref: str | None,
        registered_at: str,
    ) -> ProductRegistration:
        """Build one digest-bound registration without judging applicability."""
        product_key = require_identifier(product_key, "product_key")
        product_name = require_string(product_name, "product_name")
        manufacturer_name = require_string(manufacturer_name, "manufacturer_name")
        if (
            main_establishment_ms != "none-eu"
            and MEMBER_STATE_PATTERN.fullmatch(main_establishment_ms) is None
        ):
            raise ValueError("main_establishment_ms must be alpha-2 uppercase or none-eu")
        establishment_basis = cast(
            EstablishmentBasis,
            require_enum(establishment_basis, "establishment_basis", _BASES),
        )
        csirt_endpoint_id = require_identifier(csirt_endpoint_id, "csirt_endpoint_id")
        user_notice_channel = require_string(user_notice_channel, "user_notice_channel")
        support_period_months = require_integer(
            support_period_months, "support_period_months", minimum=1
        )
        if expected_use_months is not None:
            expected_use_months = require_integer(
                expected_use_months, "expected_use_months", minimum=1
            )
            if expected_use_months >= 60:
                raise ValueError("expected_use_months must be below 60 when declared")
            expected_use_evidence_ref = require_string(
                expected_use_evidence_ref, "expected_use_evidence_ref"
            )
        elif expected_use_evidence_ref is not None:
            raise ValueError("expected_use_evidence_ref requires expected_use_months")
        registered_at = require_cra_timestamp(registered_at, "registered_at")
        body: JsonObject = {
            "schema_version": CRA_SCHEMA_VERSION,
            "product_key": product_key,
            "product_name": product_name,
            "manufacturer_name": manufacturer_name,
            "operator_role": "manufacturer",
            "main_establishment_ms": main_establishment_ms,
            "establishment_basis": establishment_basis,
            "csirt_endpoint_id": csirt_endpoint_id,
            "user_notice_channel": user_notice_channel,
            "support_period_months": support_period_months,
            "expected_use_months": expected_use_months,
            "expected_use_evidence_ref": expected_use_evidence_ref,
            "registered_at": registered_at,
        }
        return cls(
            product_key=product_key,
            product_name=product_name,
            manufacturer_name=manufacturer_name,
            operator_role="manufacturer",
            main_establishment_ms=main_establishment_ms,
            establishment_basis=establishment_basis,
            csirt_endpoint_id=csirt_endpoint_id,
            user_notice_channel=user_notice_channel,
            support_period_months=support_period_months,
            expected_use_months=expected_use_months,
            expected_use_evidence_ref=expected_use_evidence_ref,
            registered_at=registered_at,
            registration_digest=canonical_digest(body),
        )

    def to_dict(self) -> JsonObject:
        """Serialise the exact registration protocol object."""
        return {"schema_version": CRA_SCHEMA_VERSION, **record_fields(self)}

    def to_json(self) -> str:
        """Serialise deterministic human-readable JSON."""
        return json_text(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> ProductRegistration:
        """Parse and integrity-check one registration."""
        data = require_mapping(value, "product_registration")
        require_exact_fields(data, _FIELDS, "product_registration")
        if data.get("schema_version") != CRA_SCHEMA_VERSION:
            raise ValueError("product_registration schema_version is unsupported")
        role = require_string(data.get("operator_role"), "operator_role")
        if role != "manufacturer":
            raise ValueError("operator_role must be manufacturer")
        expected_use = data.get("expected_use_months")
        expected = cls.build(
            product_key=require_string(data.get("product_key"), "product_key"),
            product_name=require_string(data.get("product_name"), "product_name"),
            manufacturer_name=require_string(data.get("manufacturer_name"), "manufacturer_name"),
            main_establishment_ms=require_string(
                data.get("main_establishment_ms"), "main_establishment_ms"
            ),
            establishment_basis=cast(EstablishmentBasis, data.get("establishment_basis")),
            csirt_endpoint_id=require_string(data.get("csirt_endpoint_id"), "csirt_endpoint_id"),
            user_notice_channel=require_string(
                data.get("user_notice_channel"), "user_notice_channel"
            ),
            support_period_months=require_integer(
                data.get("support_period_months"), "support_period_months", minimum=1
            ),
            expected_use_months=(
                None
                if expected_use is None
                else require_integer(expected_use, "expected_use_months", minimum=1)
            ),
            expected_use_evidence_ref=optional_string(
                data.get("expected_use_evidence_ref"), "expected_use_evidence_ref"
            ),
            registered_at=require_string(data.get("registered_at"), "registered_at"),
        )
        recorded = require_digest(data.get("registration_digest"), "registration_digest")
        if recorded != expected.registration_digest:
            raise ValueError("registration digest does not match its content")
        return expected
