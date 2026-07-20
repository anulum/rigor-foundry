# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA pack signing CLI
"""Emit a signed fixed CRA StandardPack without retaining private key material."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .cra_pack import build_cra_pack, cra_pack_payload_digest
from .cra_protocol import json_text
from .cra_sbom import read_import_file
from .internal_storage import write_new_text
from .standard_pack import PackSignature
from .trust import STANDARD_PACK_SIGNATURE_DOMAIN, ed25519_signature_message

_MAX_PRIVATE_KEY_BYTES = 16_384


def _load_signing_key(path: Path) -> Ed25519PrivateKey:
    """Load one bounded, stable, unencrypted Ed25519 PEM private key."""
    absolute = Path(os.path.abspath(path))
    before = absolute.stat(follow_symlinks=False)
    if os.name == "posix" and stat.S_IMODE(before.st_mode) & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("CRA pack signing key must not grant group or other permissions")
    payload, _digest = read_import_file(
        absolute,
        maximum_bytes=_MAX_PRIVATE_KEY_BYTES,
        label="CRA pack signing key",
    )
    after = absolute.stat(follow_symlinks=False)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ValueError("CRA pack signing key changed while being loaded")
    try:
        key = load_pem_private_key(payload, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("CRA pack signing key must be unencrypted Ed25519 PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("CRA pack signing key must be Ed25519")
    return key


def _cra_pack_command(args: argparse.Namespace) -> int:
    """Sign and create one immutable CRA pack JSON file."""
    key = _load_signing_key(args.signing_key)
    payload_digest = cra_pack_payload_digest()
    signature = PackSignature.build(
        key_id=args.key_id,
        payload_digest=payload_digest,
        signature_hex=key.sign(
            ed25519_signature_message(
                signature_domain=STANDARD_PACK_SIGNATURE_DOMAIN,
                payload_digest=payload_digest,
            )
        ).hex(),
    )
    pack = build_cra_pack(signature)
    write_new_text(args.out, json_text(pack.to_dict()))
    print(
        f"created signed CRA StandardPack {pack.pack_digest} at {args.out}; "
        "mapping evidence is not a compliance certification"
    )
    return 0


def add_cra_pack_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the externally keyed CRA StandardPack emitter."""
    parser = subparsers.add_parser(
        "cra-pack",
        help="Emit the fixed CRA StandardPack signed by an operator-supplied Ed25519 key.",
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.set_defaults(handler=_cra_pack_command)
