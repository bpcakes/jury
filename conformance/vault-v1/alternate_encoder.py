#!/usr/bin/env python3
"""Independent standard-library encoder for the public Jury vault-v1 fixture."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "conformance/vault-v1/example-vault.json"
VECTORS = ROOT / "conformance/vault-v1/vectors.json"


def fixed(byte: int, length: int) -> bytes:
    return bytes([byte]) * length


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def bytes_field(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def jce(domain: str, *fields: bytes) -> bytes:
    return domain.encode("ascii") + b"\x00\x00\x01" + b"".join(fields)


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build_artifact() -> bytes:
    vault_id = fixed(0x11, 32)
    principal_id = fixed(0x22, 32)
    recipient_key = fixed(0x33, 1_216)
    verification_key = fixed(0x44, 32)
    self_signature = fixed(0x55, 64)
    owner_signature = fixed(0x66, 64)
    created_at_ms = 1_700_000_000_000
    owner_bytes = (
        (1).to_bytes(2, "big")
        + principal_id
        + b"\x01"
        + recipient_key
        + verification_key
        + self_signature
    )
    genesis_signature_preimage = jce(
        "jury-v1/policy-genesis/signature",
        vault_id,
        (0).to_bytes(8, "big"),
        fixed(0, 32),
        created_at_ms.to_bytes(8, "big"),
        bytes_field(owner_bytes),
        b"\x00",
        (0).to_bytes(4, "big"),
        (0).to_bytes(4, "big"),
    )
    fingerprint = hashlib.sha256(
        jce(
            "jury-v1/policy-genesis/fingerprint",
            bytes_field(genesis_signature_preimage),
            owner_signature,
        )
    ).digest()
    owner = {
        "descriptor_version": 1,
        "principal_id": principal_id.hex(),
        "principal_kind": "human",
        "recipient_public_key": b64(recipient_key),
        "verification_public_key": b64(verification_key),
        "self_signature": b64(self_signature),
    }
    artifact = {
        "header": {
            "magic": "jury-vault",
            "version": 1,
            "vault_id": vault_id.hex(),
            "created_at_ms": created_at_ms,
            "suite": 1,
            "policy_schema": 1,
            "item_schema": 1,
            "identity_schema": 1,
            "genesis_fingerprint": b64(fingerprint),
        },
        "policy": {
            "genesis": {
                "vault_id": vault_id.hex(),
                "policy_sequence": 0,
                "previous_policy_hash": b64(fixed(0, 32)),
                "created_at_ms": created_at_ms,
                "suite": 1,
                "owner": owner,
                "source_attestation": None,
                "item_inventory": [],
                "direct_grants": [],
                "owner_signature": b64(owner_signature),
            },
            "revisions": [],
        },
        "items": [],
        "suite_migration": None,
    }
    return json_bytes(artifact)


def build_vectors(artifact: bytes) -> bytes:
    vectors = {
        "schema": "jury-vault-v1-format-vectors",
        "schema_version": 1,
        "status": "pre-alpha-public-generic-fixtures-not-for-real-secrets",
        "artifact": "example-vault.json",
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "sources": {
            "direct": "docs/security/vectors/jury-v1-suite.json",
            "witnessed": "conformance/witness-v1/vectors.json",
        },
        "negative_cases": [
            {"name": "wrong-magic", "mutation": "wrong-magic", "expected": "invalid"},
            {"name": "unknown-version", "mutation": "unknown-version", "expected": "invalid"},
            {"name": "unknown-suite", "mutation": "unknown-suite", "expected": "invalid"},
            {"name": "local-state-field", "mutation": "local-state-field", "expected": "invalid"},
            {"name": "alternate-whitespace", "mutation": "alternate-whitespace", "expected": "non-canonical"},
            {"name": "conflict-marker", "mutation": "conflict-marker", "expected": "conflict-marker"},
            {"name": "truncated", "mutation": "truncated", "expected": "invalid"},
        ],
    }
    return json_bytes(vectors)


def update(path: Path, expected: bytes, write: bool) -> None:
    if write:
        path.write_bytes(expected)
        return
    if path.read_bytes() != expected:
        raise ValueError(f"{path.relative_to(ROOT)} differs from independent encoding")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    artifact = build_artifact()
    update(ARTIFACT, artifact, args.write)
    update(VECTORS, build_vectors(artifact), args.write)
    print(
        json.dumps(
            {
                "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
                "result": "written" if args.write else "accepted",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"vault-v1 alternate encoder: {error}")
        raise SystemExit(1)
