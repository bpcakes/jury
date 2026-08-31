#!/usr/bin/env python3
"""Standard-library consumer for Jury's public witness-v1 corpus."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise ValueError(message)


def raw(value: str) -> bytes:
    return bytes.fromhex(value)


def bytes_field(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def list_bytes(values: list[bytes]) -> bytes:
    return len(values).to_bytes(4, "big") + b"".join(bytes_field(value) for value in values)


def jce(domain: str, *fields: bytes) -> bytes:
    return domain.encode("ascii") + b"\x00\x00\x01" + b"".join(fields)


def digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def gf_mul(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        high = left & 0x80
        left = (left << 1) & 0xFF
        if high:
            left ^= 0x1B
        right >>= 1
    return result


def gf_pow(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = gf_mul(result, value)
        value = gf_mul(value, value)
        exponent >>= 1
    return result


def gf_inv(value: int) -> int:
    if value == 0:
        fail("zero has no GF(256) inverse")
    return gf_pow(value, 254)


def combine(shares: list[bytes]) -> bytes:
    if not shares or any(len(share) != len(shares[0]) for share in shares):
        fail("invalid shares")
    output = bytearray(len(shares[0]) - 1)
    for byte_index in range(1, len(shares[0])):
        value = 0
        for index, share in enumerate(shares):
            xi = share[0]
            coefficient = 1
            for other_index, other in enumerate(shares):
                if other_index == index:
                    continue
                xj = other[0]
                coefficient = gf_mul(coefficient, gf_mul(xj, gf_inv(xj ^ xi)))
            value ^= gf_mul(share[byte_index], coefficient)
        output[byte_index - 1] = value
    return bytes(output)


def check_hash_vectors(corpus: dict) -> int:
    checked = 0
    for name, vector in corpus["vectors"].items():
        if "hash_domain" in vector:
            expected = digest(
                jce(
                    vector["hash_domain"],
                    bytes_field(raw(vector["preimage_hex"])),
                    raw(vector["signature_hex"]),
                )
            )
            if expected.hex() != vector["digest_hex"]:
                fail(f"{name}: signed digest mismatch")
            checked += 1
        elif all(field in vector for field in ("domain", "preimage_hex", "digest_hex")):
            if digest(raw(vector["preimage_hex"])).hex() != vector["digest_hex"]:
                fail(f"{name}: digest mismatch")
            checked += 1
        if "fingerprint_preimage_hex" in vector:
            if digest(raw(vector["fingerprint_preimage_hex"])).hex() != vector["fingerprint_hex"]:
                fail(f"{name}: fingerprint mismatch")
            checked += 1

    receipt_core = corpus["vectors"]["receipt_core"]
    expected_core = digest(
        jce("jury-witness-v1/receipt/core-hash", bytes_field(raw(receipt_core["body_hex"])))
    )
    if expected_core.hex() != receipt_core["digest_hex"]:
        fail("receipt core digest mismatch")
    return checked + 1


def check_construction(corpus: dict) -> None:
    construction = corpus["construction_vector"]
    if construction["epoch_root"] is not None or construction["reusable_contribution"]:
        fail("corpus exposes reusable construction material")
    secret = raw(construction["revision_secret_hex"])
    shares = [raw(value) for value in construction["shares"]]
    if combine(shares[:2]) != secret or combine(shares[:1]) == secret:
        fail("2-of-3 reconstruction boundary failed")
    later = construction["later_revision"]
    later_secret = raw(later["revision_secret_hex"])
    later_shares = [raw(value) for value in later["shares"]]
    if combine(later_shares[:2]) != later_secret:
        fail("later revision reconstruction failed")
    if raw(later["cross_revision_share_result_hex"]) in (secret, later_secret):
        fail("cross-revision shares reconstructed a revision")

    for capsule in construction["capsules"]:
        expected = digest(
            jce(
                "jury-witness-v1/share/commitment",
                raw(capsule["context_digest_hex"]),
                raw(capsule["share_hex"]),
            )
        )
        if expected.hex() != capsule["share_commitment_hex"]:
            fail("share commitment mismatch")
    capsule_bytes = [raw(capsule["capsule_hex"]) for capsule in construction["capsules"]]
    capsule_set_digest = digest(
        jce("jury-witness-v1/capsule-set/hash", list_bytes(capsule_bytes))
    )
    if capsule_set_digest.hex() != construction["capsule_set_digest_hex"]:
        fail("capsule-set digest mismatch")
    witnessed_slot = raw(construction["witnessed_slot_hex"])
    witnessed_slot_digest = digest(
        jce("jury-witness-v1/slot/hash", bytes_field(witnessed_slot))
    )
    if witnessed_slot_digest.hex() != construction["witnessed_slot_digest_hex"]:
        fail("witnessed-slot digest mismatch")
    witnessed_state_digest = digest(
        jce("jury-witness-v1/slot-set/hash", list_bytes([witnessed_slot]))
    )
    if witnessed_state_digest.hex() != construction["witnessed_state_digest_hex"]:
        fail("witnessed-state digest mismatch")
    for contribution in construction["contributions"]:
        expected = digest(
            jce(
                "jury-witness-v1/contribution/hash",
                bytes_field(raw(contribution["envelope_hex"])),
            )
        )
        if expected.hex() != contribution["digest_hex"]:
            fail("contribution digest mismatch")


def presentation_result(case: dict) -> str:
    if not case["human"]:
        return (
            "accepted"
            if case["automatic_rule_match"] and case["empty_presentation"]
            else "policy-denied"
        )
    checks = (
        "complete",
        "digest_match",
        "lossless",
        "untruncated",
        "meaningful",
        "label_signature_valid",
        "label_current",
        "subject_binding_valid",
        "entitled",
    )
    return "accepted" if all(case[field] for field in checks) else "wrong-scope"


def protocol_result(case: dict) -> str:
    if not all(case[field] for field in ("known_version", "known_suite", "known_construction")):
        return "unsupported-version"
    if not case["within_bounds"] or not case["canonical"]:
        return "invalid"
    if not case["signature_valid"] or not case["domain_valid"]:
        return "invalid-signature"
    if not case["scope_equal"]:
        return "wrong-scope"
    if not case["policy_current"]:
        return "stale-policy"
    if not case["revision_current"]:
        return "wrong-scope"
    if not case["time_valid"]:
        return "expired"
    if not case["replay_consistent"]:
        return "replay-conflict"
    if not case["actors_unique"]:
        return "invalid"
    if not case["quorum_reached"]:
        return "insufficient-quorum"
    if not case["anchor_consistent"]:
        return "anchor-conflict"
    if not case["restored_state_safe"]:
        return "restored-state-unsafe"
    if not case["explicit_witnessed_path"]:
        return "direct-downgrade"
    return "accepted"


def split_write_result(case: dict) -> str:
    state = (case["database"], case["external"], case["pending"], case["output_escaped"])
    return {
        ("g", "g", "none", False): "serve-base",
        ("g+1", "g", "exact-candidate", False): "repeat-cas-readback",
        ("g+1", "candidate", "exact-candidate", False): "mark-published",
        ("g+1", "candidate", "published", True): "serve-stable-output",
    }.get(state, "anchor-conflict")


def check_cases(corpus: dict) -> None:
    for case in corpus["scope_cases"]:
        result = "accepted" if case["request"] == case["manifest"] else "wrong-scope"
        if result != case["expected"]:
            fail(f"scope case {case['name']} disagreed")
    for case in corpus["presentation_cases"]:
        if presentation_result(case) != case["expected"]:
            fail(f"presentation case {case['name']} disagreed")
    for case in corpus["protocol_cases"]:
        if protocol_result(case) != case["expected"]:
            fail(f"protocol case {case['name']} disagreed")
    for case in corpus["split_write_cases"]:
        if split_write_result(case) != case["expected"]:
            fail(f"split-write case {case['name']} disagreed")


def model_counts() -> dict[str, int]:
    result = {
        "states": 0,
        "applicable_states": 0,
        "earlier_reopens": 0,
        "old_approval_replay_attempts": 0,
        "old_response_replay_attempts": 0,
        "prior_state_authorizations": 0,
        "later_opens_with_fresh_quorum": 0,
        "excluded_direct_or_mixed": 0,
        "excluded_witness_threshold": 0,
        "authorization_compromise": 0,
        "counterexamples": 0,
    }
    for mode in ("witnessed-only", "mixed", "direct-only"):
        for compromised_witnesses in range(4):
            for compromised_approvers in range(3):
                for retain_earlier_secret in (False, True):
                    for request in ("absent", "current", "wrong-seal"):
                        for honest_approvals in range(3):
                            for replay_old_approvals in (False, True):
                                for requested_honest_contributions in range(4):
                                    for replay_old_response in (False, True):
                                        for attempt_direct in (False, True):
                                            result["states"] += 1
                                            current = request == "current"
                                            approvals = (
                                                min(2, honest_approvals + compromised_approvers)
                                                if current
                                                else 0
                                            )
                                            fresh_quorum = current and approvals >= 2
                                            honest_available = 3 - compromised_witnesses
                                            honest_contributions = (
                                                min(requested_honest_contributions, honest_available)
                                                if fresh_quorum
                                                else 0
                                            )
                                            witnessed_open = (
                                                compromised_witnesses + honest_contributions >= 2
                                            )
                                            direct_open = attempt_direct and mode != "witnessed-only"
                                            later_open = witnessed_open or direct_open
                                            if replay_old_approvals:
                                                result["old_approval_replay_attempts"] += 1
                                            if replay_old_response:
                                                result["old_response_replay_attempts"] += 1
                                            if replay_old_approvals and not current and approvals >= 2:
                                                result["prior_state_authorizations"] += 1
                                            if retain_earlier_secret:
                                                result["earlier_reopens"] += 1
                                            if later_open and fresh_quorum:
                                                result["later_opens_with_fresh_quorum"] += 1
                                            if mode != "witnessed-only":
                                                result["excluded_direct_or_mixed"] += 1
                                            elif compromised_witnesses >= 2:
                                                result["excluded_witness_threshold"] += 1
                                            else:
                                                result["applicable_states"] += 1
                                                if compromised_approvers >= 2 and fresh_quorum:
                                                    result["authorization_compromise"] += 1
                                                if later_open and not fresh_quorum:
                                                    result["counterexamples"] += 1
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: alternate_runner.py PATH/TO/vectors.json", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    corpus = json.loads(path.read_text(encoding="utf-8"))
    if corpus.get("schema") != "jury-witness-v1-conformance-corpus":
        fail("unknown corpus schema")
    hash_count = check_hash_vectors(corpus)
    check_construction(corpus)
    check_cases(corpus)
    actual_model = model_counts()
    if actual_model != corpus["retention_model"]["result"]:
        fail("retention model result disagreed")
    if actual_model["counterexamples"] or actual_model["prior_state_authorizations"]:
        fail("retention model found counterexamples")
    print(
        json.dumps(
            {
                "corpus": str(path),
                "hash_vectors_checked": hash_count,
                "scope_cases": len(corpus["scope_cases"]),
                "presentation_cases": len(corpus["presentation_cases"]),
                "protocol_cases": len(corpus["protocol_cases"]),
                "split_write_cases": len(corpus["split_write_cases"]),
                "model_states": actual_model["states"],
                "counterexamples": actual_model["counterexamples"],
                "result": "accepted",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"alternate runner: {error}", file=sys.stderr)
        raise SystemExit(1)
