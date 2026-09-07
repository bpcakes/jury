#!/usr/bin/env python3
"""Independent encoder for J18's public bootstrap inputs; no runtime dependency.

Consumer: J18 bootstrap verification. Defect: ambiguous/circular bootstrap
commitment. Supersede with the next accepted format; fixtures are not live proof.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def raw(value):
    return base64.b64decode(value, validate=True)


def identifier(value):
    return bytes.fromhex(value)


def integer(value, width):
    return value.to_bytes(width, "big")


def blob(value):
    return integer(len(value), 4) + value


def records(values):
    return integer(len(values), 4) + b"".join(blob(value) for value in values)


def descriptor(value):
    return (integer(value["revision"], 8) + identifier(value["revision_seal_id"])
            + raw(value["nonce"]) + integer(value["ciphertext_length"], 4)
            + raw(value["ciphertext_digest"]) + integer(value["plaintext_schema"], 1)
            + integer(value["key_epoch"], 8))


def encode(value):
    principals = []
    for entry in value["principals"]:
        principals.append(identifier(entry["principal_id"])
                          + raw(entry["unsigned_descriptor_digest"])
                          + blob(entry["display_label"].encode("utf-8"))
                          + integer(entry["owner"], 1))
    items = []
    for entry in value["items"]:
        grants = [identifier(grant["principal_id"])
                  + integer({"reader": 1, "writer": 2, "owner": 3}[grant["role"]], 1)
                  + integer(grant["direct"], 1) for grant in entry["grants"]]
        witnessed = entry["witnessed"]
        optional = b"\0" if witnessed is None else (b"\1"
            + identifier(witnessed["policy_id"]) + identifier(witnessed["descriptor_slot_id"])
            + identifier(witnessed["body_slot_id"]))
        items.append(identifier(entry["source_item_id"]) + identifier(entry["destination_item_id"])
                     + integer({"canonical": 1, "legacy": 2}[entry["item_kind"]], 1)
                     + blob(descriptor(entry["descriptor"]))
                     + raw(entry["initial_item_revision_hash"])
                     + raw(entry["direct_slot_set_digest"]) + records(grants) + optional)
    policies = [identifier(entry["source_policy_id"]) + identifier(entry["destination_policy_id"])
                + raw(entry["intent_digest"]) for entry in value["witness_policies"]]
    return (b"jury-v1/rollover/bootstrap\0\0\1" + integer(value["version"], 2)
            + integer(value["destination_suite"], 2) + identifier(value["destination_vault_id"])
            + integer(value["created_at_ms"], 8) + identifier(value["acting_owner_principal_id"])
            + records(principals) + records(items) + records(policies))


def fixture(governed):
    def fixed(marker, length=32):
        return base64.b64encode(bytes([marker]) * length).decode("ascii")
    result = {
        "version": 1, "destination_suite": 1, "destination_vault_id": fixed(1),
        "created_at_ms": 1700000000000, "acting_owner_principal_id": fixed(2),
        "principals": [{"principal_id": fixed(2), "unsigned_descriptor_digest": fixed(3),
                        "display_label": "ExamplePrincipal", "owner": True}],
        "items": [{"source_item_id": fixed(4), "destination_item_id": fixed(5),
                   "item_kind": "canonical",
                   "descriptor": {"revision": 1, "revision_seal_id": fixed(6),
                                  "nonce": fixed(7, 12), "ciphertext_length": 272,
                                  "ciphertext_digest": fixed(8), "plaintext_schema": 1,
                                  "key_epoch": 1},
                   "initial_item_revision_hash": fixed(9),
                   "direct_slot_set_digest": (base64.b64encode(hashlib.sha256(b"\0" * 4).digest()).decode("ascii")
                                              if governed else fixed(10)),
                   "grants": [{"principal_id": fixed(2), "role": "owner", "direct": not governed}],
                   "witnessed": ({"policy_id": fixed(11), "descriptor_slot_id": fixed(12),
                                   "body_slot_id": fixed(13)} if governed else None)}],
        "witness_policies": ([{"source_policy_id": fixed(14), "destination_policy_id": fixed(11),
                               "intent_digest": fixed(15)}] if governed else []),
    }
    def convert_ids(value):
        if isinstance(value, dict):
            return {key: (raw(item).hex() if key.endswith("_id") else convert_ids(item))
                    for key, item in value.items()}
        if isinstance(value, list):
            return [convert_ids(item) for item in value]
        return value
    return convert_ids(result)


def corpus():
    vectors = []
    for name, governed in (("direct", False), ("witnessed", True)):
        manifest = fixture(governed)
        encoded = encode(manifest)
        vectors.append({"name": name, "manifest": manifest,
                        "preimage_hex": encoded.hex(),
                        "digest_hex": hashlib.sha256(encoded).hexdigest()})
    return {"schema": "jury-rollover-bootstrap-v1", "vectors": vectors}


def intent_corpus():
    source = json.loads(Path(__file__).parents[1].joinpath("witness-v1/vectors.json").read_text())
    policy = bytearray.fromhex(source["vectors"]["witness_policy"]["body_hex"])
    assert int.from_bytes(policy[34:42], "big") == 1
    policy[106:138] = bytes(32)  # genesis fingerprint
    policy[138:146] = integer(1, 8)  # initial vault policy sequence
    policy[146:178] = bytes(32)  # genesis/predecessor policy hash
    cursor = 182
    for expected_count in (2, 3):
        count = int.from_bytes(policy[cursor:cursor + 4], "big")
        assert count == expected_count
        cursor += 4
        for _ in range(count):
            size = int.from_bytes(policy[cursor:cursor + 4], "big")
            cursor += 4
            assert size >= 64 and cursor + size <= len(policy)
            policy[cursor + size - 64:cursor + size] = bytes(64)
            cursor += size
    policy[-33:-1] = bytes(32)  # real label-set digest is a later commitment
    fields = bytearray.fromhex(source["vectors"]["owner_review_label"]["field_bytes_hex"])
    fields[75:107] = bytes(32)  # label genesis fingerprint
    cursor = 107
    for width in (32, 32, 32):
        present = fields[cursor]
        assert present in (0, 1)
        cursor += 1 + present * width
    size = int.from_bytes(fields[cursor:cursor + 4], "big")
    cursor += 4 + size
    fields[cursor:cursor + 8] = integer(1, 8)
    label = b"jury-witness-v1/review-label/signature\0\0\1" + fields
    vectors = []
    for name, labels in (("empty_labels", []), ("owner_label", [label])):
        preimage = b"jury-v1/rollover/witness-intent\0\0\1" + blob(policy) + records(labels)
        vectors.append({"name": name, "projected_policy_hex": policy.hex(),
                        "projected_labels_hex": [entry.hex() for entry in labels],
                        "preimage_hex": preimage.hex(),
                        "digest_hex": hashlib.sha256(preimage).hexdigest()})
    return {"schema": "jury-rollover-witness-intent-v1", "vectors": vectors}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-initial", action="store_true")
    parser.add_argument("--intent", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).with_name("intent-vectors.json" if args.intent else "vectors.json")
    generated = json.dumps(intent_corpus() if args.intent else corpus(), indent=2, sort_keys=True) + "\n"
    if args.write_initial:
        # Never replace a mismatching golden to make a test pass.
        with path.open("x") as output:
            output.write(generated)
    elif path.read_text() != generated:
        raise SystemExit("rollover corpus differs")
    else:
        print("rollover encoding: frozen " + ("witness intent" if args.intent else "bootstrap") + " fixtures match")


if __name__ == "__main__":
    main()
