#!/usr/bin/env python3
"""J18 version-2 bootstrap encoder, independent of Rust; no runtime dependency.

Consumer: J18 bootstrap verification. Defect: ambiguous source policy revision
mapping. Supersede with this format; retained vectors are encoding evidence only.
"""
import argparse
import copy
import runpy
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
    policies = [identifier(entry["source_policy_id"]) + integer(entry["source_policy_revision"], 8)
                + identifier(entry["destination_policy_id"])
                + raw(entry["intent_digest"]) for entry in value["witness_policies"]]
    return (b"jury-v1/rollover/bootstrap\0\0\1" + integer(value["version"], 2)
            + integer(value["source_suite"], 2) + integer(value["destination_suite"], 2) + identifier(value["destination_vault_id"])
            + integer(value["created_at_ms"], 8) + identifier(value["acting_owner_principal_id"])
            + records(principals) + records(items) + records(policies))


def fixtures():
    old = runpy.run_path(str(Path(__file__).resolve().parents[1] / "rollover-v1/encoding.py"))
    for governed in (False, True):
        value = old["fixture"](governed)
        value["version"] = 2
        value["source_suite"] = 1
        for entry in value["witness_policies"]:
            entry["source_policy_revision"] = 1
        yield ("governed" if governed else "direct"), value
    value = copy.deepcopy(value)
    policy = copy.deepcopy(value["witness_policies"][0])
    policy["source_policy_revision"] = 2
    policy["destination_policy_id"] = "77" * 32
    value["witness_policies"].append(policy)
    item = copy.deepcopy(value["items"][0])
    item["source_item_id"] = "88" * 32
    item["destination_item_id"] = "99" * 32
    item["witnessed"]["policy_id"] = policy["destination_policy_id"]
    item["witnessed"]["descriptor_slot_id"] = "aa" * 32
    item["witnessed"]["body_slot_id"] = "bb" * 32
    value["items"].append(item)
    value["items"].sort(key=lambda entry: entry["source_item_id"])
    yield "two-active-policy-revisions", value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--create", action="store_true", help="create a new corpus; refuses overwrite")
    args = parser.parse_args()
    path = Path(__file__).with_name("vectors.json")
    if args.create:
        vectors = []
        for name, manifest in fixtures():
            preimage = encode(manifest)
            vectors.append(dict(name=name, manifest=manifest, preimage_hex=preimage.hex(),
                                digest_hex=hashlib.sha256(preimage).hexdigest()))
        with path.open("x") as output:
            json.dump(dict(version=2, vectors=vectors), output, indent=2)
            output.write("\n")
        return
    corpus = json.loads(path.read_text())
    assert corpus["version"] == 2 and len(corpus["vectors"]) == 3
    for vector in corpus["vectors"]:
        preimage = encode(vector["manifest"])
        assert preimage.hex() == vector["preimage_hex"], vector["name"]
        assert hashlib.sha256(preimage).hexdigest() == vector["digest_hex"], vector["name"]
    print("rollover v2: three retained canonical vectors match Python encoding")


if __name__ == "__main__":
    main()
