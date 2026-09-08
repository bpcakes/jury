#!/usr/bin/env python3
"""Candidate J18 HPKE context vectors; not complete vault or live quorum proof.

Consumer: suite-2 input acceptance and runtime context tests. Preserve accepted
component encodings while changing the seven specified HPKE domain prefixes.
Retire with this suite. Normal verification never rewrites retained outputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]


def raw(value):
    return bytes.fromhex(value)


def jce(domain, suite):
    return domain.encode("ascii") + b"\0" + suite.to_bytes(2, "big")


def component_body(preimage, domain):
    prefix = jce(domain, 1)
    assert preimage.startswith(prefix), domain
    return preimage[len(prefix):]


def records(values):
    return len(values).to_bytes(4, "big") + b"".join(
        len(value).to_bytes(4, "big") + value for value in values)


def seal(runner, name, seed, info, aad, plaintext):
    # Deterministic public conformance entropy, never runtime randomness.
    entropy = hashlib.sha512(b"ExampleSuite2Context:" + name.encode("ascii")).digest()
    result = subprocess.run([str(runner), "hpke-seal", seed.hex(), entropy.hex(),
                             info.hex(), aad.hex(), plaintext.hex()],
                            stdout=subprocess.PIPE, check=True)
    enc, ciphertext = result.stdout.decode("ascii").splitlines()
    assert len(raw(enc)) == 1120 and len(raw(ciphertext)) == len(plaintext) + 16
    subprocess.run([str(runner), "hpke-open", seed.hex(), enc, info.hex(), aad.hex(),
                    ciphertext, plaintext.hex()], check=True)
    return dict(name=name, private_seed=seed.hex(), encapsulation_entropy=entropy.hex(),
                info=info.hex(), aad=aad.hex(), plaintext=plaintext.hex(),
                encapsulation=enc, ciphertext=ciphertext)


def construct(runner):
    direct = json.loads((REPO / "docs/security/vectors/jury-v1-suite.json").read_bytes())
    witness = json.loads((REPO / "conformance/witness-v1/vectors.json").read_bytes())
    vectors = []
    for name, source in direct["encodings"]["direct_slots"].items():
        info_domain = "jury-vault-v1-direct-revision-secret-slot"
        aad_domain = "jury-vault-v1-direct-revision-secret-slot-aad"
        info = jce(info_domain, 2) + component_body(
            raw(direct["preimages"][source["info_preimage"]]["hex"]), info_domain)
        aad = jce(aad_domain, 2) + component_body(
            raw(direct["preimages"][source["aad_preimage"]]["hex"]), aad_domain)
        vectors.append(seal(runner, "direct-" + name,
                            raw(source["recipient_private_seed_hex"]), info, aad,
                            raw(source["plaintext_hex"])))

    construction = witness["construction_vector"]
    assert hashlib.sha256(jce("jury-witness-v1/capsule-set/hash", 1)
                          + records([raw(capsule["capsule_hex"]) for capsule in construction["capsules"]])).hexdigest() == construction["capsule_set_digest_hex"]
    capsules = {}
    canonical_capsules = []
    for source in construction["capsules"]:
        context_domain = "jury-witness-v1/capsule/context"
        fields = component_body(raw(source["context_preimage_hex"]), context_domain)
        context = jce(context_domain, 2) + fields
        digest = hashlib.sha256(context).digest()
        share = raw(source["share_hex"])
        commitment = hashlib.sha256(jce("jury-witness-v1/share/commitment", 1)
                                    + digest + share).digest()
        info_domain = "jury-witness-v1/capsule/info"
        info_fields = component_body(raw(source["info_hex"]), info_domain)
        assert info_fields[:32] == raw(source["context_digest_hex"])
        info = jce(info_domain, 2) + digest + info_fields[32:]
        aad_domain = "jury-witness-v1/capsule/aad"
        aad_fields = component_body(raw(source["aad_hex"]), aad_domain)
        assert aad_fields[:64] == raw(source["context_digest_hex"]) + raw(source["share_commitment_hex"])
        aad = jce(aad_domain, 2) + digest + commitment + aad_fields[64:]
        vector = seal(runner, "capsule-" + str(source["share_index"]),
                      raw(source["recipient_private_seed_hex"]), info, aad, share)
        encoded = fields + digest + commitment + raw(vector["encapsulation"]) + raw(vector["ciphertext"])
        # The component field layout is unchanged, not guessed from offsets.
        assert (fields + raw(source["context_digest_hex"]) + raw(source["share_commitment_hex"])
                + raw(source["enc_hex"]) + raw(source["ciphertext_hex"])) == raw(source["capsule_hex"])
        vector.update(context_preimage=context.hex(), context_digest=digest.hex(),
                      share_commitment=commitment.hex(), canonical_capsule=encoded.hex())
        vectors.append(vector)
        canonical_capsules.append(encoded)
        capsules[source["witness_id_hex"]] = vector
    capsule_set_digest = hashlib.sha256(jce("jury-witness-v1/capsule-set/hash", 1)
                                        + records(canonical_capsules)).digest()
    for source in construction["contributions"]:
        capsule = capsules[source["witness_id_hex"]]
        info_domain = "jury-witness-v1/contribution/info"
        info_fields = component_body(raw(source["info_hex"]), info_domain)
        assert len(info_fields) == 7 * 32 + 1
        info = jce(info_domain, 2) + info_fields[:192] + raw(capsule["share_commitment"]) + info_fields[224:]
        aad_domain = "jury-witness-v1/contribution/aad"
        aad_fields = component_body(raw(source["aad_hex"]), aad_domain)
        assert aad_fields[:32] == raw(construction["capsule_set_digest_hex"])
        aad = jce(aad_domain, 2) + capsule_set_digest + raw(capsule["context_digest"]) + aad_fields[64:]
        vectors.append(seal(runner, "contribution-" + str(source["share_index"]),
                            raw(source["request_session_private_seed_hex"]), info, aad,
                            raw(source["plaintext_share_hex"])))
    return dict(schema="jury-suite2-hpke-contexts-v1", suite=2,
                scope="public canonical HPKE contexts, not full artifact or readiness proof",
                capsule_set_digest=capsule_set_digest.hex(), vectors=vectors)


def verify_refusals(runner, corpus):
    negative = 0
    for vector in corpus["vectors"]:
        parts = [raw(vector[key]) for key in ("private_seed", "encapsulation", "info", "aad", "ciphertext")]
        cases = []
        for field in range(5):
            changed = list(parts)
            changed[field] = bytes([changed[field][0] ^ 1]) + changed[field][1:]
            cases.append(changed)
        for field in (0, 1, 4):
            changed = list(parts)
            changed[field] = changed[field][:-1]
            cases.append(changed)
        changed = list(parts)
        for field in (2, 3):
            offset = changed[field].index(b"\0") + 1
            assert changed[field][offset:offset+2] == b"\0\2"
            changed[field] = changed[field][:offset] + b"\0\1" + changed[field][offset+2:]
        cases.append(changed)
        for changed in cases:
            subprocess.run([str(runner), "hpke-reject", *[value.hex() for value in changed]], check=True)
            negative += 1
        subprocess.run([str(runner), "hpke-reject-chacha", *[value.hex() for value in parts]], check=True)
        negative += 1
    assert negative == 70
    print("BoringSSL: 70 context key/ciphertext/truncation/profile/AEAD refusals passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--create", action="store_true", help="create once; refuses overwrite")
    args = parser.parse_args()
    corpus = construct(args.runner.resolve())
    path = ROOT / "context-vectors.json"
    if args.create:
        with path.open("x") as output:
            json.dump(corpus, output, indent=2)
            output.write("\n")
    else:
        assert json.loads(path.read_bytes()) == corpus, "retained suite-2 contexts or ciphertexts differ"
        verify_refusals(args.runner.resolve(), corpus)
        print("suite 2: seven retained canonical HPKE contexts match BoringSSL seal/open")


if __name__ == "__main__":
    main()
