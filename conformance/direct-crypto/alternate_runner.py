#!/usr/bin/env python3
"""Run the frozen J01A primitive corpus through independent native providers."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import subprocess
from pathlib import Path


DIRECT_SLOT_HEADER_BYTES = 197
XWING_ENCAPSULATION_BYTES = 1_120


def altered(value: bytes, index: int = 0) -> bytes:
    output = bytearray(value)
    output[index] ^= 1
    return bytes(output)


def run(runner: Path, operation: str, *values: bytes) -> None:
    subprocess.run(
        [str(runner), operation, *(value.hex() for value in values)],
        check=True,
        stdin=subprocess.DEVNULL,
    )


def preimage(corpus: dict[str, object], name: str) -> bytes:
    return bytes.fromhex(corpus["preimages"][name]["hex"])


def check_boringssl(runner: Path, corpus: dict[str, object]) -> dict[str, int]:
    positive = 0
    negative = 0
    for vector in corpus["aead"].values():
        key = bytes.fromhex(vector["key_hex"])
        nonce = bytes.fromhex(vector["nonce_hex"])
        aad = preimage(corpus, vector["aad_preimage"])
        ciphertext = bytes.fromhex(vector["ciphertext_hex"])
        plaintext = bytes.fromhex(
            corpus["encodings"][vector["plaintext_encoding"]]["hex"]
        )
        run(runner, "aead-open", key, nonce, aad, ciphertext, plaintext)
        positive += 1
        for rejected in (
            (altered(key), nonce, aad, ciphertext),
            (key[:-1], nonce, aad, ciphertext),
            (key, nonce[:-1], aad, ciphertext),
            (key, nonce, altered(aad), ciphertext),
            (key, nonce, aad, altered(ciphertext)),
            (key, nonce, aad, altered(ciphertext, -1)),
            (key, nonce, aad, ciphertext[:-1]),
        ):
            run(runner, "aead-reject", *rejected)
            negative += 1

    hpke_vectors = list(corpus["encodings"]["direct_slots"].values()) + [
        corpus["encodings"]["registration_challenge_hpke"]
    ]
    for vector in hpke_vectors:
        private_key = bytes.fromhex(vector["recipient_private_seed_hex"])
        if "enc_hex" in vector:
            encapsulation = bytes.fromhex(vector["enc_hex"])
        else:
            slot = bytes.fromhex(vector["hex"])
            encapsulation = slot[
                DIRECT_SLOT_HEADER_BYTES : DIRECT_SLOT_HEADER_BYTES
                + XWING_ENCAPSULATION_BYTES
            ]
        info = preimage(corpus, vector["info_preimage"])
        aad = preimage(corpus, vector["aad_preimage"])
        ciphertext = bytes.fromhex(vector["ciphertext_hex"])
        plaintext = bytes.fromhex(vector["plaintext_hex"])
        run(
            runner,
            "hpke-open",
            private_key,
            encapsulation,
            info,
            aad,
            ciphertext,
            plaintext,
        )
        positive += 1
        for rejected in (
            (private_key[:-1], encapsulation, info, aad, ciphertext),
            (bytes(len(private_key)), encapsulation, info, aad, ciphertext),
            (private_key, altered(encapsulation), info, aad, ciphertext),
            (private_key, altered(encapsulation, -1), info, aad, ciphertext),
            (private_key, encapsulation[:-1], info, aad, ciphertext),
            (private_key, encapsulation, altered(info), aad, ciphertext),
            (private_key, encapsulation, info, altered(aad), ciphertext),
            (private_key, encapsulation, info, aad, altered(ciphertext)),
            (private_key, encapsulation, info, aad, altered(ciphertext, -1)),
            (private_key, encapsulation, info, aad, ciphertext[:-1]),
        ):
            run(runner, "hpke-reject", *rejected)
            negative += 1

    for vector in corpus["hkdf_sha256"].values():
        run(
            runner,
            "hkdf",
            bytes.fromhex(vector["ikm_hex"]),
            bytes.fromhex(vector["salt_hex"]),
            preimage(corpus, vector["info_preimage"]),
            bytes.fromhex(vector["output_hex"]),
        )
        positive += 1

    for vector in corpus["hmac_sha256"].values():
        key = bytes.fromhex(corpus["hkdf_sha256"][vector["key_vector"]]["output_hex"])
        message = preimage(corpus, vector["input_preimage"])
        tag = bytes.fromhex(vector["tag_hex"])
        run(runner, "hmac-valid", key, message, tag)
        positive += 1
        run(runner, "hmac-reject", key, message, altered(tag))
        run(runner, "hmac-reject", key, message, altered(tag, -1))
        negative += 2

    for vector in corpus["ed25519"].values():
        public_key = bytes.fromhex(
            corpus["fixture_signing_keys"][vector["signer"]]["public_key_hex"]
        )
        message = preimage(corpus, vector["message_preimage"])
        signature = bytes.fromhex(vector["signature_hex"])
        run(runner, "ed25519-valid", public_key, message, signature)
        positive += 1
        run(runner, "ed25519-reject", public_key, message, altered(signature))
        run(runner, "ed25519-reject", public_key, message, altered(signature, -1))
        run(runner, "ed25519-reject", public_key, message, signature[:-1])
        negative += 3

    noncanonical = next(
        case
        for case in corpus["negative_vectors"]
        if case["name"] == "ed25519_noncanonical_s"
    )
    positive_vector = corpus["ed25519"][noncanonical["source"]]
    public_key = bytes.fromhex(
        corpus["fixture_signing_keys"][positive_vector["signer"]]["public_key_hex"]
    )
    run(
        runner,
        "ed25519-reject",
        public_key,
        preimage(corpus, positive_vector["message_preimage"]),
        bytes.fromhex(noncanonical["mutated_hex"]),
    )
    negative += 1
    return {"positive": positive, "negative": negative}


def check_system_argon2(corpus: dict[str, object]) -> int:
    library_name = ctypes.util.find_library("argon2")
    if library_name is None:
        raise RuntimeError("system libargon2 was not found")
    library = ctypes.CDLL(library_name)
    argon2id_hash_raw = library.argon2id_hash_raw
    argon2id_hash_raw.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    argon2id_hash_raw.restype = ctypes.c_int
    password = bytes.fromhex(corpus["argon2id"]["password_hex"])
    checked = 0
    for name in ("portable-v1", "hardened-v1"):
        vector = corpus["argon2id"][name]
        salt = bytes.fromhex(vector["salt_hex"])
        expected = bytes.fromhex(vector["output_hex"])
        output = ctypes.create_string_buffer(len(expected))
        result = argon2id_hash_raw(
            vector["passes"],
            vector["memory_kib"],
            vector["lanes"],
            password,
            len(password),
            salt,
            len(salt),
            output,
            len(expected),
        )
        if result != 0 or output.raw != expected:
            raise RuntimeError(f"system libargon2 differs for {name}")
        checked += 1
    return checked


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("runner", type=Path)
    parser.add_argument("corpus", type=Path)
    arguments = parser.parse_args()
    corpus = json.loads(arguments.corpus.read_text(encoding="utf-8"))
    boringssl = check_boringssl(arguments.runner.resolve(), corpus)
    argon2 = check_system_argon2(corpus)
    print(
        json.dumps(
            {
                "argon2_positive_cases": argon2,
                "boringssl_negative_cases": boringssl["negative"],
                "boringssl_positive_cases": boringssl["positive"],
                "claim": "cross-provider primitive conformance; not independent review",
                "schema": "jury-j25-alternate-crypto-v1",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"alternate crypto conformance failed: {error}")
        raise SystemExit(1)
