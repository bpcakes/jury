#!/usr/bin/env python3
"""J18 suite-2 primitive interoperability; not a runtime or protocol acceptance gate.

Consumer: suite-2 provider selection. Checks two-way primitive interoperability
and wrong-key/context/ciphertext/AEAD refusal. Retire with suite 2. Uses only fixed public fixtures and never rewrites them.
"""
import argparse
from pathlib import Path
import json
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--runner", type=Path, required=True, help="consumer built from alternate/boringssl_runner.cc with the pinned BoringSSL provider")
args = parser.parse_args()
root = Path(__file__).resolve().parent
vectors = json.loads((root / "primitive-vectors.json").read_text())
alternate = json.loads((root / "primitive-alternate.json").read_text())
assert len(vectors) == len(alternate) == 4
assert [len(bytes.fromhex(v["plaintext"])) for v in vectors] == [32, 33, 0, 256]
runner = str(args.runner.resolve())
command = ["cargo", "run", "--manifest-path", str(root / "Cargo.toml"), "--locked", "--bin", "primitives"]
current = subprocess.run(command, stdout=subprocess.PIPE, check=True)
assert json.loads(current.stdout) == vectors, "current Rust deterministic seals differ from retained outputs"

def run(operation, values):
    return subprocess.run([runner, operation, *values], stdout=subprocess.PIPE, check=True)

negative = 0
for vector, retained in zip(vectors, alternate):
    run("hpke-open", [vector[k] for k in ("private_seed", "encapsulation", "info", "aad", "ciphertext", "plaintext")])
    result = run("hpke-seal", [vector[k] for k in ("private_seed", "encapsulation_entropy", "info", "aad", "plaintext")])
    enc, cipher = result.stdout.decode().splitlines()
    assert enc == vector["encapsulation"] == retained["encapsulation"]
    assert cipher == vector["ciphertext"] == retained["ciphertext"]
    assert vector == retained
    fields = ("private_seed", "encapsulation", "info", "aad", "ciphertext")
    original = [bytes.fromhex(vector[k]) for k in fields]
    for field, kind in [(0, "flip"), (0, "truncate"), (1, "flip"), (1, "truncate"),
                        (2, "flip"), (3, "flip"), (4, "flip"), (4, "last"), (4, "truncate")]:
        changed = list(original)
        data = bytearray(changed[field])
        if kind == "truncate":
            data = data[:-1]
        elif kind == "last":
            data[-1] ^= 1
        else:
            data[0] ^= 1
        changed[field] = bytes(data)
        run("hpke-reject", [value.hex() for value in changed])
        negative += 1
assert negative == 36
print("BoringSSL: 4 opens, 4 exact deterministic seals, 36 mutation/truncation refusals passed.", flush=True)
subprocess.run(["cargo", "run", "--manifest-path", str(root / "Cargo.toml"), "--locked",
                "--bin", "primitives", "--", "verify", str(root / "primitive-alternate.json")], check=True)
