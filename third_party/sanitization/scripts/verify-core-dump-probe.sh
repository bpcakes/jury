#!/usr/bin/env bash
set -euo pipefail

if [[ "${SANITIZATION_RUN_CORE_DUMP_PROBE:-0}" != "1" ]]; then
    echo "skipping core-dump marker probe; set SANITIZATION_RUN_CORE_DUMP_PROBE=1 on a permitted Linux runner"
    exit 0
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "core-dump marker probe currently requires Linux" >&2
    exit 1
fi

core_pattern="$(cat /proc/sys/kernel/core_pattern)"
if [[ "${core_pattern}" == \|* || "${core_pattern}" == /* ]]; then
    echo "core-dump marker probe requires a non-piped relative core_pattern" >&2
    exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo build --release --manifest-path "${root}/tools/core-dump-probe/Cargo.toml"

probe="${root}/tools/core-dump-probe/target/release/core-dump-probe"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

(
    cd "${work}"
    ulimit -c unlimited
    "${probe}" &
    pid=$!
    wait "${pid}" || true
    printf '%s\n' "${pid}" >probe.pid
)

pid="$(cat "${work}/probe.pid")"
core_file="$(
    find "${work}" -maxdepth 1 -type f -name 'core*' -print -quit
)"
if [[ -z "${core_file}" ]]; then
    echo "requested core-dump probe produced no core file" >&2
    exit 1
fi

python3 - "${core_file}" "${pid}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
pid = int(sys.argv[2])

def rotate_left(value: int, amount: int) -> int:
    amount %= 32
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFF_FFFF

marker = bytearray()
for index in range(32):
    mixed = (pid * 0x9E37_79B9) & 0xFFFF_FFFF
    mixed = rotate_left(mixed, index % 31)
    mixed = (mixed + index * 0x045D_9F3B) & 0xFFFF_FFFF
    marker.append((mixed ^ (mixed >> 8) ^ (mixed >> 16) ^ (mixed >> 24)) & 0xFF)

if bytes(marker) in path.read_bytes():
    raise SystemExit("locked secret marker was present in the core dump")
print(f"locked secret marker absent from {path}")
PY
