#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys

from common import read_bytes, require, run_cmd, temp_path


def main() -> int:
    vm1_asm = pathlib.Path(sys.argv[1])
    fixture = pathlib.Path(sys.argv[2])
    seed_hex = "00112233445566778899aabbccddeeff"

    first = temp_path("vm1_env_seed_repro", ".vm1")
    second = temp_path("vm1_env_seed_repro", ".vm1")

    env = {"VMP_OPCODE_MAP_SEED": seed_hex}
    run_cmd([vm1_asm, fixture, first], env=env)
    run_cmd([vm1_asm, fixture, second], env=env)

    require(read_bytes(first) == read_bytes(second), "fixed VMP_OPCODE_MAP_SEED must produce byte-identical VM1 output")
    print("cryptor_env_seed_reproducible OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
