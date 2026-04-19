#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys

from common import VM2_BLNK_OPCODE, VM2_ENCRYPTED_FLAG, parse_vm2_module, read_bytes, require, run_cmd, seeded_hex_values, temp_path


def main() -> int:
    vm2_asm = pathlib.Path(sys.argv[1])
    vm2_run = pathlib.Path(sys.argv[2])
    fixture = pathlib.Path(sys.argv[3])

    for index, seed_hex in enumerate(seeded_hex_values(5)):
        module_path = temp_path(f"vm2_fib20_seed_{index}", ".vm2")
        run_cmd([vm2_asm, "--opcode-seed", seed_hex, fixture, module_path])
        completed = run_cmd([vm2_run, module_path, "20"])
        require("ret_int=6765" in completed.stdout, f"vm2 fib20 incorrect for seed {seed_hex}")

    env_seed = "8899aabbccddeeff0011223344556677"
    env_a = temp_path("vm2_env_seed", ".vm2")
    env_b = temp_path("vm2_env_seed", ".vm2")
    run_cmd([vm2_asm, fixture, env_a], env={"VMP_OPCODE_MAP_SEED": env_seed})
    run_cmd([vm2_asm, fixture, env_b], env={"VMP_OPCODE_MAP_SEED": env_seed})
    require(read_bytes(env_a) == read_bytes(env_b), "fixed VMP_OPCODE_MAP_SEED must produce byte-identical VM2 output")

    identity_path = temp_path("vm2_no_encrypt", ".vm2")
    run_cmd([vm2_asm, "--no-encrypt-opcodes", fixture, identity_path])
    parsed_identity = parse_vm2_module(identity_path)
    require((parsed_identity.flags & VM2_ENCRYPTED_FLAG) == 0, "--no-encrypt-opcodes must clear VM2 encrypted flag")
    require(int.from_bytes(parsed_identity.code[:2], "little") == VM2_BLNK_OPCODE,
            "identity VM2 code stream must keep canonical first opcode")

    print("cryptor_vm2_equivalent OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
