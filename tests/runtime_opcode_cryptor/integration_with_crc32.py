#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys

from common import header_body_crc32_vm1, header_body_crc32_vm2, parse_vm1_module, parse_vm2_module, require, run_cmd, temp_path


def main() -> int:
    vm1_asm = pathlib.Path(sys.argv[1])
    vm2_asm = pathlib.Path(sys.argv[2])
    integrity_probe = pathlib.Path(sys.argv[3])
    vm1_fixture = pathlib.Path(sys.argv[4])
    vm2_fixture = pathlib.Path(sys.argv[5])

    vm1_module = temp_path("vm1_crc_opcode", ".vm1")
    vm2_module = temp_path("vm2_crc_opcode", ".vm2")

    run_cmd([vm1_asm, "--opcode-seed", "0102030405060708090a0b0c0d0e0f10", vm1_fixture, vm1_module])
    run_cmd([vm2_asm, "--opcode-seed", "102030405060708090a0b0c0d0e0f001", vm2_fixture, vm2_module])

    parsed_vm1 = parse_vm1_module(vm1_module)
    parsed_vm2 = parse_vm2_module(vm2_module)
    require(parsed_vm1.crc32 == header_body_crc32_vm1(parsed_vm1), "VM1 header CRC32 must cover encrypted raw payload")
    require(parsed_vm2.crc32 == header_body_crc32_vm2(parsed_vm2), "VM2 header CRC32 must cover encrypted raw payload")

    crc_only = run_cmd([vm1_asm, "--crc-only", vm1_module])
    require(crc_only.stdout.strip().lower() == f"0x{parsed_vm1.crc32:08x}", "VM1 --crc-only output must match header CRC32")

    run_cmd([integrity_probe, vm1_module])
    run_cmd([integrity_probe, vm2_module])

    print("integration_with_crc32 OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
