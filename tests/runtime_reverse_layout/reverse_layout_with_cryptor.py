from __future__ import annotations

from common import (
    ROOT,
    VM1_REVERSE_FLAG,
    VM2_REVERSE_FLAG,
    VM_ENCRYPTED_FLAG,
    expect_ret_int,
    parse_vm1,
    parse_vm2,
    require,
    run_cmd,
    temp_path,
)


def main() -> None:
    build = ROOT / "build"
    vm1_asm = build / "tools" / "vmp-vm1-asm"
    vm1_run = build / "tools" / "vmp-vm1-run"
    vm2_asm = build / "tools" / "vmp-vm2-asm"
    vm2_run = build / "tools" / "vmp-vm2-run"

    env = {"VMP_OPCODE_MAP_SEED": "00112233445566778899AABBCCDDEEFF"}

    vm1_module = temp_path("reverse_cryptor_vm1", ".vm1")
    run_cmd([vm1_asm, "--encrypt-opcodes", "--reverse-layout", ROOT / "tests" / "runtime_vm1" / "fixtures" / "fib20.vm1s", vm1_module], env=env)
    vm1_parsed = parse_vm1(vm1_module)
    require((vm1_parsed["flags"] & (VM_ENCRYPTED_FLAG | VM1_REVERSE_FLAG)) == (VM_ENCRYPTED_FLAG | VM1_REVERSE_FLAG),
            "vm1 flags should include reverse + encrypted")
    expect_ret_int(run_cmd([vm1_run, vm1_module, "20"]), 6765)

    vm2_module = temp_path("reverse_cryptor_vm2", ".vm2")
    run_cmd([vm2_asm, "--encrypt-opcodes", "--reverse-layout", ROOT / "tests" / "runtime_vm2" / "fixtures" / "fib20.vm2s", vm2_module], env=env)
    vm2_parsed = parse_vm2(vm2_module)
    require((vm2_parsed["flags"] & (VM_ENCRYPTED_FLAG | VM2_REVERSE_FLAG)) == (VM_ENCRYPTED_FLAG | VM2_REVERSE_FLAG),
            "vm2 flags should include reverse + encrypted")
    expect_ret_int(run_cmd([vm2_run, vm2_module, "20"]), 6765)

    print("reverse_layout_with_cryptor OK")


if __name__ == "__main__":
    main()
