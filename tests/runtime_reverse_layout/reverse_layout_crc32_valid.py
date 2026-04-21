from __future__ import annotations

from common import ROOT, VM1_REVERSE_FLAG, expect_ret_int, parse_vm1, require, run_cmd, temp_path


def main() -> None:
    build = ROOT / "build"
    asm = build / "tools" / "vmp-vm1-asm"
    run = build / "tools" / "vmp-vm1-run"
    fib = ROOT / "tests" / "runtime_vm1" / "fixtures" / "fib20.vm1s"
    module = temp_path("reverse_crc32", ".vm1")

    run_cmd([asm, "--no-encrypt-opcodes", "--reverse-layout", fib, module])
    parsed = parse_vm1(module)
    require((parsed["flags"] & VM1_REVERSE_FLAG) != 0, "reverse flag missing")
    crc_text = run_cmd([asm, "--crc-only", module]).stdout.strip()
    require(crc_text == f"0x{parsed['crc32']:08X}", f"crc mismatch header={parsed['crc32']:08X} tool={crc_text}")
    expect_ret_int(run_cmd([run, module, "20"]), 6765)
    print("reverse_layout_crc32_valid OK")


if __name__ == "__main__":
    main()
