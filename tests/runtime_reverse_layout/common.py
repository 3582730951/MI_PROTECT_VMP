from __future__ import annotations

import os
import pathlib
import struct
import subprocess
import tempfile
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parents[2]

VM1_REVERSE_FLAG = 0x0002
VM2_REVERSE_FLAG = 0x0002
VM_ENCRYPTED_FLAG = 0x0001


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run_cmd(args: Iterable[os.PathLike[str] | str], *, env: dict[str, str] | None = None, expected: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    proc = subprocess.run([str(arg) for arg in args], text=True, capture_output=True, env=merged_env)
    if proc.returncode not in expected:
        raise RuntimeError(
            f"command failed rc={proc.returncode} expected={expected}: {' '.join(map(str, args))}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
    return proc


def temp_path(stem: str, suffix: str) -> pathlib.Path:
    fd, path = tempfile.mkstemp(prefix=f"{stem}_", suffix=suffix)
    os.close(fd)
    return pathlib.Path(path)


def parse_vm1(path: pathlib.Path) -> dict[str, int]:
    image = path.read_bytes()
    require(image[:4] == b"VM1B", "vm1 bad magic")
    version, flags = struct.unpack_from("<HH", image, 4)
    _, code_size, _, crc32 = struct.unpack_from("<IIII", image, 8)
    return {"version": version, "flags": flags, "code_size": code_size, "crc32": crc32}


def parse_vm2(path: pathlib.Path) -> dict[str, int]:
    image = path.read_bytes()
    require(image[:4] == b"VMP2", "vm2 bad magic")
    version, flags = struct.unpack_from("<HH", image, 4)
    _, code_size, _, crc32 = struct.unpack_from("<IIII", image, 8)
    return {"version": version, "flags": flags, "code_size": code_size, "crc32": crc32}


def expect_ret_int(proc: subprocess.CompletedProcess[str], value: int) -> None:
    require(f"ret_int={value}" in proc.stdout, f"expected ret_int={value}, got stdout={proc.stdout!r}")
