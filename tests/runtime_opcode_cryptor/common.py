from __future__ import annotations

import binascii
import os
import pathlib
import random
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parents[2]

VM1_ENCRYPTED_FLAG = 0x0001
VM2_ENCRYPTED_FLAG = 0x0001
VM1_CALL_OPCODE = 0x0507
VM2_BLNK_OPCODE = 0x1503
VM1_VERSION_WITH_OPCODE_SEED = 4
VM2_VERSION_WITH_OPCODE_SEED = 4


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run_cmd(args: Iterable[str], *, env: dict[str, str] | None = None, expected=(0,), cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    proc = subprocess.run(list(map(str, args)), cwd=cwd, env=merged_env, text=True, capture_output=True)
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


def read_bytes(path: pathlib.Path) -> bytes:
    return path.read_bytes()


def write_bytes(path: pathlib.Path, data: bytes) -> None:
    path.write_bytes(data)


def seeded_hex_values(count: int) -> list[str]:
    rng = random.Random(0x23A9)
    return [rng.randbytes(16).hex() for _ in range(count)]


@dataclass
class Vm1Parsed:
    version: int
    flags: int
    entry_pc: int
    code_size: int
    const_count: int
    crc32: int
    seed: bytes
    code_offset: int
    body_end: int
    code: bytes
    image: bytes


@dataclass
class Vm2Parsed:
    version: int
    flags: int
    entry_pc: int
    code_size: int
    const_pool_size: int
    crc32: int
    seed: bytes
    code_offset: int
    body_end: int
    key_context_id: bytes
    code: bytes
    image: bytes



def parse_vm1_module(path: pathlib.Path) -> Vm1Parsed:
    image = read_bytes(path)
    require(image[:4] == b"VM1B", "vm1 bad magic")
    version, flags = struct.unpack_from("<HH", image, 4)
    entry_pc, code_size, const_count, crc32 = struct.unpack_from("<IIII", image, 8)
    if version == VM1_VERSION_WITH_OPCODE_SEED:
        seed = image[24:40]
        code_offset = 40
    else:
        seed = b""
        code_offset = 24
    cursor = code_offset + code_size
    for _ in range(const_count):
        require(cursor + 5 <= len(image), "vm1 truncated const entry")
        cursor += 1
        payload_size = struct.unpack_from("<I", image, cursor)[0]
        cursor += 4 + payload_size
    return Vm1Parsed(version, flags, entry_pc, code_size, const_count, crc32, seed, code_offset, cursor, image[code_offset:code_offset + code_size], image)



def parse_vm2_module(path: pathlib.Path) -> Vm2Parsed:
    image = read_bytes(path)
    require(image[:4] == b"VMP2", "vm2 bad magic")
    version, flags = struct.unpack_from("<HH", image, 4)
    entry_pc, code_size, const_pool_size, crc32 = struct.unpack_from("<IIII", image, 8)
    if version == VM2_VERSION_WITH_OPCODE_SEED:
        seed = image[24:40]
        code_offset = 40
    else:
        seed = b""
        code_offset = 24
    body_end = code_offset + code_size + const_pool_size
    key_context_id = image[body_end:body_end + 16]
    return Vm2Parsed(version, flags, entry_pc, code_size, const_pool_size, crc32, seed, code_offset, body_end, key_context_id, image[code_offset:code_offset + code_size], image)



def patch_seed(path: pathlib.Path, seed: bytes, *, vm: str) -> None:
    data = bytearray(read_bytes(path))
    require(len(seed) == 16, "patched seed must be 16 bytes")
    offset = 24
    if vm == "vm1":
        require(data[:4] == b"VM1B", "patch_seed expected vm1 image")
    elif vm == "vm2":
        require(data[:4] == b"VMP2", "patch_seed expected vm2 image")
    else:
        raise RuntimeError(f"unsupported vm kind: {vm}")
    data[offset:offset + 16] = seed
    write_bytes(path, bytes(data))



def header_body_crc32_vm1(parsed: Vm1Parsed) -> int:
    return binascii.crc32(parsed.image[parsed.code_offset:parsed.body_end]) & 0xFFFFFFFF



def header_body_crc32_vm2(parsed: Vm2Parsed) -> int:
    return binascii.crc32(parsed.image[parsed.code_offset:parsed.body_end]) & 0xFFFFFFFF
