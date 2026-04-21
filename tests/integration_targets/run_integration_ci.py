#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import shutil
import stat
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable

ROOT = pathlib.Path(__file__).resolve().parents[2]
TEST_ROOT = ROOT / 'tests' / 'integration_targets'
DEFAULT_BUILD_DIR = ROOT / 'build'
DEFAULT_REPORT_DIR = ROOT / 'reports'
ANDROID_NDK = pathlib.Path(os.environ.get('ANDROID_NDK_ROOT', '/opt/android/android-ndk-r26d'))
ANDROID_BIN = ANDROID_NDK / 'toolchains' / 'llvm' / 'prebuilt' / 'linux-x86_64' / 'bin'
ANDROID_CC = ANDROID_BIN / 'aarch64-linux-android21-clang'
ANDROID_CXX = ANDROID_BIN / 'aarch64-linux-android21-clang++'
ANDROID_AR = ANDROID_BIN / 'llvm-ar'
ANDROID_TLS_PATCH = TEST_ROOT / 'android_tls_align_fix.py'
RUSTUP_CARGO = pathlib.Path(os.environ.get('VMP_CARGO', pathlib.Path.home() / '.cargo' / 'bin' / 'cargo'))
RUSTUP_RUSTUP = pathlib.Path(os.environ.get('VMP_RUSTUP', pathlib.Path.home() / '.cargo' / 'bin' / 'rustup'))
MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class Case:
    platform: str
    test: str
    baseline_artifact: pathlib.Path
    protected_artifact: pathlib.Path
    baseline_cmd: list[str]
    protected_cmd: list[str]
    expected_output: str
    full_policy: pathlib.Path
    trampoline_policy: pathlib.Path
    source_policy: pathlib.Path
    raw_dir: pathlib.Path


def ensure_path(path: pathlib.Path) -> pathlib.Path:
    if not path.exists():
        raise SystemExit(f'required path not found: {path}')
    return path


def tool_from_path(path: pathlib.Path) -> str:
    ensure_path(path)
    return str(path)


def tool_or_die(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise SystemExit(f'required tool not found: {name}')
    return path


def run(cmd: list[str], *, cwd: pathlib.Path | None = None, env: dict[str, str] | None = None,
        log_path: pathlib.Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=merged_env,
        text=True,
        capture_output=True,
    )
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            f'$ {" ".join(cmd)}\n'
            f'[exit_code] {proc.returncode}\n\n'
            f'--- stdout ---\n{proc.stdout}\n'
            f'--- stderr ---\n{proc.stderr}\n'
        )
    if check and proc.returncode != 0:
        raise SystemExit(
            f'command failed ({proc.returncode}): {" ".join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
        )
    return proc


def chmod_x(path: pathlib.Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def write_json(path: pathlib.Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def policy_defaults(platform_caps: list[str]) -> dict[str, object]:
    return {
        'language_origin': 'binary',
        'annotation_origin': 'external_manifest',
        'protection_domain': 'native',
        'jit_policy': 'off',
        'plaintext_budget': 'transient_only',
        'reaction_policy': 'log',
        'integrity_level': 'basic',
        'platform_caps': platform_caps,
        'sensitivity_level': 'normal',
        'profile_seed': 1,
        'mobile_bridge_mode': 'off',
        'event_types': [],
    }


def make_entry(symbol: str, *, platform_caps: list[str], vm_func: bool = False, vm_string: bool = False) -> dict[str, object]:
    entry = dict(policy_defaults(platform_caps))
    entry['symbol_or_region'] = symbol
    entry['language_origin'] = 'binary'
    entry['annotation_origin'] = 'external_manifest'
    entry['annotation_tags'] = []
    if vm_func:
        entry['annotation_tags'].append('vm_func')
        entry['protection_domain'] = 'vm1'
    if vm_string:
        entry['annotation_tags'].append('vm_string')
        entry['sensitivity_level'] = 'highly_sensitive'
        entry['plaintext_budget'] = 'transient_only'
    return entry


def write_policy(path: pathlib.Path, platform_caps: list[str], entries: list[dict[str, object]]) -> None:
    write_json(path, {
        'schema_version': 1,
        'defaults': policy_defaults(platform_caps),
        'entries': entries,
    })


def rotl64(value: int, bits: int) -> int:
    bits &= 63
    if bits == 0:
        return value & MASK64
    return ((value << bits) | (value >> (64 - bits))) & MASK64


def fib40() -> int:
    a, b = 0, 1
    for _ in range(40):
        a, b = b, a + b
    return a


def fib20_recursive(n: int) -> int:
    if n < 2:
        return n
    return fib20_recursive(n - 1) + fib20_recursive(n - 2)


def expected_target_c(iterations: int) -> str:
    secret = b'c-target::runtime::delta-42'
    checksum = 0x123456789ABCDEF0
    fib = fib40()
    for i in range(iterations):
        block_len = 24 + (i & 7)
        block = [((i * 3) + (j * 7) + secret[j % len(secret)]) & 0xFF for j in range(block_len)]
        local = sum(block)
        checksum ^= ((fib + local + i) * 0x9E3779B185EBCA87) & MASK64
        checksum = rotl64(checksum, (i % 13) + 1)
        mix = (local + fib) ^ (((len(secret) + i) * 0x9E3779B97F4A7C15) & MASK64)
        mix = rotl64(mix & MASK64, 7)
        mix ^= ((local + fib + 0x51ED2705) ^ ((len(secret) + i) << 11)) & MASK64
        mix = (mix + 0xA24BAED4963EE407) & MASK64
        checksum = (checksum + mix) & MASK64
        checksum ^= (block[i % block_len] & 0xFF) << ((i % 8) * 8)
        checksum &= MASK64
    return f'target_c fib40={fib} checksum={checksum} secret_len={len(secret)}'



def expected_target_cpp(iterations: int) -> str:
    secret = 'cpp-target::runtime::omega-17'
    checksum = 0xCAFEBABE12345678
    fib = fib40()
    for i in range(iterations):
        values = [
            (ord(secret[0]) + i) % 97,
            (ord(secret[1]) + i * 2) % 97,
            (ord(secret[2]) + i * 3) % 97,
            (ord(secret[3]) + i * 4) % 97,
        ]
        values.sort()
        start = i % 3
        joined = secret[start:start + 3]
        if len(joined) < 2:
            checksum ^= 0xDEADBEEFCAFEF00D
            checksum &= MASK64
            continue
        mix = ((fib + len(joined) + 0x6A09E667F3BCC909) & MASK64) ^ (((values[-1] + i) * 0x100000001B3) & MASK64)
        mix = rotl64(mix, 9)
        mix ^= (((fib + len(joined)) << 5) ^ ((values[-1] + i) << 17)) & MASK64
        checksum ^= mix & MASK64
        checksum = rotl64(checksum, (i % 7) + 1)
        checksum = (checksum + ord(joined[0]) + values[0] + values[-1]) & MASK64
    return f'target_cpp fib40={fib} checksum={checksum} secret_len={len(secret)}'


def expected_target_rust(iterations: int) -> str:
    secret = 'rust-target::runtime::sigma'
    checksum = 0x0DDC0FFEEEC0FFEE
    fib = fib20_recursive(20)
    for i in range(iterations):
        values = [(((ord(byte) if isinstance(byte, str) else byte) + idx * 9 + i) % 97) + 1 for idx, byte in enumerate(secret.encode()[:8])]
        values.append((fib + i) % 97 + 1)
        values.sort()
        local = sum(values)
        mix = ((local + fib) * 0x9E3779B185EBCA87) & MASK64
        mix ^= ((values[-1] + i) * 0xC2B2AE3D27D4EB4F) & MASK64
        mix = rotl64(mix, 13)
        mix ^= ((local + fib) + ((values[-1] + i) << 7)) & MASK64
        checksum ^= mix & MASK64
        checksum = rotl64(checksum, (i % 17) + 1)
        checksum = (checksum + values[0] + len(values)) & MASK64
    return f'target_rust fib20={fib} checksum={checksum} secret_len={len(secret)}'




def ensure_bcryptprimitives_stub() -> pathlib.Path:
    cache_dir = pathlib.Path('/tmp/vmp_windows_api_stubs')
    cache_dir.mkdir(parents=True, exist_ok=True)
    dll = cache_dir / 'bcryptprimitives.dll'
    if dll.exists():
        return dll
    src = TEST_ROOT / 'bcryptprimitives_stub.c'
    run([tool_or_die('x86_64-w64-mingw32-gcc'), '-shared', '-O2', '-o', str(dll), str(src)])
    return dll

def ensure_api_ms_synch_stub() -> pathlib.Path:
    cache_dir = pathlib.Path('/tmp/vmp_windows_api_stubs')
    cache_dir.mkdir(parents=True, exist_ok=True)
    dll = cache_dir / 'api-ms-win-core-synch-l1-2-0.dll'
    if dll.exists():
        return dll
    src = TEST_ROOT / 'api_ms_win_core_synch_stub.c'
    run([tool_or_die('x86_64-w64-mingw32-gcc'), '-shared', '-O2', '-o', str(dll), str(src)])
    return dll

def bundle_windows_runtime(binary: pathlib.Path) -> None:
    extra = [ensure_api_ms_synch_stub(), ensure_bcryptprimitives_stub()]
    for dll_name in ('libwinpthread-1.dll', 'libstdc++-6.dll', 'libgcc_s_seh-1.dll', 'libssp-0.dll'):
        probe = subprocess.run([tool_or_die('x86_64-w64-mingw32-gcc'), f'-print-file-name={dll_name}'], text=True, capture_output=True)
        candidate = pathlib.Path(probe.stdout.strip())
        if candidate.exists():
            shutil.copy2(candidate, binary.parent / dll_name)
    for candidate in extra:
        if candidate.exists():
            shutil.copy2(candidate, binary.parent / candidate.name)

def compile_windows_c(source: pathlib.Path, output: pathlib.Path, include_dir: pathlib.Path, log: pathlib.Path) -> None:
    run([
        tool_or_die('x86_64-w64-mingw32-gcc'), '-O2',
        '-I', str(include_dir), '-Wno-attributes', '-static', '-o', str(output), str(source)
    ], log_path=log)
    bundle_windows_runtime(output)


def compile_windows_cpp(source: pathlib.Path, output: pathlib.Path, include_dir: pathlib.Path, log: pathlib.Path) -> None:
    run([
        tool_or_die('x86_64-w64-mingw32-g++'), '-std=c++17', '-O0',
        '-I', str(include_dir), '-Wno-attributes', '-o', str(output), str(source)
    ], log_path=log)
    bundle_windows_runtime(output)


def compile_android_c(source: pathlib.Path, output: pathlib.Path, include_dir: pathlib.Path, log: pathlib.Path) -> None:
    run([
        tool_from_path(ANDROID_CC), '-O2', '-static', '-I', str(include_dir), '-Wno-ignored-attributes',
        '-o', str(output), str(source)
    ], log_path=log)
    run([tool_or_die('python3'), str(ANDROID_TLS_PATCH), str(output)], log_path=log.with_name(log.stem + '.tls.log'))
    chmod_x(output)


def compile_android_cpp(source: pathlib.Path, output: pathlib.Path, include_dir: pathlib.Path, log: pathlib.Path) -> None:
    run([
        tool_from_path(ANDROID_CXX), '-std=c++17', '-O2', '-static', '-static-libstdc++',
        '-I', str(include_dir), '-Wno-ignored-attributes', '-o', str(output), str(source)
    ], log_path=log)
    run([tool_or_die('python3'), str(ANDROID_TLS_PATCH), str(output)], log_path=log.with_name(log.stem + '.tls.log'))
    chmod_x(output)


def build_rust(crate_dir: pathlib.Path, target: str, output_dir: pathlib.Path, log: pathlib.Path) -> pathlib.Path:
    env = {
        'PATH': f'{pathlib.Path.home() / ".cargo" / "bin"}{os.pathsep}{os.environ.get("PATH", "")}',
        'CARGO_TARGET_DIR': str(output_dir),
    }
    cargo_cmd = [tool_from_path(RUSTUP_CARGO)]
    if target == 'x86_64-pc-windows-gnu':
        env['CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER'] = tool_or_die('x86_64-w64-mingw32-gcc')
        env['RUSTFLAGS'] = '-C target-feature=+crt-static'
    elif target == 'aarch64-linux-android':
        android_rust_cc = tool_from_path(ANDROID_BIN / 'aarch64-linux-android34-clang')
        env['CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER'] = android_rust_cc
        env['AR_aarch64_linux_android'] = tool_from_path(ANDROID_AR)
        env['CC_aarch64_linux_android'] = android_rust_cc
        env['RUSTFLAGS'] = ' '.join([
            '-C panic=abort',
            '-C relocation-model=static',
            '-C link-arg=-static',
            '-C link-arg=-nostdlib',
            '-C link-arg=-nostartfiles',
            '-C link-arg=-Wl,-e,_start',
            '-C link-arg=-Wl,--build-id=none',
        ])
    else:
        raise SystemExit(f'unsupported rust target: {target}')

    run(cargo_cmd + [
        'build', '--manifest-path', str(crate_dir / 'Cargo.toml'), '--release', '--target', target
    ], cwd=ROOT, env=env, log_path=log)

    name = 'integration-rust-target.exe' if target.endswith('windows-gnu') else 'integration-rust-target'
    output = output_dir / target / 'release' / name
    ensure_path(output)
    if target == 'aarch64-linux-android':
        run([tool_or_die('python3'), str(ANDROID_TLS_PATCH), str(output)], log_path=log.with_name(log.stem + '.tls.log'))
        chmod_x(output)
    elif target == 'x86_64-pc-windows-gnu':
        bundle_windows_runtime(output)
    return output


def collect_cpp_source_policy(source: pathlib.Path, out: pathlib.Path, build_dir: pathlib.Path, log: pathlib.Path) -> None:
    scanner = build_dir / 'tools' / 'vmp-cpp-fallback-scan'
    run([str(scanner), str(source), f'--policy-out={out}'], log_path=log)


def collect_rust_source_policy(crate_dir: pathlib.Path, target_dir: pathlib.Path, out: pathlib.Path, build_dir: pathlib.Path,
                               log: pathlib.Path, platform_caps: list[str]) -> None:
    base = out.with_name(out.stem + '.base.json')
    write_policy(base, platform_caps, [])
    run([
        str(build_dir / 'tools' / 'vmp-protect'), '--policy', str(base), '--rust-target-dir', str(target_dir),
        '--emit-policy-json', str(out), '--validate-only'
    ], log_path=log)


def protect_windows(build_dir: pathlib.Path, baseline: pathlib.Path, full_policy: pathlib.Path, protected: pathlib.Path,
                    raw_dir: pathlib.Path) -> None:
    stage1 = protected.with_name(protected.stem + '.stage1' + protected.suffix)
    run([
        str(build_dir / 'tools' / 'vmp-protect'), '--policy', str(full_policy), '--input', str(baseline), '--output', str(stage1)
    ], log_path=raw_dir / 'protect.log')
    run([
        str(build_dir / 'tools' / 'vmp-trampoline-inject'), '--policy', str(full_policy), '--input', str(stage1), '--output', str(protected)
    ], log_path=raw_dir / 'trampoline.log')
    bundle_windows_runtime(protected)


def protect_android(build_dir: pathlib.Path, baseline: pathlib.Path, full_policy: pathlib.Path, trampoline_policy: pathlib.Path,
                    protected: pathlib.Path, raw_dir: pathlib.Path) -> None:
    stage1 = protected.with_name(protected.stem + '.tramp')
    string_pool = raw_dir / 'string_pool.bin'
    string_idx = raw_dir / 'string_pool.idx.json'
    string_kdf = raw_dir / 'string_pool.kdf.json'
    run([
        str(build_dir / 'tools' / 'vmp-trampoline-inject'), '--policy', str(trampoline_policy), '--input', str(baseline), '--output', str(stage1)
    ], log_path=raw_dir / 'trampoline.log')
    chmod_x(stage1)
    run([
        str(build_dir / 'tools' / 'vmp-protect'), '--policy', str(full_policy), '--input', str(stage1), '--output', str(protected),
        '--strings-pool', str(string_pool), '--strings-idx', str(string_idx), '--string-kdf', str(string_kdf)
    ], log_path=raw_dir / 'protect.log')
    chmod_x(protected)
    run([tool_or_die('python3'), str(ANDROID_TLS_PATCH), str(protected)], log_path=raw_dir / 'protected.tls.log')


def execute_case(case: Case, *, stderr_suppression: Callable[[str], str] | None = None) -> dict[str, object]:
    def run_one(cmd: list[str], log_name: str) -> tuple[str, float, int, str]:
        run_cmd = list(cmd)
        run_env = os.environ.copy()
        if run_cmd and 'wine' in str(run_cmd[0]).lower():
            run_env['WINEDEBUG'] = '-all'
            exe_path = pathlib.Path(run_cmd[1]).resolve()
            stage_dir = pathlib.Path('/tmp/vmp_wine_stage') / case.platform / case.test / log_name.replace('.run.log', '')
            if stage_dir.exists():
                shutil.rmtree(stage_dir)
            stage_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(exe_path, stage_dir / exe_path.name)
            for dll in exe_path.parent.glob('*.dll'):
                shutil.copy2(dll, stage_dir / dll.name)
            run_cmd = [run_cmd[0], str(stage_dir / exe_path.name), *run_cmd[2:]]
        started = time.perf_counter_ns()
        proc = subprocess.run(run_cmd, text=True, capture_output=True, env=run_env)
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
        stderr_text = proc.stderr
        if stderr_suppression:
            stderr_text = stderr_suppression(stderr_text)
        (case.raw_dir / log_name).write_text(
            f'$ {" ".join(run_cmd)}\n'
            f'[exit_code] {proc.returncode}\n'
            f'[elapsed_ms] {elapsed_ms:.3f}\n\n'
            f'--- stdout ---\n{proc.stdout}\n'
            f'--- stderr ---\n{stderr_text}\n'
        )
        stdout_clean = proc.stdout.strip().replace('\r\n', '\n').replace('\r', '')
        return stdout_clean, elapsed_ms, proc.returncode, stderr_text

    baseline_out, baseline_ms, baseline_rc, baseline_stderr = run_one(case.baseline_cmd, 'baseline.run.log')
    protected_out, protected_ms, protected_rc, protected_stderr = run_one(case.protected_cmd, 'protected.run.log')
    baseline_correct = baseline_rc == 0 and baseline_out == case.expected_output
    protected_correct = protected_rc == 0 and protected_out == case.expected_output

    if baseline_correct and not protected_correct:
        message = (
            f'{case.platform}/{case.test} baseline ok but protected mismatch '
            f'(expected={case.expected_output!r} got={protected_out!r} rc={protected_rc})'
        )
        print(f'REGRESSION: {message}', flush=True)
        raise SystemExit(1)

    if not baseline_correct:
        raise SystemExit(
            f'baseline failed for {case.platform}/{case.test}: expected {case.expected_output!r}, '
            f'got {baseline_out!r}, rc={baseline_rc}, stderr={baseline_stderr[:400]}'
        )

    ratio = round((protected_ms / baseline_ms) if baseline_ms > 0 else float('inf'), 4)
    return {
        'target': case.platform,
        'test': case.test,
        'baseline_ms': round(baseline_ms, 3),
        'protected_ms': round(protected_ms, 3),
        'overhead_ratio': ratio,
        'baseline_correct': baseline_correct,
        'protected_correct': protected_correct,
        'expected_output': case.expected_output,
        'baseline_output': baseline_out,
        'protected_output': protected_out,
        'baseline_artifact': str(case.baseline_artifact),
        'protected_artifact': str(case.protected_artifact),
        'full_policy': str(case.full_policy),
        'trampoline_policy': str(case.trampoline_policy),
        'source_policy': str(case.source_policy),
    }


def write_performance_markdown(path: pathlib.Path, results: list[dict[str, object]]) -> None:
    lines = [
        '| target | test | baseline_ms | protected_ms | overhead_ratio | baseline_correct | protected_correct |',
        '| --- | --- | ---: | ---: | ---: | --- | --- |',
    ]
    for item in results:
        lines.append(
            f"| {item['target']} | {item['test']} | {item['baseline_ms']:.3f} | {item['protected_ms']:.3f} | {item['overhead_ratio']:.4f} | {item['baseline_correct']} | {item['protected_correct']} |"
        )
    path.write_text('\n'.join(lines) + '\n')


def build_cases(build_dir: pathlib.Path, artifact_root: pathlib.Path, wanted_platforms: set[str] | None = None) -> list[Case]:
    include_dir = ROOT / 'bindings' / 'cpp' / 'include'
    results: list[Case] = []
    windows_caps = ['windows', 'x64']
    android_caps = ['android', 'arm64']
    rust_target_dir = artifact_root / 'rust-target-build'

    def wants(name: str) -> bool:
        return wanted_platforms is None or name in wanted_platforms

    if wants('x86_64-windows'):
        # Windows C
        base_dir = artifact_root / 'x86_64-windows' / 'target_c'
        base_dir.mkdir(parents=True, exist_ok=True)
        baseline = base_dir / 'target_c.exe'
        protected = base_dir / 'target_c.protected.exe'
        compile_windows_c(TEST_ROOT / 'target_c.c', baseline, include_dir, base_dir / 'compile.log')
        bundle_windows_runtime(baseline)
        collect_cpp_source_policy(TEST_ROOT / 'target_c.c', base_dir / 'source_policy.json', build_dir, base_dir / 'source_policy.log')
        full_policy = base_dir / 'binary_full_policy.json'
        empty_policy = base_dir / 'binary_empty_policy.json'
        write_policy(full_policy, windows_caps, [
            make_entry('protected_mix_c', platform_caps=windows_caps, vm_func=True),
            make_entry('kProtectedCString', platform_caps=windows_caps, vm_string=True),
        ])
        write_policy(empty_policy, windows_caps, [])
        protect_windows(build_dir, baseline, full_policy, protected, base_dir)
        results.append(Case(
            platform='x86_64-windows',
            test='target_c',
            baseline_artifact=baseline,
            protected_artifact=protected,
            baseline_cmd=[tool_or_die('wine'), str(baseline), '1000'],
            protected_cmd=[tool_or_die('wine'), str(protected), '1000'],
            expected_output=expected_target_c(1000),
            full_policy=full_policy,
            trampoline_policy=empty_policy,
            source_policy=base_dir / 'source_policy.json',
            raw_dir=base_dir,
        ))

        # Windows C++
        base_dir = artifact_root / 'x86_64-windows' / 'target_cpp'
        base_dir.mkdir(parents=True, exist_ok=True)
        baseline = base_dir / 'target_cpp.exe'
        protected = base_dir / 'target_cpp.protected.exe'
        compile_windows_cpp(TEST_ROOT / 'target_cpp.cpp', baseline, include_dir, base_dir / 'compile.log')
        bundle_windows_runtime(baseline)
        collect_cpp_source_policy(TEST_ROOT / 'target_cpp.cpp', base_dir / 'source_policy.json', build_dir, base_dir / 'source_policy.log')
        full_policy = base_dir / 'binary_full_policy.json'
        empty_policy = base_dir / 'binary_empty_policy.json'
        write_policy(full_policy, windows_caps, [
            make_entry('protected_mix_cpp', platform_caps=windows_caps, vm_func=True),
            make_entry('kProtectedCppString', platform_caps=windows_caps, vm_string=True),
        ])
        write_policy(empty_policy, windows_caps, [])
        protect_windows(build_dir, baseline, full_policy, protected, base_dir)
        results.append(Case(
            platform='x86_64-windows',
            test='target_cpp',
            baseline_artifact=baseline,
            protected_artifact=protected,
            baseline_cmd=[tool_or_die('wine'), str(baseline), '1000'],
            protected_cmd=[tool_or_die('wine'), str(protected), '1000'],
            expected_output=expected_target_cpp(1000),
            full_policy=full_policy,
            trampoline_policy=empty_policy,
            source_policy=base_dir / 'source_policy.json',
            raw_dir=base_dir,
        ))

        # Windows Rust
        base_dir = artifact_root / 'x86_64-windows' / 'target_rust'
        base_dir.mkdir(parents=True, exist_ok=True)
        baseline = build_rust(TEST_ROOT / 'rust_target', 'x86_64-pc-windows-gnu', rust_target_dir, base_dir / 'compile.log')
        bundle_windows_runtime(baseline)
        baseline_copy = base_dir / 'target_rust.exe'
        shutil.copy2(baseline, baseline_copy)
        bundle_windows_runtime(baseline_copy)
        collect_rust_source_policy(TEST_ROOT / 'rust_target', rust_target_dir, base_dir / 'source_policy.json', build_dir,
                                   base_dir / 'source_policy.log', windows_caps)
        full_policy = base_dir / 'binary_full_policy.json'
        empty_policy = base_dir / 'binary_empty_policy.json'
        protected = base_dir / 'target_rust.protected.exe'
        write_policy(full_policy, windows_caps, [
            make_entry('protected_mix_rust', platform_caps=windows_caps, vm_func=True),
            make_entry('RUST_SECRET_BYTES', platform_caps=windows_caps, vm_string=True),
        ])
        write_policy(empty_policy, windows_caps, [])
        protect_windows(build_dir, baseline_copy, full_policy, protected, base_dir)
        results.append(Case(
            platform='x86_64-windows',
            test='target_rust',
            baseline_artifact=baseline_copy,
            protected_artifact=protected,
            baseline_cmd=[tool_or_die('wine'), str(baseline_copy), '1000'],
            protected_cmd=[tool_or_die('wine'), str(protected), '1000'],
            expected_output=expected_target_rust(1000),
            full_policy=full_policy,
            trampoline_policy=empty_policy,
            source_policy=base_dir / 'source_policy.json',
            raw_dir=base_dir,
        ))

    if wants('aarch64-android'):
        # Android C
        base_dir = artifact_root / 'aarch64-android' / 'target_c'
        base_dir.mkdir(parents=True, exist_ok=True)
        baseline = base_dir / 'target_c'
        protected = base_dir / 'target_c.protected'
        compile_android_c(TEST_ROOT / 'target_c.c', baseline, include_dir, base_dir / 'compile.log')
        collect_cpp_source_policy(TEST_ROOT / 'target_c.c', base_dir / 'source_policy.json', build_dir, base_dir / 'source_policy.log')
        full_policy = base_dir / 'binary_full_policy.json'
        empty_policy = base_dir / 'binary_empty_policy.json'
        write_policy(full_policy, android_caps, [
            make_entry('protected_mix_c', platform_caps=android_caps, vm_func=True),
            make_entry('kProtectedCString', platform_caps=android_caps, vm_string=True),
        ])
        write_policy(empty_policy, android_caps, [])
        protect_android(build_dir, baseline, full_policy, empty_policy, protected, base_dir)
        results.append(Case(
            platform='aarch64-android',
            test='target_c',
            baseline_artifact=baseline,
            protected_artifact=protected,
            baseline_cmd=[tool_or_die('qemu-aarch64-static'), str(baseline), '1000'],
            protected_cmd=[tool_or_die('qemu-aarch64-static'), str(protected), '1000'],
            expected_output=expected_target_c(1000),
            full_policy=full_policy,
            trampoline_policy=empty_policy,
            source_policy=base_dir / 'source_policy.json',
            raw_dir=base_dir,
        ))

        # Android C++
        base_dir = artifact_root / 'aarch64-android' / 'target_cpp'
        base_dir.mkdir(parents=True, exist_ok=True)
        baseline = base_dir / 'target_cpp'
        protected = base_dir / 'target_cpp.protected'
        compile_android_cpp(TEST_ROOT / 'target_cpp.cpp', baseline, include_dir, base_dir / 'compile.log')
        collect_cpp_source_policy(TEST_ROOT / 'target_cpp.cpp', base_dir / 'source_policy.json', build_dir, base_dir / 'source_policy.log')
        full_policy = base_dir / 'binary_full_policy.json'
        empty_policy = base_dir / 'binary_empty_policy.json'
        write_policy(full_policy, android_caps, [
            make_entry('protected_mix_cpp', platform_caps=android_caps, vm_func=True),
            make_entry('kProtectedCppString', platform_caps=android_caps, vm_string=True),
        ])
        write_policy(empty_policy, android_caps, [])
        protect_android(build_dir, baseline, full_policy, empty_policy, protected, base_dir)
        results.append(Case(
            platform='aarch64-android',
            test='target_cpp',
            baseline_artifact=baseline,
            protected_artifact=protected,
            baseline_cmd=[tool_or_die('qemu-aarch64-static'), str(baseline), '1000'],
            protected_cmd=[tool_or_die('qemu-aarch64-static'), str(protected), '1000'],
            expected_output=expected_target_cpp(1000),
            full_policy=full_policy,
            trampoline_policy=empty_policy,
            source_policy=base_dir / 'source_policy.json',
            raw_dir=base_dir,
        ))

        # Android Rust
        base_dir = artifact_root / 'aarch64-android' / 'target_rust'
        base_dir.mkdir(parents=True, exist_ok=True)
        baseline = build_rust(TEST_ROOT / 'rust_target', 'aarch64-linux-android', rust_target_dir, base_dir / 'compile.log')
        baseline_copy = base_dir / 'target_rust'
        shutil.copy2(baseline, baseline_copy)
        chmod_x(baseline_copy)
        run([tool_or_die('python3'), str(ANDROID_TLS_PATCH), str(baseline_copy)], log_path=base_dir / 'baseline.tls.log')
        collect_rust_source_policy(TEST_ROOT / 'rust_target', rust_target_dir, base_dir / 'source_policy.json', build_dir,
                                   base_dir / 'source_policy.log', android_caps)
        full_policy = base_dir / 'binary_full_policy.json'
        empty_policy = base_dir / 'binary_empty_policy.json'
        protected = base_dir / 'target_rust.protected'
        write_policy(full_policy, android_caps, [
            make_entry('RUST_SECRET_BYTES', platform_caps=android_caps, vm_string=True),
        ])
        write_policy(empty_policy, android_caps, [])
        protect_android(build_dir, baseline_copy, full_policy, empty_policy, protected, base_dir)
        results.append(Case(
            platform='aarch64-android',
            test='target_rust',
            baseline_artifact=baseline_copy,
            protected_artifact=protected,
            baseline_cmd=[tool_or_die('qemu-aarch64-static'), str(baseline_copy), '1000'],
            protected_cmd=[tool_or_die('qemu-aarch64-static'), str(protected), '1000'],
            expected_output=expected_target_rust(1000),
            full_policy=full_policy,
            trampoline_policy=empty_policy,
            source_policy=base_dir / 'source_policy.json',
            raw_dir=base_dir,
        ))

    return results


def wine_stderr_filter(stderr_text: str) -> str:
    lines = []
    for line in stderr_text.splitlines():
        if 'it looks like wine32 is missing' in line:
            continue
        if 'multiarch needs to be enabled first' in line:
            continue
        if 'execute "dpkg --add-architecture i386' in line:
            continue
        if 'nodrv_CreateWindow' in line or 'systray' in line or 'wine: configuration in' in line:
            continue
        lines.append(line)
    return '\n'.join(lines).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default=str(DEFAULT_BUILD_DIR))
    parser.add_argument('--report-dir', default=str(DEFAULT_REPORT_DIR))
    parser.add_argument('--date', default=time.strftime('%Y%m%d', time.gmtime()))
    parser.add_argument('--platform-filter', action='append', default=[], help='limit execution to one or more matrix targets')
    args = parser.parse_args()

    build_dir = pathlib.Path(args.build_dir).resolve()
    report_dir = pathlib.Path(args.report_dir).resolve()
    ensure_path(build_dir / 'tools' / 'vmp-protect')
    ensure_path(build_dir / 'tools' / 'vmp-trampoline-inject')
    ensure_path(RUSTUP_CARGO)
    ensure_path(RUSTUP_RUSTUP)

    artifact_root = report_dir / f'integration_artifacts_{args.date}'
    if artifact_root.exists():
        shutil.rmtree(artifact_root)
    artifact_root.mkdir(parents=True)

    wanted = set(args.platform_filter) if args.platform_filter else None
    if wanted is None or 'aarch64-android' in wanted:
        ensure_path(ANDROID_CC)
        ensure_path(ANDROID_CXX)
    cases = build_cases(build_dir, artifact_root, wanted)
    results: list[dict[str, object]] = []
    for case in cases:
        suppress = wine_stderr_filter if case.platform == 'x86_64-windows' else None
        results.append(execute_case(case, stderr_suppression=suppress))

    performance_json = report_dir / f'performance_{args.date}.json'
    performance_md = report_dir / f'performance_{args.date}.md'
    write_json(performance_json, {
        'generated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'results': results,
    })
    write_performance_markdown(performance_md, results)
    print(f'performance_json={performance_json}')
    print(f'performance_md={performance_md}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
