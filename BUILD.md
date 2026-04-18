# Build Guide

This repository currently provides a **skeleton build system** only.

## Dependencies

### Common
- CMake >= 3.20
- C++17 compiler
- Python 3
- Ninja or Make (optional)

### Rust workspace placeholders
- Rust toolchain
- Cargo

### Android placeholder
- JDK 17+
- Android SDK / NDK
- Gradle
- CMake

### iOS placeholder
- Xcode / Apple toolchain
- Swift Package Manager
- CMake (for native core parts if used externally)

## Top-level CMake options
- `VMP_WITH_JIT=ON|OFF` (default: `ON`)
- `VMP_WITH_VM2=ON|OFF` (default: `ON`)
- `VMP_PLATFORM=linux|windows|macos|android|ios`
- `VMP_ARCH=x86|x64|arm|arm64`

## Linux example
```bash
cmake -S /workspace/vmp -B /workspace/vmp/build-linux-x64 -DVMP_PLATFORM=linux -DVMP_ARCH=x64
cmake --build /workspace/vmp/build-linux-x64 -j
ctest --test-dir /workspace/vmp/build-linux-x64 --output-on-failure
/workspace/vmp/build-linux-x64/tools/vmp-protect
```

## Windows example
```bash
cmake -S . -B build-windows-x64 -G Ninja -DVMP_PLATFORM=windows -DVMP_ARCH=x64
cmake --build build-windows-x64 -j
ctest --test-dir build-windows-x64 --output-on-failure
```

## macOS example
```bash
cmake -S . -B build-macos-arm64 -G Ninja -DVMP_PLATFORM=macos -DVMP_ARCH=arm64
cmake --build build-macos-arm64 -j
ctest --test-dir build-macos-arm64 --output-on-failure
```

## Android placeholder flow
```bash
cmake -S . -B build-android-arm64 -DVMP_PLATFORM=android -DVMP_ARCH=arm64
cmake --build build-android-arm64 -j
# loader/android/build.gradle.kts is a placeholder for Gradle-side integration.
```

## iOS placeholder flow
```bash
cmake -S . -B build-ios-arm64 -DVMP_PLATFORM=ios -DVMP_ARCH=arm64
cmake --build build-ios-arm64 -j
# loader/ios/Package.swift is a placeholder for SwiftPM-side integration.
```

## Policy CLI
```bash
/workspace/vmp/build-linux-x64/tools/vmp-protect --dump-schema
/workspace/vmp/build-linux-x64/tools/vmp-protect --policy /workspace/vmp/tests/policy/examples/good.json
/workspace/vmp/build-linux-x64/tools/vmp-protect --policy /workspace/vmp/tests/policy/examples/good.json --emit-policy-json /tmp/policy-roundtrip.json
/workspace/vmp/build-linux-x64/tools/vmp-protect --policy /workspace/vmp/tests/policy/examples/good.json --validate-only
```

## Notes
- `vmp-protect` now fully implements policy loading, strict JSON validation, schema dumping, and JSON round-trip emission.
- Other executable paths still print `NOT_IMPLEMENTED` until later subtasks land.
- Unsupported business logic is tracked in `STATUS.md`.
