# STATUS

## 本轮清单
- 完成 `/workspace/vmp/` 仓库骨架与 plan §2 六层、§3 对外接口、§10 平台/架构分层的目录布局。
- 完成顶层 CMake 构建骨架，提供 `VMP_WITH_JIT`、`VMP_WITH_VM2`、`VMP_PLATFORM`、`VMP_ARCH` 选项。
- 完成 Cargo workspace 骨架，覆盖 `bindings/rust/` 与 `runtime/` 下 Rust crates。
- 完成 Android `build.gradle.kts` 占位与 iOS `Package.swift` 占位。
- 完成 `tools/` 空入口与 `tests/` dummy CTest。
- 完成每个目录 `README.md`，标注 plan 对应范围、状态与 TODO。

## 本轮产出文件清单（相对路径）
- `BUILD.md`
- `Cargo.lock`
- `Cargo.toml`
- `CMakeLists.txt`
- `README.md`
- `STATUS.md`
- `analyzer/CMakeLists.txt`
- `analyzer/README.md`
- `analyzer/include/vmp/analyzer/analyzer.h`
- `analyzer/src/analyzer.cpp`
- `arch/CMakeLists.txt`
- `arch/README.md`
- `arch/arm/CMakeLists.txt`
- `arch/arm/README.md`
- `arch/arm/include/vmp/arch/arm/arm.h`
- `arch/arm/src/arm.cpp`
- `arch/arm64/CMakeLists.txt`
- `arch/arm64/README.md`
- `arch/arm64/include/vmp/arch/arm64/arm64.h`
- `arch/arm64/src/arm64.cpp`
- `arch/x64/CMakeLists.txt`
- `arch/x64/README.md`
- `arch/x64/include/vmp/arch/x64/x64.h`
- `arch/x64/src/x64.cpp`
- `arch/x86/CMakeLists.txt`
- `arch/x86/README.md`
- `arch/x86/include/vmp/arch/x86/x86.h`
- `arch/x86/src/x86.cpp`
- `backends/CMakeLists.txt`
- `backends/README.md`
- `backends/llvm/CMakeLists.txt`
- `backends/llvm/README.md`
- `backends/llvm/include/vmp/backend/llvm_backend.h`
- `backends/llvm/src/llvm_backend.cpp`
- `backends/rewriter/CMakeLists.txt`
- `backends/rewriter/README.md`
- `backends/rewriter/include/vmp/backend/rewriter_backend.h`
- `backends/rewriter/src/rewriter_backend.cpp`
- `bindings/README.md`
- `bindings/cpp/CMakeLists.txt`
- `bindings/cpp/README.md`
- `bindings/cpp/include/vmp/bindings/cpp/plugin.h`
- `bindings/cpp/src/plugin.cpp`
- `bindings/rust/README.md`
- `bindings/rust/vmp-macros/Cargo.toml`
- `bindings/rust/vmp-macros/src/lib.rs`
- `cmake/vmp_placeholder.h.in`
- `docs/README.md`
- `loader/CMakeLists.txt`
- `loader/README.md`
- `loader/android/build.gradle.kts`
- `loader/android/CMakeLists.txt`
- `loader/android/README.md`
- `loader/android/include/vmp/loader/android/android_loader.h`
- `loader/android/src/android_loader.cpp`
- `loader/ios/CMakeLists.txt`
- `loader/ios/Package.swift`
- `loader/ios/README.md`
- `loader/ios/include/vmp/loader/ios/ios_loader.h`
- `loader/ios/src/ios_loader.cpp`
- `loader/linux/CMakeLists.txt`
- `loader/linux/README.md`
- `loader/linux/include/vmp/loader/linux/linux_loader.h`
- `loader/linux/src/linux_loader.cpp`
- `loader/windows/CMakeLists.txt`
- `loader/windows/README.md`
- `loader/windows/include/vmp/loader/windows/windows_loader.h`
- `loader/windows/src/windows_loader.cpp`
- `planner/CMakeLists.txt`
- `planner/README.md`
- `planner/include/vmp/planner/planner.h`
- `planner/src/planner.cpp`
- `policy/CMakeLists.txt`
- `policy/README.md`
- `policy/include/vmp/policy/policy_ir.h`
- `policy/src/policy_ir.cpp`
- `runtime/CMakeLists.txt`
- `runtime/README.md`
- `runtime/audit/CMakeLists.txt`
- `runtime/audit/README.md`
- `runtime/audit/include/vmp/runtime/audit/audit.h`
- `runtime/audit/rust_audit/Cargo.toml`
- `runtime/audit/rust_audit/src/lib.rs`
- `runtime/audit/src/audit.cpp`
- `runtime/integrity/CMakeLists.txt`
- `runtime/integrity/README.md`
- `runtime/integrity/include/vmp/runtime/integrity/integrity.h`
- `runtime/integrity/rust_integrity/Cargo.toml`
- `runtime/integrity/rust_integrity/src/lib.rs`
- `runtime/integrity/src/integrity.cpp`
- `runtime/jit/CMakeLists.txt`
- `runtime/jit/README.md`
- `runtime/jit/include/vmp/runtime/jit/jit.h`
- `runtime/jit/rust_jit/Cargo.toml`
- `runtime/jit/rust_jit/src/lib.rs`
- `runtime/jit/src/jit.cpp`
- `runtime/state/CMakeLists.txt`
- `runtime/state/README.md`
- `runtime/state/include/vmp/runtime/state/state.h`
- `runtime/state/rust_state/Cargo.toml`
- `runtime/state/rust_state/src/lib.rs`
- `runtime/state/src/state.cpp`
- `runtime/strings/CMakeLists.txt`
- `runtime/strings/README.md`
- `runtime/strings/include/vmp/runtime/strings/strings.h`
- `runtime/strings/rust_strings/Cargo.toml`
- `runtime/strings/rust_strings/src/lib.rs`
- `runtime/strings/src/strings.cpp`
- `runtime/vm1/CMakeLists.txt`
- `runtime/vm1/README.md`
- `runtime/vm1/include/vmp/runtime/vm1/vm1.h`
- `runtime/vm1/rust_vm1/Cargo.toml`
- `runtime/vm1/rust_vm1/src/lib.rs`
- `runtime/vm1/src/vm1.cpp`
- `runtime/vm2/CMakeLists.txt`
- `runtime/vm2/README.md`
- `runtime/vm2/include/vmp/runtime/vm2/vm2.h`
- `runtime/vm2/rust_vm2/Cargo.toml`
- `runtime/vm2/rust_vm2/src/lib.rs`
- `runtime/vm2/src/vm2.cpp`
- `tests/CMakeLists.txt`
- `tests/dummy_test.py`
- `tests/README.md`
- `tools/CMakeLists.txt`
- `tools/README.md`
- `tools/src/vmp_clang.cpp`
- `tools/src/vmp_clangxx.cpp`
- `tools/src/vmp_link.cpp`
- `tools/src/vmp_protect.cpp`

## 构建 / 验证命令与结果
1. 配置：
   ```bash
   cmake -S /workspace/vmp -B /workspace/vmp/build-linux-x64 -DVMP_PLATFORM=linux -DVMP_ARCH=x64
   ```
   结果：成功，生成目录 `/workspace/vmp/build-linux-x64`。

2. 构建：
   ```bash
   cmake --build /workspace/vmp/build-linux-x64 -j
   ```
   结果：成功，全部 placeholder target 构建完成。

3. 入口验证：
   ```bash
   /workspace/vmp/build-linux-x64/tools/vmp-protect
   ```
   实际输出：
   ```text
   NOT_IMPLEMENTED
   ```

4. CTest：
   ```bash
   ctest --test-dir /workspace/vmp/build-linux-x64 --output-on-failure
   ```
   结果：3/3 通过。

5. 附加验证（Cargo workspace）：
   ```bash
   cd /workspace/vmp && cargo check
   ```
   结果：成功。

## 遇到的依赖安装记录
- 执行：
  ```bash
  apt-get update
  apt-get install -y cmake build-essential ninja-build python3 cargo
  ```
- 结果：安装 `cmake`、`cmake-data`、`libarchive13`、`libjsoncpp25`、`librhash0`、`libuv1`、`ninja-build`；`build-essential`、`python3`、`cargo` 已存在。

## 已知未实现项清单
- `policy/`：Policy IR 具体字段、解析、校验、序列化未实现。
- `analyzer/`：源码级/二进制级分析逻辑未实现。
- `planner/`：Protection Plan 决策逻辑未实现。
- `backends/llvm/`：LLVM lifting / pass / 插桩未实现。
- `backends/rewriter/`：PE/ELF/Mach-O/APK/IPA 重写未实现。
- `runtime/vm1/`、`runtime/vm2/`：VM ISA、解释器、桥接 ABI 未实现。
- `runtime/jit/`：JIT 能力门控以外的实现未实现。
- `runtime/strings/`：字符串保护未实现。
- `runtime/integrity/`：完整性校验未实现。
- `runtime/state/`：运行时状态机/画像融合未实现。
- `runtime/audit/`：审计落盘与 `audit_then_delayed_exit` 协同未实现。
- `loader/*`：平台生命周期接入未实现。
- `arch/*`：各 ISA lifting / ABI 适配未实现。
- `tools/*`：参数解析与驱动逻辑未实现，统一打印 `NOT_IMPLEMENTED`。
- `bindings/rust/`：过程宏仅保留占位透传。
- `bindings/cpp/`：attribute plugin/front-end 集成未实现。
- Android / iOS 工程文件仅为占位接线，未接入真实 native 产物。

## 下一子任务建议
- 先补 `policy/`、`analyzer/`、`planner/` 三层的最小接口闭环：定义 `PolicyIR` / `ProgramIR` / `ProtectionPlan` 基础类型与最小序列化格式，使 `vmp-protect` 能读取外部策略文件并走通空规划流程。
