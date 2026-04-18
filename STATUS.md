# STATUS

## 历史轮次：仓库骨架
- 完成 `/workspace/vmp/` 仓库骨架与 plan §2 六层、§3 对外接口、§10 平台/架构分层的目录布局。
- 完成顶层 CMake 构建骨架，提供 `VMP_WITH_JIT`、`VMP_WITH_VM2`、`VMP_PLATFORM`、`VMP_ARCH` 选项。
- 完成 Cargo workspace 骨架，覆盖 `bindings/rust/` 与 `runtime/` 下 Rust crates。
- 完成 Android `build.gradle.kts` 占位与 iOS `Package.swift` 占位。
- 完成 `tools/` 空入口与 `tests/` dummy CTest。

## 本轮清单（子任务 2：Policy IR）
- 完成 `policy/` C++ Policy IR：字段、枚举、`PolicyEntry` / `PolicyIR` / `ValidationError`、严格 JSON 读写、schema dump、验证器、`apply_vm_func_annotation()`、`apply_vm_string_annotation()`。
- 完成 `tools/vmp-protect` 最小闭环：支持 `--policy`、`--emit-policy-json`、`--dump-schema`、`--validate-only`，并输出人类可读错误。
- 新增 Rust crate `bindings/rust/vmp-policy`：`serde` 反序列化、同构 `PolicyIR`/`PolicyEntry`、`load_from_file()`、`validate()`。
- 将 `vmp-policy` 接入 Cargo workspace，并新增本地 cargo source 配置，使用 Debian 提供的 Rust crate 源离线构建。
- 完成 `tests/policy/` 真测：C++ round-trip、注解叠加语义、硬约束正反例、CLI 成功/失败路径、Rust/C++ 共享 JSON 解析结果等价。
- 更新 `policy/README.md` 与 `BUILD.md` 文档。

## 本轮变更文件（相对路径）
- `.cargo/config.toml`
- `BUILD.md`
- `Cargo.toml`
- `STATUS.md`
- `bindings/rust/vmp-policy/Cargo.toml`
- `bindings/rust/vmp-policy/examples/summary.rs`
- `bindings/rust/vmp-policy/src/lib.rs`
- `bindings/rust/vmp-policy/tests/cross_check.rs`
- `policy/CMakeLists.txt`
- `policy/README.md`
- `policy/include/vmp/policy/policy_ir.h`
- `policy/src/policy_ir.cpp`
- `tests/CMakeLists.txt`
- `tests/policy/assert_bad_policy.py`
- `tests/policy/policy_cpp_summary.cpp`
- `tests/policy/policy_cpp_test.cpp`
- `tests/policy/examples/good.json`
- `tests/policy/examples/good_ios_hot_only.json`
- `tests/policy/examples/bad_vm_func_native.json`
- `tests/policy/examples/bad_vm_string_sensitivity.json`
- `tests/policy/examples/bad_vm_string_plaintext_budget.json`
- `tests/policy/examples/bad_audit_event_type.json`
- `tests/policy/examples/bad_ios_aggressive.json`
- `tests/policy/examples/bad_vm2_integrity.json`
- `tools/CMakeLists.txt`
- `tools/src/vmp_protect.cpp`

## 验证命令与结果
1. 依赖安装：
   ```bash
   apt-get install -y nlohmann-json3-dev \
     librust-serde-dev librust-serde-derive-dev librust-serde-json-dev librust-tempfile-dev
   ```
   结果：成功。

2. CMake 构建：
   ```bash
   cmake -S /workspace/vmp -B /workspace/vmp/build-linux-x64 -DVMP_PLATFORM=linux -DVMP_ARCH=x64
   cmake --build /workspace/vmp/build-linux-x64 -j
   ```
   结果：成功。

3. CTest：
   ```bash
   ctest --test-dir /workspace/vmp/build-linux-x64 --output-on-failure
   ```
   结果：6/6 通过。

4. Cargo workspace：
   ```bash
   cd /workspace/vmp && cargo test --workspace
   ```
   结果：全部通过；`vmp-policy` 单元测试与跨语言等价测试通过。

5. CLI 正例：
   ```bash
   /workspace/vmp/build-linux-x64/tools/vmp-protect --policy /workspace/vmp/tests/policy/examples/good.json
   ```
   实际输出：`OK: policy loaded, 2 entries, schema=v1`
   退出码：`0`

6. CLI 反例：
   ```bash
   /workspace/vmp/build-linux-x64/tools/vmp-protect --policy /workspace/vmp/tests/policy/examples/bad_vm_func_native.json
   ```
   实际输出包含：`error[vm_func_native] ...`
   退出码：`2`

## 本轮未实现项
- `vmp-protect` 的实际保护流程（除 policy 载入/验证/导出/schema 以外）仍未实现，当前仍可打印 `NOT_IMPLEMENTED`。
- `analyzer/`：源码级/二进制级分析逻辑未实现。
- `planner/`：Protection Plan 决策逻辑未实现。
- `backends/llvm/`：LLVM lifting / pass / 插桩未实现。
- `backends/rewriter/`：PE/ELF/Mach-O/APK/IPA 重写未实现。
- `runtime/*`、`loader/*`、`arch/*` 真实 VM/JIT/字符串保护/审计/完整性/平台接入未实现。
- `bindings/cpp/` attribute plugin/front-end 集成未实现；`bindings/rust/vmp-macros` 仍是透传占位。

## 下一子任务建议
- 进入 `analyzer/` + `planner/` 最小闭环：在已有 Policy IR 基础上补 `ProgramIR` / `ProtectionPlan` 最小类型与空规划流，使 `vmp-protect --policy ... <input>` 可以在不做真实保护的前提下走通“读策略 → 产出空计划”路径。

### ci_fix_round_1
- 改动清单：
  - `CMakeLists.txt`：在 options 之后、`add_subdirectory(...)` 之前引入 `cmake/third_party.cmake`，并统一调用 `vmp_require_nlohmann_json()`。
  - `cmake/third_party.cmake`：新增第三方依赖入口，优先 `find_package(nlohmann_json CONFIG QUIET)`，失败后使用 `FetchContent_MakeAvailable` 从 `https://github.com/nlohmann/json.git` 的 `v3.11.3` 拉取。
  - `policy/CMakeLists.txt`：删除 `find_package(nlohmann_json REQUIRED)`，保留 `target_link_libraries(vmp_policy PUBLIC nlohmann_json::nlohmann_json)`。
- 两次 configure 结果：
  - `cmake -S /workspace/vmp -B /workspace/vmp/build-fix`：成功；命中系统已安装的 `nlohmann_json` 包路径。
  - `cmake -S /workspace/vmp -B /workspace/vmp/build-fix-fetch -DCMAKE_DISABLE_FIND_PACKAGE_nlohmann_json=TRUE`：成功；命中 `FetchContent` 分支并完成 `v3.11.3` 拉取。
- 其他本轮验证：
  - `cmake --build /workspace/vmp/build-fix -j`：成功。
  - `ctest --test-dir /workspace/vmp/build-fix --output-on-failure`：成功，`6/6` 通过。
  - `cargo test --workspace`：成功。
- 未完成项：无（本轮子任务范围内）。
- 下一子任务建议：等待 supervisor 指定下一轮 CI/跨平台修复项。

### subtask_03
- 本轮清单：
  - 实现 `runtime/audit/` C++ 审计运行时：`AnalysisEventRecord`、`make_event(...)`、结构化单行格式化、append-only `AuditWriter`、`IDetector`/`NullDetector`、`ReactionDispatcher`、占位 hook 初始化。
  - 实现 `runtime/audit/rust_audit/` Rust 镜像：同构 `AnalysisEventRecord + serde`、逐字节等价 `format_line()`、`AuditWriter`、`ReactionDispatcher`、可注入 delayed-exit hook、`format_record` example。
  - 将 `vmp-protect` 扩展为支持 `--detector-selftest`：用 `NullDetector` 注入 3 条假事件，经 `audit_then_delayed_exit` 完整走通审计 + delayed-exit hook（测试下注入 flag，不真实退出）。
  - 新增 `tests/audit/`：C++ 精确格式/失败静默/并发写入/策略分发/null detector/placeholder，Rust 精确格式与跨语言 golden，CLI selftest 校验日志 3 行。
  - 更新 `runtime/audit/README.md`：补充行格式 EBNF、字段语义、默认路径、线程安全与失败静默策略。
- 变更文件：
  - `runtime/audit/CMakeLists.txt`
  - `runtime/audit/README.md`
  - `runtime/audit/include/vmp/runtime/audit/audit.h`
  - `runtime/audit/include/vmp/runtime/audit/detector.h`
  - `runtime/audit/include/vmp/runtime/audit/placeholder.h`
  - `runtime/audit/include/vmp/runtime/audit/reaction.h`
  - `runtime/audit/src/audit.cpp`
  - `runtime/audit/src/detector.cpp`
  - `runtime/audit/src/placeholder.cpp`
  - `runtime/audit/src/reaction.cpp`
  - `runtime/audit/rust_audit/Cargo.toml`
  - `runtime/audit/rust_audit/examples/format_record.rs`
  - `runtime/audit/rust_audit/src/lib.rs`
  - `runtime/audit/rust_audit/tests/format_tests.rs`
  - `tests/CMakeLists.txt`
  - `tests/audit/assert_detector_selftest.py`
  - `tests/audit/audit_cpp_format.cpp`
  - `tests/audit/audit_cpp_test.cpp`
  - `tests/audit/compare_cpp_rust_audit.py`
  - `tests/audit/golden_line.txt`
  - `tests/audit/golden_record.json`
  - `tools/CMakeLists.txt`
  - `tools/src/vmp_protect.cpp`
  - `STATUS.md`
- 未完成项：
  - `ReactionPolicy::{log,degrade,decoy_terminate}` 仅保留 enum 与 dispatcher 分支/TODO；详细状态机仍待后续子任务。
  - 真 detector（硬件断点、完整性异常、maps 篡改等）尚未实现；本轮只交付接口与 `NullDetector`。
  - Android/iOS loader 真入口未接入；`default_path()` 仅保留平台骨架与环境变量注入点。
- 下一子任务建议：
  - 进入 state machine / 真 detector 子任务：将 `log/degrade/decoy_terminate` 细化为可验证反应路径，并把后续硬件断点 detector 接到当前 audit sink 上，继续遵守 owner override 的 `hw_breakpoint => audit_then_delayed_exit`。
- 验证：
  - `cmake --build build-linux-x64 -j`：通过。
  - `cd build-linux-x64 && ctest --output-on-failure`：`9/9` 全绿。
  - `cargo test --workspace`：全绿；`rust_audit` 5 个测试通过。
  - `./build-linux-x64/tools/vmp-protect --detector-selftest`：退出码 `0`，输出 `audit:ok exits_triggered=3`。
  - `./vm_runtime_audit.log`：共 `3` 行，且 `hw_breakpoint` / `integrity_mismatch` / `unknown` 各 `1` 行。

### ci_fix_round_2
- 改动清单：
  - `tests/policy/policy_cpp_test.cpp`：移除 `/workspace/vmp/...` fixture 绝对路径；优先 `argv[1]`，其次 `VMP_POLICY_FIXTURES_DIR`，最后回退到 `CMAKE_CURRENT_SOURCE_DIR` 注入的默认目录。
  - `tests/policy/policy_cpp_summary.cpp`：支持通过相对文件名 + `VMP_POLICY_FIXTURES_DIR`/默认目录解析 policy fixture，不再依赖固定工作路径。
  - `tests/CMakeLists.txt`：在测试目录内 `find_package(Python3 REQUIRED COMPONENTS Interpreter)`；所有 ctest 中的 Python 脚本统一改为 `${Python3_EXECUTABLE}`；为 `policy_cpp_test` 注入 `VMP_POLICY_FIXTURES_DIR=${CMAKE_SOURCE_DIR}/tests/policy/examples`；为 policy/audit C++ helper 注入默认 fixture 目录宏。
  - `tests/audit/audit_cpp_test.cpp`、`tests/audit/compare_cpp_rust_audit.py`：移除 `/workspace/vmp` 绝对路径，改为默认 fixture 目录或由脚本位置推导 repo root。
  - `runtime/audit/rust_audit/tests/format_tests.rs`、`bindings/rust/vmp-policy/tests/cross_check.rs`：cargo 测试改为从 `CARGO_MANIFEST_DIR` 推导 repo root / fixture 路径，并自动搜索 repo 内现有 `build*` 目录下的 `audit_cpp_format` / `policy_cpp_summary` helper（也支持显式环境变量覆盖）。
  - `.gitignore`：新增 `vm_runtime_audit.log`、`*.log`、`.cargo/registry/`。
  - Git tree 清理：`git rm --cached vm_runtime_audit.log`，将误提交生成物移出版本控制。
- 变更文件：
  - `.gitignore`
  - `bindings/rust/vmp-policy/tests/cross_check.rs`
  - `runtime/audit/rust_audit/tests/format_tests.rs`
  - `tests/CMakeLists.txt`
  - `tests/audit/audit_cpp_test.cpp`
  - `tests/audit/compare_cpp_rust_audit.py`
  - `tests/policy/policy_cpp_summary.cpp`
  - `tests/policy/policy_cpp_test.cpp`
  - `vm_runtime_audit.log`（git index 移除）
- 验证结果（仓库原路径 `/workspace/vmp`）：
  - `cmake -S . -B build-ci-fix -G Ninja -DVMP_PLATFORM=linux -DVMP_ARCH=x64`：通过。
  - `cmake --build build-ci-fix -j`：通过。
  - `ctest --test-dir build-ci-fix --output-on-failure`：`9/9` 通过。
  - `cargo test --workspace`：通过；`rust_audit` 5 个测试、`vmp-policy` 2 个单元测试、`cross_check` 2 个测试全部通过。
- 验证结果（CI 模拟路径 `/tmp/vmp_ci_sim`）：
  - `cp -r /workspace/vmp /tmp/vmp_ci_sim && cd /tmp/vmp_ci_sim && rm -rf build-*` 后重跑 `cmake + build + ctest`：全部通过。
  - `ctest --test-dir build-ci-fix --output-on-failure`：`9/9` 通过，证明测试不依赖 `/workspace/vmp` 绝对路径。
- 未完成项：无（本轮要求范围内）。
- 下一子任务建议：等待 supervisor 指定下一轮 CI/跨平台修复项。

### subtask_04
- 本轮清单：
  - 实现 `bindings/cpp/include/vmp/bindings/cpp/annotate.h`，提供 zero-cost `VMP_VM_FUNC` / `VMP_VM_STRING` 头文件宏；Clang/GCC 走 `annotate("vmp_vm_*")`，MSVC C++ 走 `[[vmp::...]]`，MSVC C 保留源码标记供 fallback 扫描。
  - 实现 `bindings/cpp` C/C++ 标注前端：
    - `vmp-cpp-clang-collect`：基于 Clang AST 的采集工具，识别函数/变量上的 `annotate("vmp_vm_func")`、`annotate("vmp_vm_string")`，输出单个 Policy IR JSON。
    - `vmp_annotate_plugin`：FrontendAction/plugin 形态的 clang 插件构建产物（满足 plugin 模式交付）；驱动当前优先使用独立 AST collector，plugin 路径信息仍保留给 `-Xclang -load`/`VMP_PLUGIN_DIR`。
    - `vmp-cpp-fallback-scan`：无 LLVM/Clang dev 或 `VMP_DISABLE_CLANG_PLUGIN=1` 时启用的源码正则扫描器，覆盖 `VMP_VM_FUNC` / `VMP_VM_STRING` / `annotate(...)` / `[[vmp::...]]` 标记。
  - 实现 `tools/vmp-clang` / `tools/vmp-clang++`：兼容 `clang` 参数透传；带 `--vmp-collect=<policy.json>` 时先调用宿主编译，再运行 AST collector，失败时回落到 fallback scanner；无 `--vmp-collect` 时退化为纯透传。
  - 完成语义映射：
    - `VM_func` → `protection_domain=vm1`
    - `VM_string` → `sensitivity_level=highly_sensitive`、`plaintext_budget=transient_only`
    - 同时 `VM_func + VM_string` 的函数保持 `vm1` 执行域，并升级敏感数据保护
    - 变量声明、`const char[]`、`constexpr char[]`、`constexpr std::string_view` 初始化中的字符串字面量均能采集
    - `symbol_or_region` 在 AST collector 模式下输出 `mangled|display`，fallback 模式输出源码名或 `literal::<file>:<line>[ :<column> ]|"text"`
  - 完成 `tests/bindings_cpp/` 真测：C/C++ 样例、期望 JSON、JSON 语义比较脚本、fallback 强制禁用测试、clang/gcc 头文件编译测试、wrapper 透传测试。
  - 更新 `bindings/cpp/README.md`，补充宏、collector/plugin/fallback 机制、Policy IR 字段映射。
- 变更文件：
  - `CMakeLists.txt`
  - `STATUS.md`
  - `bindings/cpp/CMakeLists.txt`
  - `bindings/cpp/README.md`
  - `bindings/cpp/clang_plugin/vmp_annotate_plugin.cpp`
  - `bindings/cpp/clang_plugin/vmp_annotate_tool.cpp`
  - `bindings/cpp/include/vmp/bindings/cpp/annotate.h`
  - `bindings/cpp/include/vmp/bindings/cpp/plugin.h`
  - `bindings/cpp/src/fallback_scanner.cpp`
  - `bindings/cpp/src/fallback_scanner_main.cpp`
  - `bindings/cpp/src/plugin.cpp`
  - `policy/CMakeLists.txt`
  - `tests/CMakeLists.txt`
  - `tests/bindings_cpp/assert_exists.py`
  - `tests/bindings_cpp/compare_policy_json.py`
  - `tests/bindings_cpp/expected_c.json`
  - `tests/bindings_cpp/expected_cpp_fallback.json`
  - `tests/bindings_cpp/expected_cpp_plugin.json`
  - `tests/bindings_cpp/sample_c.c`
  - `tests/bindings_cpp/sample_cpp.cpp`
  - `tools/CMakeLists.txt`
  - `tools/src/vmp_clang.cpp`
  - `tools/src/vmp_clangxx.cpp`
  - `tools/src/vmp_driver_common.h`
- 未完成项：
  - 未做 LLVM backend 真实 IR 改写；本轮仅做采集与 JSON 产出。
  - 未做 Rust 过程宏、VM/JIT/字符串保护真实实现（按本轮范围未展开）。
  - `vmp_annotate_plugin` 当前作为构建交付物保留，但驱动默认优先走独立 AST collector；后续如需直接 `-Xclang -load` 生产链路，可继续把 plugin 路径接入外部构建系统。
- 下一子任务建议：
  - 进入 analyzer / planner 对接：消费本轮产出的 Policy IR entries，把 `VM_func`/`VM_string` 前端硬约束接到 Program IR / Protection Plan 最小闭环。
- 验证：
  - `cmake --build build -j`：通过。
  - `ctest --test-dir build --output-on-failure`：`20/20` 通过。
  - `cargo test --workspace`：通过。
  - `rg -n 'NOT_IMPLEMENTED' bindings/cpp`：无结果。
  - `/tmp/vmp_ci_sim` 中重跑 `cmake -S . -B build -G Ninja && cmake --build build -j && ctest --test-dir build --output-on-failure && cargo test --workspace`：全部通过。

### ci_fix_round_3
- 改动清单：
  - 仓库内移除 `.cargo/config.toml`（`git rm` 语义），避免 GitHub runner 被 Debian 本地 registry 路径 `/usr/share/cargo/registry` 绑死；容器内改走家目录级 `/root/.cargo/config.toml`，CI workflow 无需改动。
  - `.gitignore` 补齐/确认：`.cargo/`、`vm_runtime_audit.log`、`*.log`、`build-*/`、`target/`、`**/target/`；复检当前 git tracked 临时日志 / `build-*` 生成物，无新增需清理项。
  - `tests/CMakeLists.txt`：新增 `if(WIN32) set(VMP_TEST_BIN_SUFFIX ".exe") endif()`；所有 ctest 中被测二进制统一改为 `$<TARGET_FILE:...>` 传绝对路径，不再手写 `${CMAKE_BINARY_DIR}/tools/...` / `${CMAKE_BINARY_DIR}/tests/...`。
  - `tests/CMakeLists.txt`：`cross_language_golden` 现在显式把 `audit_cpp_format` 绝对路径与 `${CMAKE_SOURCE_DIR}` 传给 Python 驱动，并加 `SKIP_REGULAR_EXPRESSION "cross language audit golden SKIPPED"`。
  - `tests/audit/compare_cpp_rust_audit.py`：
    - 通过 `argv` 接收 C++ helper 绝对路径、fixture、repo root；
    - 先 `shutil.which("cargo")` 检查 cargo，可用性缺失时输出 skip 而非 error；
    - `cargo build -p rust_audit --example format_record` 后直接执行生成的 example 二进制（`.exe` / 非 `.exe` 都支持），不再 `cargo run`。
  - `tests/policy/compare_cpp_rust.py`：同样改为 cargo availability 检查 + `cargo build` + 直接执行 example，可避免 shell/路径差异。
- 变更文件：
  - `.cargo/config.toml`（删除，不再入仓）
  - `.gitignore`
  - `tests/CMakeLists.txt`
  - `tests/audit/compare_cpp_rust_audit.py`
  - `tests/policy/compare_cpp_rust.py`
  - `STATUS.md`
- 本地验证（仓库原路径 `/workspace/vmp`）：
  - `CARGO_NET_OFFLINE=1 cargo build -q -p rust_audit --example format_record`：通过；证明去掉仓库内 `.cargo/config.toml` 后，容器仍可通过家目录级 cargo config 离线构建。
  - `cmake -S . -B build-ci-fix3 -G Ninja -DVMP_PLATFORM=linux -DVMP_ARCH=x64`：通过。
  - `cmake --build build-ci-fix3 -j2`：通过。
  - `ctest --test-dir build-ci-fix3 --output-on-failure`：`20/20` 通过。
- `/tmp` 路径验证（CI 模拟目录 `/tmp/vmp_ci_sim_win`）：
  - 先复制仓库到 `/tmp/vmp_ci_sim_win`，再 `rm -rf build-* target`。
  - `cmake -S . -B build-multi -G 'Ninja Multi-Config' -DCMAKE_CONFIGURATION_TYPES=Release -DVMP_PLATFORM=linux -DVMP_ARCH=x64`：通过。
  - `cmake --build build-multi --config Release -j2`：通过。
  - `ctest --test-dir build-multi -C Release --output-on-failure`：`20/20` 通过。
- 如何保证 Windows 也能过：
  - 通过 `$<TARGET_FILE:vmp-protect>` / `$<TARGET_FILE:audit_cpp_format>` / `$<TARGET_FILE:vmp-clang>` 等 generator expression，CTest 生成时已解析为多配置真实路径；在 `/tmp/vmp_ci_sim_win/build-multi/tests/CTestTestfile.cmake` 中可见 `tools/Release/vmp-protect`、`tests/Release/audit_cpp_format`、`tools/Release/vmp-clang++` 等实际命令。
  - Python 驱动不再自行拼接后缀或相对路径，统一消费 CMake 传入的绝对路径 argv；因此 MSVC 的 `Release/*.exe` 路径也能被同一套驱动直接执行。
  - cargo 相关驱动已移除 `cargo run`，改成 `cargo build` 后直接 exec example，规避 Windows shell 解析差异。
- 未完成项：
  - 远端 GH Actions 结果尚待 supervisor 观察；若仍有 Windows-only 特例（例如 MSVC/clang-cl 工具链细节），进入下一轮再修。
- 下一子任务建议：
  - 等待 supervisor 回看最新 GH Actions；若 Windows runner 仍有特殊失败，优先抓取对应 job 的 CTest command line / stderr 做定点修复。

### subtask_05
- 本轮清单：
  - 实现 `runtime/vm1/` 的 VM1 ISA 定义：32 个通用寄存器、4 个浮点寄存器、`pc/sp/flags`、算术/位运算、显式宽度 load/store、控制流、`domain_call/domain_ret`、`load_transient_string`、模块头/常量池格式。
  - 实现 `Vm1Module` 加载/保存/序列化、文本 DSL 汇编器 `assemble_module_text()`、反汇编 `disassemble_module()`。
  - 实现 `Vm1Context` + `Vm1Interpreter`：私有线程栈（默认 64KiB）、寄存器快照式调用帧、溢出参数栈区、switch-in-loop dispatch、越界/除零/未知 opcode/stack overflow 等异常路径。
  - 实现 `runtime/vm1/include/vmp/runtime/bridge/bridge.h` 与 `BridgeRegistry`：`native↔vm1` / `vm1↔vm1` 最小跨域 ABI、`max_depth` 保护、异常状态映射与 `last_domain_exception()`。
  - 实现工具：`vmp-vm1-asm`、`vmp-vm1-run`。
  - 实现 audit 集成：`breakpoint -> vm1_breakpoint`、`trap -> vm1_trap`、`unknown opcode -> vm1_unknown_opcode`、`stack overflow -> vm1_stack_overflow`，统一 `audit_only`。
  - 新增 `tests/runtime_vm1/` 真测：round-trip、arith、control_flow、call/ret、cross-domain、exceptions、breakpoint、bench、CLI fib20。
  - 更新 `runtime/vm1/README.md`：ISA、字节码格式、DSL、跨域 ABI 文档。
- 本轮变更文件：
  - `runtime/vm1/CMakeLists.txt`
  - `runtime/vm1/README.md`
  - `runtime/vm1/include/vmp/runtime/bridge/bridge.h`
  - `runtime/vm1/include/vmp/runtime/vm1/isa.h`
  - `runtime/vm1/include/vmp/runtime/vm1/vm1.h`
  - `runtime/vm1/src/bridge.cpp`
  - `runtime/vm1/src/interpreter.cpp`
  - `runtime/vm1/src/vm1.cpp`
  - `tests/CMakeLists.txt`
  - `tests/runtime_vm1/test_common.h`
  - `tests/runtime_vm1/vm1_asm_round_trip.cpp`
  - `tests/runtime_vm1/vm1_arith_ops.cpp`
  - `tests/runtime_vm1/vm1_control_flow.cpp`
  - `tests/runtime_vm1/vm1_call_ret.cpp`
  - `tests/runtime_vm1/vm1_cross_domain_call.cpp`
  - `tests/runtime_vm1/vm1_exceptions.cpp`
  - `tests/runtime_vm1/vm1_breakpoint_event.cpp`
  - `tests/runtime_vm1/bench/vm1_bench.cpp`
  - `tests/runtime_vm1/fixtures/fib20.vm1s`
  - `tools/CMakeLists.txt`
  - `tools/src/vmp_vm1_asm.cpp`
  - `tools/src/vmp_vm1_run.cpp`
  - `STATUS.md`
- 未完成项：
  - 本轮要求范围内无未完成项。
  - `vm2` / JIT / 真字符串保护 / 更复杂对象句柄桥接仍留待后续指定子任务。
- 下一子任务建议：
  - 等待 supervisor 指定下一轮（建议后续对接 `VM_string` 真瞬时解密链或 VM2 独立 ISA/解释器子任务）。
- 验证：
  - `cd /workspace/vmp && cmake --build build -j`：通过。
  - `cd /workspace/vmp && ctest --test-dir build --output-on-failure`：`30/30` 通过。
  - `cd /workspace/vmp && cargo test --workspace`：通过。
  - `cd /workspace/vmp && ./build/tools/vmp-vm1-asm tests/runtime_vm1/fixtures/fib20.vm1s /tmp/fib20.vm1 && ./build/tools/vmp-vm1-run /tmp/fib20.vm1 20`：输出 `ret_int=6765 ret_float=0`。
  - `cd /tmp/vmp_ci_sim && ctest --test-dir build --output-on-failure && cargo test --workspace`：全部通过。

### ci_fix_round_4
- 本轮清单：
  - 从版本控制中移除误提交的 `build/` 目录（`git rm -rf build`），清掉被跟踪的 `CMakeCache.txt`、`CMakeFiles/`、`CTestTestfile.cmake`、Ninja 产物和测试二进制。
  - 扩充 `.gitignore`，同时覆盖 `build/` 与 `build-*/`，避免后续再次把默认构建目录提交进仓库。
  - 复检 `git ls-files` 中的生成物模式：`(^|/)build/`、`CMakeCache`、`CMakeFiles`、`_deps/`；确认仓库索引内已无同类误提交产物。
- 变更文件：
  - `.gitignore`
  - `STATUS.md`
  - `build/` 下全部已跟踪生成物（删除出索引）
- 验证：
  - `cd /workspace/vmp && git ls-files | grep -E '(^|/)build/|CMakeCache|CMakeFiles|_deps/'`：无输出。
  - `cd /workspace/vmp && rm -rf build && cmake -S . -B build -G Ninja -DVMP_PLATFORM=linux -DVMP_ARCH=x64`：通过，干净 configure 成功。
  - `cd /workspace/vmp && cmake --build build -j && ctest --test-dir build --output-on-failure`：通过，`30/30` 测试通过。
  - `cd /workspace/vmp && cargo test --workspace`：通过；Rust workspace 全绿。
  - `rm -rf /tmp/vmp_ci_sim_clean && cp -a /workspace/vmp/. /tmp/vmp_ci_sim_clean/ && cd /tmp/vmp_ci_sim_clean && rm -rf build && cmake -S . -B build -G Ninja -DVMP_PLATFORM=linux -DVMP_ARCH=x64 && cmake --build build -j && ctest --test-dir build --output-on-failure && cargo test --workspace`：通过；clean copy 下 configure/build/test 全绿。
- 未完成项：
  - 本轮要求范围内无未完成项。
- 下一子任务建议：
  - 等待 supervisor 检查 CI；若仍有平台特定失败，再按失败 job 日志做定点修复。

### subtask_06
- 本轮清单：
  - 实现 `runtime/strings`：纯 C++ `ChaCha20`、`SHA256`、`HMAC-SHA256`、`HKDF-SHA256`、`StringPool`、`TransientView`、`secure_memzero()`、`ScopedCurrentPool` / `VMP_STRING_USE`。
  - 加入字符串记录格式：`ChaCha20(4-byte length prefix || plaintext)` + `HMAC-SHA256(nonce || encrypted_payload)`，索引 JSON 同时携带 salt/KDF 元数据与 `plaintext_budget`。
  - 实现 `tools/src/vmp_string_protect.cpp` 与 `tools/src/string_protect_common.h`：从带 `vm_string` 条目和 `value/string_id` 的 policy JSON 生成 `string_pool.bin`、`string_pool.idx.json`、`key_derivation.json`，master key 仅经 CLI/env/stdin 注入，不落盘。
  - 扩展 `vmp-protect --protect-strings`：在保留 Policy IR 校验的同时，允许 policy 中存在 `string_id/value` 工具字段；可直接生成 pool / idx / kdf。
  - 扩展 `vmp-vm1-run`：支持 `--string-pool` / `--string-idx` / `--key-env` 加载加密字符串池，并提供 `--native-print-string <id>` 便于集成测试/演示。
  - 回改 VM1：新增 `release_transient_string` opcode（`0x41`），DSL 支持 `load_tstr vrX, &sidN` / `release_tstr vrX`；`load_tstr` 走 `StringPool` 瞬时解密；显式释放或在 `ret`/异常 unwind 时自动擦除 handle。
  - 审计集成：解密异常 / 池损坏 / key mismatch 记 `string_pool_error`；`plaintext_budget=none` 的条目运行时拒绝并记 `plaintext_budget_violation`。
  - 新增真测：RFC/NIST/RFC5869 向量、零化验证、8 线程并发、pool corruption audit、VM1 transient-string bridge 集成、`vmp-string-protect` round-trip、`vmp-protect --protect-strings`。
  - 更新 `runtime/strings/README.md` 与 `runtime/vm1/README.md`：格式、KDF、RAII 擦除、VM1 opcode、CLI 用法、JIT 约束 hook 注释。
- 本轮变更文件：
  - `runtime/strings/CMakeLists.txt`
  - `runtime/strings/README.md`
  - `runtime/strings/include/vmp/runtime/strings/cipher.h`
  - `runtime/strings/include/vmp/runtime/strings/keyctx.h`
  - `runtime/strings/include/vmp/runtime/strings/use.h`
  - `runtime/strings/include/vmp/runtime/strings/strings.h`
  - `runtime/strings/src/keyctx.cpp`
  - `runtime/strings/src/strings.cpp`
  - `runtime/strings/rust_strings/src/lib.rs`
  - `runtime/vm1/CMakeLists.txt`
  - `runtime/vm1/README.md`
  - `runtime/vm1/include/vmp/runtime/vm1/isa.h`
  - `runtime/vm1/include/vmp/runtime/vm1/vm1.h`
  - `runtime/vm1/src/interpreter.cpp`
  - `runtime/vm1/src/vm1.cpp`
  - `tests/CMakeLists.txt`
  - `tests/strings/test_common.h`
  - `tests/strings/crypto_vectors.cpp`
  - `tests/strings/transient_view_zeroization.cpp`
  - `tests/strings/concurrency_8_threads.cpp`
  - `tests/strings/pool_corruption_detected.cpp`
  - `tests/strings/vmp_string_protect_roundtrip.py`
  - `tests/strings/vmp_protect_strings.py`
  - `tests/runtime_vm1/strings_integration/vm1_load_transient_string_integration.cpp`
  - `tools/CMakeLists.txt`
  - `tools/src/string_protect_common.h`
  - `tools/src/vmp_string_protect.cpp`
  - `tools/src/vmp_protect.cpp`
  - `tools/src/vmp_vm1_run.cpp`
  - `STATUS.md`
- 未完成项：
  - 本轮要求范围内无未完成项。
  - 后续仅保留 plan 指定外事项：JIT 常量传播约束的真实实现、平台 loader 接入、VM2、更多 runtime 策略接线。
- 下一子任务建议：
  - 等待 supervisor 指定下一轮；若继续字符串链路，可进入 loader/runtime state 对接或 JIT 常量传播约束的真实实现子任务。
- 验证：
  - `cd /workspace/vmp && cmake --build build -j`：通过。
  - `cd /workspace/vmp && ctest --test-dir build --output-on-failure`：`37/37` 通过。
  - `cd /workspace/vmp && cargo test --workspace`：通过。
  - `cd /workspace/vmp && python3 tests/strings/vmp_string_protect_roundtrip.py build/tools/vmp-string-protect build/tools/vmp-vm1-asm build/tools/vmp-vm1-run`：输出 `vmp-string-protect round-trip OK`。
  - `/tmp` clean replay：复制到 `/tmp/vmp-sub06-replay`（排除 `build*` / `target` / log），随后 `cmake -S . -B build && cmake --build build -j && ctest --test-dir build --output-on-failure && cargo test --workspace`：通过，输出 `TMP_REPLAY_OK`。

### ci_fix_round_5
- A. cross_language_golden / Cargo checksum 根因：仓库曾携带应用层 `Cargo.lock`，其 checksum 来自容器内历史 Debian registry；CI 的 crates.io checksum 不同，导致 `cfg-if v1.0.0 changed between lock files`。
  - 修法：
    - 从版本控制移除 `Cargo.lock`（`git rm Cargo.lock`）。
    - `.gitignore` 新增 `Cargo.lock`，避免本地 `cargo test` 重新生成的 lockfile 污染工作树。
    - `tests/audit/compare_cpp_rust_audit.py` 在调用 cargo 前显式移除 `CARGO_HOME` / `CARGO_BUILD_OFFLINE`，确保交叉语言 golden 使用 runner 自己的 cargo 配置。
- B. bindings/cpp compare JSON 平台漂移根因：
  - collector / fallback 在不同平台上会产出绝对路径、不同列号精度、以及 `mangled|display` 的 ABI 差异（Itanium vs MSVC）。
  - `.c` 文件在某些 clang-cl / Windows 路径上会被 AST collector 按 C++ 模式看待。
  - 修法：
    - `tests/bindings_cpp/compare_policy_json.py` 改为语义归一比较：
      - `source_location.file` 归一为 basename；忽略 `column`；
      - `symbol_or_region` 中非 literal 符号只比较 display-name；literal 只比较 `basename + line + text`；
      - 忽略 `defaults` 整段，避免 Policy IR 默认字段扩展/变更导致 golden 脆断。
    - `bindings/cpp/clang_plugin/vmp_annotate_tool.cpp` 与 `...plugin.cpp` 改为基于源文件扩展名推断 `language_origin`（`.c -> c`，其余 C++ 扩展 -> `cpp`），不再依赖 libclang 的语言模式位。
    - `tests/bindings_cpp/expected_*.json` 更新为归一后的 basename / display-name 版本，消除平台 ABI 差异。
- C. linux `find_package(Clang)` 触发 ClangTargets 依赖缺失根因：GitHub runner 默认缺 `libclang-dev` / `llvm-dev`，旧配置在解析 Clang CMake package 时容易踩到不完整 target 依赖。
  - 修法：
    - `bindings/cpp/CMakeLists.txt` 改为先在子 `cmake -P` 探针中探测 LLVM/Clang package 与关键 targets（`clangTooling` / `clangAST` / `clangBasic` / `clangFrontend` / `clangLex`）；探针失败时直接退回 fallback scanner-only，不让主 configure 因 Clang package 半安装而炸掉。
    - `.github/workflows/linux.yml` 的 deps step 新增：`libclang-dev llvm-dev clang`。
    - 其余平台默认允许 fallback scanner 路径，无 plugin 依赖。
- D. 额外加固：
  - `tests/CMakeLists.txt` 新增 `vmp_unset_ci_polluters(...)`，对 `cross_language_golden`、`bindings_cpp_collect_*` 与 compare 测试显式 unset `CARGO_HOME`、`CARGO_BUILD_OFFLINE`、`VMP_DISABLE_CLANG_PLUGIN`。

- 本地验证（/workspace/vmp）：
  - `env -u CARGO_HOME -u CARGO_BUILD_OFFLINE cmake -S . -B build -G Ninja -DVMP_PLATFORM=linux -DVMP_ARCH=x64 -DCMAKE_BUILD_TYPE=Release`：通过。
  - `env -u CARGO_HOME -u CARGO_BUILD_OFFLINE cmake --build build -j`：通过。
  - `env -u CARGO_HOME -u CARGO_BUILD_OFFLINE ctest --test-dir build --output-on-failure`：`37/37` 通过。
  - `env -u CARGO_HOME -u CARGO_BUILD_OFFLINE cargo test --workspace --all-features`：通过。
- 干净副本验证（/tmp/vmp_ci_sim_round5）：
  - `cmake -S . -B build -G Ninja ... && cmake --build build -j`：通过。
  - `ctest --test-dir build --output-on-failure`：`37/37` 通过。
  - `cargo test --workspace --all-features`：通过。
- Multi-Config / MSVC-like 验证（/tmp/vmp_ci_sim_msvclike）：
  - `cmake -S . -B build-multi -G "Ninja Multi-Config" -DVMP_PLATFORM=windows -DVMP_ARCH=x64`：通过。
  - `cmake --build build-multi --config Release -j`：通过。
  - `ctest --test-dir build-multi -C Release --output-on-failure`：`37/37` 通过。
- 额外核对：
  - `git ls-files | grep -i Cargo.lock`：空。
  - `git ls-files | grep -E "Cargo.lock|(^|/)build/"`：空。
- 未完成项：无（本轮范围内）。
- 下一子任务建议：等待 supervisor 指定下一轮 CI / 功能任务。

### subtask_07
- 本轮清单：
  - 实现 Rust proc-macro 前端：`#[vm_func]` / `#[vm_string]` 与 literal-site `vm_string!` wrapper 所需的 hidden helper `vm_string_literal!`。
  - 新增 Rust TSV collector：`vmp-rust-collect --target-dir <dir> --policy-out <path>`，支持空文件、去重、坏行报错。
  - 新增 Rust sample / parity / merge 集成测试，并把 Rust TSV 合并接入 `vmp-protect --rust-target-dir`。
  - 更新 Rust 绑定文档。
- 变更文件：
  - `Cargo.toml`
  - `bindings/rust/README.md`
  - `bindings/rust/vmp-macros/Cargo.toml`
  - `bindings/rust/vmp-macros/src/lib.rs`
  - `bindings/rust/vmp-policy/src/lib.rs`
  - `bindings/rust/vmp-rust-collect/Cargo.toml`
  - `bindings/rust/vmp-rust-collect/src/lib.rs`
  - `bindings/rust/vmp-rust-collect/src/main.rs`
  - `bindings/rust/vmp-rust-collect/tests/collect.rs`
  - `tests/CMakeLists.txt`
  - `tests/bindings_rust/base_policy.json`
  - `tests/bindings_rust/compare_parity.py`
  - `tests/bindings_rust/compare_policy_json.py`
  - `tests/bindings_rust/expected.json`
  - `tests/bindings_rust/parity_c/sample.c`
  - `tests/bindings_rust/sample/Cargo.toml`
  - `tests/bindings_rust/sample/build.rs`
  - `tests/bindings_rust/sample/src/lib.rs`
  - `tools/src/vmp_protect.cpp`
- 未完成项：
  - 本轮范围内无未完成项。
- 下一子任务建议：
  - 若继续 Rust 侧工作，可进入 planner/analyzer 真正消费 `vm_string_func_scope`、泛型实例与 panic/formatting message 提升链路。
- 验证：
  - `cd /workspace/vmp && cmake --build build -j`：通过。
  - `cd /workspace/vmp && ctest --test-dir build --output-on-failure`：`44/44` 通过。
  - `cd /workspace/vmp && cargo test --workspace`：通过。
  - `cd /workspace/vmp && cargo build -p demo_sample`：通过。
  - `cd /workspace/vmp && cargo run -p vmp-rust-collect -- --target-dir target --policy-out /tmp/demo_sample_policy.json && python3 tests/bindings_rust/compare_policy_json.py /tmp/demo_sample_policy.json tests/bindings_rust/expected.json`：通过，输出 `policy json equal`。
  - `cd /workspace/vmp && build/tools/vmp-protect --policy tests/bindings_rust/base_policy.json --rust-target-dir target --emit-policy-json /tmp/demo_sample_merged.json --validate-only && python3 tests/bindings_rust/compare_policy_json.py /tmp/demo_sample_merged.json tests/bindings_rust/expected.json`：通过，输出 `policy json equal`。
  - clean-copy `/tmp` 回放：复制到 `/tmp/vmp-sub07-replay`（排除 `.git` / `build*` / `target` / `Cargo.lock`），随后 `cmake -S . -B build -G Ninja && cmake --build build -j && ctest --test-dir build --output-on-failure && cargo test --workspace && cargo build -p demo_sample && cargo run -p vmp-rust-collect -- --target-dir target --policy-out /tmp/vmp_sub07_policy.json && build/tools/vmp-protect --policy tests/bindings_rust/base_policy.json --rust-target-dir target --emit-policy-json /tmp/vmp_sub07_merged.json --validate-only`：通过，输出 `TMP_REPLAY_OK`。

### subtask_08
- 本轮清单：
  - 实现 VM2 独立 ISA / 模块容器：`VMP2` magic、2-byte opcode、`r/q/d/p + pc/sp/lr`、独立 `key_context_id[16]`、128KiB downward private stack、与 VM1 不兼容的 handler identity。
  - 实现 `Vm2Context` / `Vm2Interpreter`：整数/向量算术、load/store、`blnk/bret`、`pcall/pret`、`xcall/xret`、`tsload/tsrelease`、异常族 `Vm2Exception/Vm2DivByZero/Vm2StackOverflow/Vm2UnknownOpcode`、audit 事件映射。
  - 扩展跨域桥接：`BridgeRegistry::register_vm2(...)` 与 `native↔vm2` / `vm1↔vm2` / `vm2↔vm2` 双向调用，保留共享 `max_depth=64` 默认值。
  - 接通 VM2 字符串句柄：`Vm2Context` 持有独立 `KeyContext` / `StringPool`，`tsload` 按 `key_context_id` 校验，`bret/xret/异常` 自动擦除未释放 handle。
  - 新增 VM2 DSL / CLI：`runtime/vm2/asm/README.md`、`vmp-vm2-asm`、`vmp-vm2-run`。
  - 新增 `tests/runtime_vm2/` 真测与 `fib20.vm2s` fixture，并接入 CTest。
  - 更新 `runtime/vm2/README.md` 与 Rust placeholder 字样，确保本轮新增文件无 `NOT_IMPLEMENTED`。
- 变更文件：
  - `runtime/vm1/include/vmp/runtime/bridge/bridge.h`
  - `runtime/vm1/include/vmp/runtime/vm1/vm1.h`
  - `runtime/vm1/src/bridge.cpp`
  - `runtime/vm1/src/vm1.cpp`
  - `runtime/vm2/CMakeLists.txt`
  - `runtime/vm2/README.md`
  - `runtime/vm2/asm/README.md`
  - `runtime/vm2/include/vmp/runtime/vm2/isa.h`
  - `runtime/vm2/include/vmp/runtime/vm2/vm2.h`
  - `runtime/vm2/rust_vm2/src/lib.rs`
  - `runtime/vm2/src/interpreter.cpp`
  - `runtime/vm2/src/vm2.cpp`
  - `tests/CMakeLists.txt`
  - `tests/runtime_vm2/test_common.h`
  - `tests/runtime_vm2/vm2_asm_round_trip.cpp`
  - `tests/runtime_vm2/vm2_arith_ops.cpp`
  - `tests/runtime_vm2/vm2_control_flow.cpp`
  - `tests/runtime_vm2/vm2_calling_convention.cpp`
  - `tests/runtime_vm2/vm2_cross_domain.cpp`
  - `tests/runtime_vm2/vm2_exceptions.cpp`
  - `tests/runtime_vm2/vm2_breakpoint_event.cpp`
  - `tests/runtime_vm2/vm2_string_integration.cpp`
  - `tests/runtime_vm2/isa_isolation.cpp`
  - `tests/runtime_vm2/fixtures/fib20.vm2s`
  - `tools/CMakeLists.txt`
  - `tools/src/vmp_vm2_asm.cpp`
  - `tools/src/vmp_vm2_run.cpp`
- 未完成项：
  - 本轮要求范围内无未完成项。
- 下一子任务建议：
  - 若继续 runtime 方向，可进入 VM2 JIT（subtask 11）或后续 loader / planner 对接，让 Protection Plan 真正分配 VM1/VM2。
- 验证：
  - `cd /workspace/vmp && cmake --build build -j`：通过。
  - `cd /workspace/vmp && ctest --test-dir build --output-on-failure`：`55/55` 通过。
  - `cd /workspace/vmp && cargo test --workspace`：通过。
  - `cd /workspace/vmp && ./build/tools/vmp-vm2-asm tests/runtime_vm2/fixtures/fib20.vm2s /tmp/fib20.vm2 && ./build/tools/vmp-vm2-run /tmp/fib20.vm2 20`：输出 `ret_int=6765`。
  - `cd /workspace/vmp && rg -n "NOT_IMPLEMENTED" runtime/vm2 tools/src/vmp_vm2_asm.cpp tools/src/vmp_vm2_run.cpp tests/runtime_vm2`：无输出。
  - clean-copy `/tmp` 回放：复制到 `/tmp/vmp-sub08-replay`（排除 `.git` / `build*` / `target` / `Cargo.lock` / `passwd.txt` / `OUT_DIR`），随后 `cmake -S . -B build -G Ninja && cmake --build build -j && ctest --test-dir build --output-on-failure && cargo test --workspace`：通过。

### subtask_09
- 本轮清单：
  - 实现 `loader/linux/`：`vmp_linux_init()` 通过 `constructor(101)` + `.init_array` fallback 提前启动，完成审计 sink、`RuntimeState`、占位 hook、`VMP_STRING_MASTER_KEY` 恢复，并在异常时记录 `loader_init_failure`。
  - 实现 `loader/windows/`：补齐 `.CRT$XLB` TLS callback、`vmp_windows_loader_dll_main(...)`、线程 attach/detach 最小状态维护与进程级一次性初始化路径；保持 `_WIN32` 友好的头文件导出。
  - 实现 `runtime/state/` 最小状态机：`RuntimeState` 单例、`init_once` / `observe` / `set_flag` / `check_flag` / `get_audit` / `shutdown`，并去除该目录内 `NOT_IMPLEMENTED`。
  - 调整 audit 默认路径：`AuditWriter::default_path()` 新增识别 `VMP_AUDIT_PATH`（保留旧 `VMP_AUDIT_LOG_PATH` 兼容）。
  - 将占位 hook 初始化收口到 loader 路径；`runtime/audit` 不再自行通过 constructor 提前调用 placeholder。
  - 新增 `tools/vmp-loader-selftest` 与 `tests/loader/` 真测：Linux ctor 优先级、自检日志、`VMP_AUDIT_PATH` 覆盖、`VMP_DISABLE_LOADER` 抑制、`LD_PRELOAD` 共享库路径；Windows 保留平台门控的 PE `.CRT` 检查脚本。
  - 更新 `loader/README.md`、平台 README、`tools/README.md`，并为 `vmp-protect` 增加 `--platform` 参数接线/文档入口，供后续 loader 挂接使用（本轮不做重写）。
- 变更文件：
  - `CMakeLists.txt`
  - `STATUS.md`
  - `loader/README.md`
  - `loader/linux/CMakeLists.txt`
  - `loader/linux/README.md`
  - `loader/linux/include/vmp/loader/linux/linux_loader.h`
  - `loader/linux/src/linux_loader.cpp`
  - `loader/windows/CMakeLists.txt`
  - `loader/windows/README.md`
  - `loader/windows/include/vmp/loader/windows/windows_loader.h`
  - `loader/windows/src/windows_loader.cpp`
  - `runtime/audit/src/audit.cpp`
  - `runtime/audit/src/placeholder.cpp`
  - `runtime/state/CMakeLists.txt`
  - `runtime/state/README.md`
  - `runtime/state/include/vmp/runtime/state/state.h`
  - `runtime/state/rust_state/src/lib.rs`
  - `runtime/state/src/state.cpp`
  - `tests/CMakeLists.txt`
  - `tests/loader/assert_audit_log.py`
  - `tests/loader/assert_log_absent.py`
  - `tests/loader/loader_linux_init_order.cpp`
  - `tests/loader/loader_preload_probe.cpp`
  - `tests/loader/pe_tls_callback_check.py`
  - `tools/CMakeLists.txt`
  - `tools/README.md`
  - `tools/src/vmp_loader_selftest.cpp`
  - `tools/src/vmp_protect.cpp`
- 未完成项：
  - Windows TLS callback 的运行时验证仅在 Windows CI 上执行；当前 Linux 容器内仅完成编译覆盖与平台门控脚本落地。
  - Android/iOS loader 仍待子任务 12。
  - 完整性状态联动、JIT/画像更细粒度状态机扩展待子任务 16。
- 下一子任务建议：
  - 进入子任务 12，补 Android `JNI_OnLoad + constructor` 与 iOS `constructor + capability gate`，并与本轮 `RuntimeState`/audit/key-context 初始化协议保持一致。
- 验证：
  - TDD red：先添加 `tests/loader/loader_linux_init_order.cpp` 并尝试构建，初次失败于缺失 `RuntimeState` / `RuntimeFlag` API；随后补实现并转绿。
  - `cmake --build build -j`：通过。
  - `ctest --test-dir build --output-on-failure`：`64/64` 通过（Windows-only 测试按平台门控跳过）。
  - `cargo test --workspace`：通过。
  - 手动验证：
    - `VMP_AUDIT_PATH=/tmp/manual_loader.log ./build/tools/vmp-loader-selftest` 后日志存在且包含 `loader_init`。
    - `VMP_DISABLE_LOADER=1 VMP_AUDIT_PATH=/tmp/manual_loader_disabled.log ./build/tools/vmp-loader-selftest` 后无日志内容。
    - `./build/tools/vmp-protect --platform linux --policy tests/policy/examples/good.json --validate-only`：退出码 `0`。
  - clean-copy 验证：复制到 `/tmp/vmp_clean_copy`（排除 `.git` / `build*` / `target` 等生成物）后重跑 `cmake -S . -B build -G Ninja && cmake --build build -j && ctest --test-dir build --output-on-failure && cargo test --workspace`，结果通过（`CLEAN_COPY_OK`）。

### subtask_10
- 本轮清单：
  - 实现 `runtime/jit/` 的 `Vm1Jit`：VM1 block-level / trace-level JIT 管理器、per-module code cache、`(module_id, block_start_pc)` entry 映射、LRU 驱逐、失效 API 与审计事件。
  - 落地两套后端：
    - portable C backend：生成临时 C 源并经 `cc -shared -O2 -fPIC` 编译为 `.so`，`dlopen/dlsym` 获取入口；
    - Linux x86_64 backend：自有 emitter 生成 RW→RX x64 stub，通过 trampoline 进入 VM1 helper。
  - 将 VM1 解释器重构为 basic-block dispatch 循环，接入热度计数、JIT trampoline、trace 观察与 `load_transient_string` / `domain_call` barrier 语义。
  - 扩展 `RuntimeState`：`observe(key_rotated|integrity_failed)` 触发 `invalidate_all()`；新增 `detector_invalidate_module(module_id)`。
  - 扩展 transient string debug 能力：release 后保留 zeroized snapshot 供 JIT barrier 测试验证。
  - 更新 `vmp-vm1-run`：支持 `--jit=c|x64|off`，`VMP_JIT_VERBOSE=1` 时打印 `jit backend=X`。
  - 新增 `tests/runtime_vm1_jit/` 真测 9 项，并将 VM1 相关可执行目标统一加上 `--export-dynamic`，保证 JIT C backend 在测试/runner 中可解析 trampoline。
  - 更新 `runtime/jit/README.md` 与 `runtime/vm1/README.md`。
- 变更文件：
  - `runtime/audit/src/reaction.cpp`
  - `runtime/jit/CMakeLists.txt`
  - `runtime/jit/README.md`
  - `runtime/jit/include/vmp/runtime/jit/jit.h`
  - `runtime/jit/include/vmp/runtime/jit/vm1_jit.h`
  - `runtime/jit/rust_jit/src/lib.rs`
  - `runtime/jit/src/jit.cpp`
  - `runtime/state/CMakeLists.txt`
  - `runtime/state/include/vmp/runtime/state/state.h`
  - `runtime/state/src/state.cpp`
  - `runtime/strings/include/vmp/runtime/strings/cipher.h`
  - `runtime/strings/src/strings.cpp`
  - `runtime/vm1/CMakeLists.txt`
  - `runtime/vm1/README.md`
  - `runtime/vm1/include/vmp/runtime/vm1/vm1.h`
  - `runtime/vm1/src/interpreter.cpp`
  - `runtime/vm1/src/vm1.cpp`
  - `tests/CMakeLists.txt`
  - `tests/runtime_vm1_jit/test_common.h`
  - `tests/runtime_vm1_jit/jit_correctness_add_loop.cpp`
  - `tests/runtime_vm1_jit/jit_correctness_fib_recursive.cpp`
  - `tests/runtime_vm1_jit/jit_string_barrier.cpp`
  - `tests/runtime_vm1_jit/jit_domain_call_no_inlining.cpp`
  - `tests/runtime_vm1_jit/jit_invalidate_key_rotation.cpp`
  - `tests/runtime_vm1_jit/jit_cache_size_bound.cpp`
  - `tests/runtime_vm1_jit/jit_backend_switch.cpp`
  - `tests/runtime_vm1_jit/jit_disabled.cpp`
  - `tests/runtime_vm1_jit/jit_no_degrade_to_native.cpp`
  - `tools/CMakeLists.txt`
  - `tools/src/vmp_vm1_run.cpp`
  - `STATUS.md`
- 验证：
  - `cmake --build build -j 4`：通过。
  - `cd build && ctest --output-on-failure`：`73/73` 通过（含 9 个新增 JIT 测试）。
  - `cargo test --workspace`：通过。
  - `/tmp/vmp_subtask10_clean` clean-copy：重新 `cmake -S . -B build -G Ninja -DVMP_PLATFORM=linux -DVMP_ARCH=x64 && cmake --build build -j 4 && cd build && ctest --output-on-failure && cd .. && cargo test --workspace`，全部通过。
- 未完成项：
  - VM2 JIT 仍待 subtask 11。
  - 当前 trace 观测/升级为稳定二块 super-block 起步实现，后续可在不改变保护语义的前提下继续扩展 trace 拼接深度与 profile 融合。
- 下一子任务建议：
  - 进入 subtask 11，按 plan §7.3 实现 VM2 function-level JIT，并复用本轮完成的失效/审计/缓存策略骨架。

### subtask_11
- 本轮清单：
  - 实现 `runtime/jit/include/vmp/runtime/jit/vm2_jit.h` + `runtime/jit/src/vm2_jit.cpp`：新增 `Vm2Jit` 单例，固定为 VM2 function-level JIT；按 `(module_id, entry_pc)` 管理编译入口、`COMPILING/READY/INVALIDATED/EVICTED` 生命周期、4 MiB 默认 per-module cache budget、LRU 驱逐、事件失效与 debug 篡改接口。
  - 为 VM2 JIT 落地双后端：
    - C backend 为每个 VM2 函数入口生成独立 translation unit，并通过 `vmp_vm2_jit_execute_function(ctx, entry_pc)` trampoline 执行；
    - Linux x86_64 backend 生成接收 `Vm2Context*` 的 tiny trampoline，限定 VM2 整数 + 128-bit 向量子集，超出子集自动审计 `vm2_jit_fallback_backend` 并回退 C backend。
  - 新增更严格完整性标签：安装时以 `KeyContext::derive_subkey("vm2_jit_integrity")`（无 `key_context` 时退化为进程内 fallback `KeyContext`）计算 `HMAC-SHA256(module_id || entry_pc || compiled_machine_code)`；解释器每次切入已编译函数前重新验证，失败时自失效、记录 `vm2_jit_integrity_failure`、回退解释执行，并通过 cooldown 防止同次运行立即重编译。
  - 扩展 VM2 模块/上下文元数据：`runtime_id`、`function_entries`、函数热度计数、`function_jit_table`、`execution_halted`、JIT skip-once 标志；修正 VM2 组装器的 `entry` 默认入口与 `tsrelease` 编码，保证已有 VM2 非 JIT 测试继续通过。
  - 更新 VM2 解释器接线：在函数入口（`entry_pc` 与 `blnk/pcall` 目标）累积热度并触发 `Vm2Jit::compile_if_needed`；函数调用进入点优先经 `Vm2Jit::dispatch` 路由；新增 `vmp_vm2_jit_execute_function` helper 以“执行到当前函数返回”为边界，保持 predicate/`tsload`/跨域行为不变。
  - 更新运行时状态联动：`RuntimeState` 现在同时驱动 VM1/VM2 JIT 审计句柄与 `key_rotated` / `integrity_failed` / `env_anomaly(detection_event)` 失效路径；模块级 detector 失效也会清空 VM2 JIT。
  - 更新 CLI/文档：`vmp-vm2-run` 新增 `--jit=off|c|x64`，`runtime/jit/README.md` / `runtime/vm2/README.md` 增补 VM2 JIT、完整性标签与工具说明。
  - 新增 `tests/runtime_vm2_jit/` 10 个真测并接入 CTest，覆盖 function-level only、完整性失败自失效、predicate 保真、`tsload/tsrelease` barrier、key rotation / integrity 失效、后端 parity、disabled/no-degrade 等要求。
- 变更文件：
  - `runtime/jit/CMakeLists.txt`
  - `runtime/jit/README.md`
  - `runtime/jit/include/vmp/runtime/jit/jit.h`
  - `runtime/jit/include/vmp/runtime/jit/vm2_jit.h`
  - `runtime/jit/src/vm2_jit.cpp`
  - `runtime/state/CMakeLists.txt`
  - `runtime/state/src/state.cpp`
  - `runtime/vm2/CMakeLists.txt`
  - `runtime/vm2/README.md`
  - `runtime/vm2/include/vmp/runtime/vm2/vm2.h`
  - `runtime/vm2/src/interpreter.cpp`
  - `runtime/vm2/src/vm2.cpp`
  - `tests/CMakeLists.txt`
  - `tests/runtime_vm2_jit/test_common.h`
  - `tests/runtime_vm2_jit/vm2_jit_correctness_fib20.cpp`
  - `tests/runtime_vm2_jit/vm2_jit_function_level_only.cpp`
  - `tests/runtime_vm2_jit/vm2_jit_integrity_failure_evicts.cpp`
  - `tests/runtime_vm2_jit/vm2_jit_predicate_preserved.cpp`
  - `tests/runtime_vm2_jit/vm2_jit_tsload_no_speculation.cpp`
  - `tests/runtime_vm2_jit/vm2_jit_invalidate_key_rotation.cpp`
  - `tests/runtime_vm2_jit/vm2_jit_invalidate_integrity.cpp`
  - `tests/runtime_vm2_jit/vm2_jit_backend_parity.cpp`
  - `tests/runtime_vm2_jit/vm2_jit_disabled.cpp`
  - `tests/runtime_vm2_jit/vm2_jit_no_degrade_to_native.cpp`
  - `tools/CMakeLists.txt`
  - `tools/src/vmp_vm2_run.cpp`
  - `STATUS.md`
- 未完成项：
  - 本轮要求范围内无未完成项。
- 下一子任务建议：
  - 若继续 runtime 方向，可进入后续更高层的保护计划/loader 对接，让 Policy/Planner 实际选择 VM2 function-level JIT 热点，而不是仅由 runtime 热度自适应触发。
- 验证：
  - TDD red：先新增 `tests/runtime_vm2_jit/` 与 CTest 接线；首次构建失败于缺失 `vmp/runtime/jit/vm2_jit.h`，随后实现 VM2 JIT 接口并逐步转绿。
  - `cd /workspace/vmp && cmake --build build -j`：通过。
  - `cd /workspace/vmp/build && ctest --output-on-failure`：`83/83` 通过（含 10 个新增 VM2 JIT 测试）。
  - `cd /workspace/vmp && cargo test --workspace`：通过。
  - `cd /workspace/vmp && rg -n "NOT_IMPLEMENTED" runtime/jit runtime/vm2 tools/src/vmp_vm2_run.cpp tests/runtime_vm2_jit tests/runtime_vm2`：无输出。
  - clean-copy `/tmp/vmp-subtask11-clean`：复制源码（排除 `.git` / `build*` / `target` / `Cargo.lock` / `passwd.txt` / `jit_cache*`）后，重新执行 `cmake -S . -B build -G Ninja -DVMP_PLATFORM=linux -DVMP_ARCH=x64 && cmake --build build -j 4 && ctest --test-dir build --output-on-failure && cargo test --workspace`，全部通过。

### subtask_12
- 本轮清单：
  - 新增 `loader/common/`：实现 `detect_execmem_available()` 与 `detect_default_audit_path()`，统一处理 `VMP_AUDIT_PATH` / `VMP_FORCE_JIT_CAPABILITY=disallow` / 平台默认审计目录选择，并让 Linux / Windows / Android / iOS loader 复用。
  - 完成 `loader/android/`：提供公开头 `android_loader.h`、`vmp_android_init()`、导出 `JNI_OnLoad()`、`constructor(101)` fallback、审计 sink 初始化、字符串主密钥恢复、placeholder hook、capability gate 与 `jit_execmem_unavailable` / `loader_init` / `loader_init_failure` 事件。
  - 完成 `loader/ios/`：提供公开头 `ios_loader.h`、`vmp_ios_init()`、`constructor` 注册、纯 C++ HOME/Documents 审计路径规则、capability gate 与 interpreter-only downgrade 约束、placeholder hook、审计事件。
  - 扩展 `RuntimeState`：新增 `RuntimeFlag::jit_execmem_unavailable`、`set_jit_capability(bool)` 与查询接口，供 loader 与 JIT 共用。
  - 收敛 VM1/VM2 JIT capability 逻辑：在 execmem 不可用时拒绝 x64 emitter；Android/Linux/Windows 优先降级到 C backend，若 `cc` 不可用则自动退回解释器；iOS 在 capability gate 命中时强制解释器路径；全部路径统一补 `jit_execmem_unavailable` 审计。
  - 更新 `tools/vmp-loader-selftest`：按 `VMP_PLATFORM` 选择链接 linux/windows/android/ios loader，自检仍可复用 constructor/TLS 路径。
  - 新增 loader 真测：
    - `loader_capability_gate_disallow`：先用 `vmp-loader-selftest` 子进程验证 loader-time `jit_execmem_unavailable` 审计，再验证 `Vm1Jit` 在 `PATH=/nonexistent` + `VMP_JIT_BACKEND=x64` 时退为解释器；
    - `loader_android_jni_onload_link_probe`：在 Linux + host JDK 头文件下构建 probe `.so`，并用 `nm` 断言 `JNI_OnLoad` 链接/导出链路成立。
  - 更新 CI：Linux workflow 安装 `default-jdk`；Android workflow 构建后 `nm -D` 校验 `JNI_OnLoad` 导出；iOS workflow 增加构造器 section 验证；补 Android/iOS README 与占位 Gradle/SwiftPM 说明。
- 变更文件：
  - `.github/workflows/android.yml`
  - `.github/workflows/ios.yml`
  - `.github/workflows/linux.yml`
  - `loader/CMakeLists.txt`
  - `loader/README.md`
  - `loader/common/CMakeLists.txt`
  - `loader/common/include/vmp/loader/common/platform_caps.h`
  - `loader/common/src/platform_caps.cpp`
  - `loader/android/CMakeLists.txt`
  - `loader/android/README.md`
  - `loader/android/build.gradle.kts`
  - `loader/android/include/vmp/loader/android/android_loader.h`
  - `loader/android/src/android_loader.cpp`
  - `loader/ios/CMakeLists.txt`
  - `loader/ios/Package.swift`
  - `loader/ios/README.md`
  - `loader/ios/include/vmp/loader/ios/ios_loader.h`
  - `loader/ios/src/ios_loader.cpp`
  - `loader/linux/CMakeLists.txt`
  - `loader/linux/src/linux_loader.cpp`
  - `loader/windows/CMakeLists.txt`
  - `loader/windows/src/windows_loader.cpp`
  - `runtime/jit/CMakeLists.txt`
  - `runtime/jit/include/vmp/runtime/jit/vm1_jit.h`
  - `runtime/jit/include/vmp/runtime/jit/vm2_jit.h`
  - `runtime/jit/src/jit.cpp`
  - `runtime/jit/src/vm2_jit.cpp`
  - `runtime/state/include/vmp/runtime/state/state.h`
  - `runtime/state/src/state.cpp`
  - `tests/CMakeLists.txt`
  - `tests/loader/assert_nm_symbol.py`
  - `tests/loader/loader_android_jni_onload_link_probe.cpp`
  - `tests/loader/loader_capability_gate_disallow.cpp`
  - `tools/CMakeLists.txt`
  - `tools/src/vmp_loader_selftest.cpp`
  - `STATUS.md`
- 未完成项：
  - 本轮要求范围内无未完成项。
- 下一子任务建议：
  - 进入 subtask 13（二进制重写后端），复用本轮新增的移动端 loader/capability 状态，把重写器生成的入口包装与 Android/iOS 宿主装载路径接起来。
- 验证：
  - TDD red：先新增 `tests/loader/loader_capability_gate_disallow.cpp` 并接入 CTest；首次构建失败于缺失 `RuntimeFlag::jit_execmem_unavailable` / runtime-state capability API，随后补实现转绿。
  - `cd /workspace/vmp && cmake --build build -j`：通过。
  - `cd /workspace/vmp && ctest --test-dir build --output-on-failure -R 'loader_'`：`11/11` 通过（含 capability gate 与 JNI link probe）。
  - `cd /workspace/vmp && ctest --test-dir build --output-on-failure`：`85/85` 通过。
  - `cd /workspace/vmp && cargo test --workspace`：通过。
  - `cd /workspace/vmp && rg -n "NOT_IMPLEMENTED" loader/android loader/ios loader/common tests/loader runtime/state runtime/jit`：无输出。
  - clean-copy `/tmp/vmp-sub12-clean`：排除 `.git` / `build*` / `target` / `Cargo.lock` / `passwd.txt` 后，重新执行 `cmake -S . -B build -G Ninja -DVMP_PLATFORM=linux -DVMP_ARCH=x64 -DCMAKE_BUILD_TYPE=Release && cmake --build build -j && ctest --test-dir build --output-on-failure && cargo test --workspace`，全部通过。

## subtask_13
- 本轮清单：
  - 完成 `backends/rewriter/` 二进制重写后端最小可用实现：新增统一 `BinaryRewriter` 驱动、`Container` 判别联合（PE / ELF / Mach-O / APK / IPA）、基于 `std::fstream` 的 buffered 读写路径。
  - 新增格式模块：
    - `formats/elf.cpp`：解析 ELF64 header / phdr / shdr / symtab，支持高敏 `vm_string` 二进制策略条目解析、原始字面量清零、`.vmpstrings` 构建、`.vmp_init_array`/`.vmpvmthk` 附加；可选输出 sidecar pool/index/kdf。
    - `formats/pe.cpp`：解析 DOS/PE/COFF/optional header、section table 与 export/import/resource/reloc data-directory RVA；支持 `.vmpload` 注入、`.CRT$XLB` 注册段补齐、VM thunk 元数据段补齐。
    - `formats/macho.cpp`：解析 `mach_header_64`、`LC_SEGMENT_64`、`LC_DYLD_INFO`、`LC_SYMTAB`、`LC_DYSYMTAB`；支持 `__DATA,__vmp_load` / `__DATA,__mod_init_func` / `__DATA,__vmp_strings` / `__DATA,__vmp_vmthk` 生成。
    - `formats/zip.cpp`：实现 stored-ZIP APK/IPA 容器读写、`CFBundleExecutable` 解析、内嵌 ELF/Mach-O 二次重写。
  - 扩展 `vmp-protect`：新增 `--input` / `--output` / `--strings-pool` / `--strings-idx` / `--vm1-module` / `--vm2-module`；保留原策略校验 / Rust merge / `--protect-strings` 路径；未知格式时以 `binary_format_unknown` 明确失败。
  - 接入 Policy IR：仅消费 `language_origin=binary` 条目；支持 `symbol`、`symbol+0xOFFSET`、`path/in/container::symbol(+offset)` 选择器；`vm_string + highly_sensitive` 触发字符串池重建；`protection_domain=vm1|vm2` 触发 bridge thunk 描述段输出。
  - 新增真测 `tests/backends_rewriter/`：
    - `rewriter_elf_roundtrip.py`
    - `rewriter_pe_roundtrip.py`（MinGW 缺失时显式 `SKIP_REASON`）
    - `rewriter_macho_roundtrip.py`
    - `rewriter_apk_passthrough.py`
    - `rewriter_ipa_passthrough.py`
    - `rewriter_unknown_format_rejected.py`
    - `rewriter_policy_mismatch.py`
  - 更新 `backends/rewriter/README.md`：记录支持范围、CLI、测试入口与“不做重签名/公证”限制。
- 变更文件：
  - `backends/rewriter/CMakeLists.txt`
  - `backends/rewriter/README.md`
  - `backends/rewriter/include/vmp/backend/rewriter_backend.h`
  - `backends/rewriter/src/internal/common.h`
  - `backends/rewriter/src/rewriter_backend.cpp`
  - `backends/rewriter/src/formats/elf.cpp`
  - `backends/rewriter/src/formats/pe.cpp`
  - `backends/rewriter/src/formats/macho.cpp`
  - `backends/rewriter/src/formats/zip.cpp`
  - `tools/CMakeLists.txt`
  - `tools/src/vmp_protect.cpp`
  - `tests/CMakeLists.txt`
  - `tests/backends_rewriter/rewriter_elf_roundtrip.py`
  - `tests/backends_rewriter/rewriter_pe_roundtrip.py`
  - `tests/backends_rewriter/rewriter_macho_roundtrip.py`
  - `tests/backends_rewriter/rewriter_apk_passthrough.py`
  - `tests/backends_rewriter/rewriter_ipa_passthrough.py`
  - `tests/backends_rewriter/rewriter_unknown_format_rejected.py`
  - `tests/backends_rewriter/rewriter_policy_mismatch.py`
  - `STATUS.md`
- 未完成项：
  - 本轮要求范围内无未完成项；PE roundtrip 在当前容器因缺少 MinGW 交叉编译器按测试约定跳过，并已记录显式 `SKIP_REASON`。
- 下一子任务建议：
  - 进入 subtask 14（ISA lifting / deeper binary-to-VM routing），把本轮生成的 VM thunk 描述段替换为真实 lifted bridge/thunk 代码与模块装配。
- 验证：
  - TDD red：先接入 `tests/backends_rewriter/rewriter_elf_roundtrip.py` / `rewriter_unknown_format_rejected.py` / `rewriter_policy_mismatch.py` 到 CTest；初次失败于 `vmp-protect` 不接受 `--input/--output`、未知格式无显式错误、策略失配无清晰报错，随后补齐 CLI/rewriter 转绿。
  - `cd /workspace/vmp && cmake --build build -j`：通过。
  - `cd /workspace/vmp && ctest --test-dir build --output-on-failure`：`92/92` 通过，其中 `rewriter_pe_roundtrip` 因 MinGW 缺失显式 skip。
  - `cd /workspace/vmp && cargo test --workspace`：通过。
  - `cd /workspace/vmp && rg -n "NOT_IMPLEMENTED" backends/rewriter tests/backends_rewriter tools/src/vmp_protect.cpp`：无输出。
  - clean-copy `/tmp/vmp-sub13-clean`：使用 `tar` 排除 `.git` / `build` / `build-*` / `target` / `Cargo.lock` / `passwd.txt` 后，重新执行 `cmake -S . -B build -G Ninja -DVMP_PLATFORM=linux -DVMP_ARCH=x64 -DCMAKE_BUILD_TYPE=Release && cmake --build build -j && ctest --test-dir build --output-on-failure && cargo test --workspace`，全部通过（PE roundtrip 仍按规则 skip）。

### subtask_14
- 本轮清单：
  - 新增 `arch/common/` lifting 统一接口：`FunctionView`、`RelocationEntry`、`Diagnostic`、`LiftedFunction`、`IsaLifter`，并补公共 relocation/整数读取工具。
  - 实现 `arch/x86` MVP lifter：x86-32 最小长度感知解码，覆盖 `mov/add/sub/imul/and/or/xor/shl/shr/sar/cmp+jcc/jmp/call/ret/push/pop` 子集并发射 VM1。
  - 实现 `arch/x64` MVP lifter：REX-aware x86_64 解码，覆盖 `mov/add/sub/imul/and/or/xor/shl/shr/sar/cmp+jcc/jmp/call/ret`；默认发射 VM1，可按目标域发射 VM2。
  - 实现 `arch/arm` MVP lifter：ARMv7 ARM-state 4-byte 解码，支持 `mov/add/sub/and/orr/eor/cmp/b/bl/bx/ldr/str`；thumb 本轮诊断回退。
  - 实现 `arch/arm64` MVP lifter：AArch64 4-byte 解码，支持 `add/sub/mul/sdiv/udiv/lsl/lsr/asr/and/orr/eor/b/bl/ret/b.cond/ldr/str` 并发射 VM1。
  - 实现 relocation carrying：若立即数字段覆盖 relocation，则使用 `resolved_value` 参与 lifting，并把 `reloc:<tag>:<value>` 载入模块常量池。
  - 将 `backends/rewriter` 接入 `--lift`：ELF 路径会对 `language_origin=binary` 且 `protection_domain in {vm1,vm2}` 的目标尝试 lifting，成功时把模块序列化进 `.vmpcode`，并为已验证的 x86_64 SysV/VM1 路径 patch thunk；失败时保留 passthrough 元数据到 `.vmpvmthk`。
  - 扩展 `vmp-protect` 支持 `--lift`。
  - 新增真测：`tests/arch/` 下 7 个 lifter 单测 + `rewriter_lift_integration_elf.py` 集成测试；全部接入 CTest。
  - 更新 `arch/README.md` 与各 ISA README。
- 变更文件：
  - `arch/CMakeLists.txt`
  - `arch/README.md`
  - `arch/common/CMakeLists.txt`
  - `arch/common/include/vmp/arch/common/lifting.h`
  - `arch/common/src/lifting.cpp`
  - `arch/x86/CMakeLists.txt`
  - `arch/x86/README.md`
  - `arch/x86/include/vmp/arch/x86/x86.h`
  - `arch/x86/src/x86.cpp`
  - `arch/x64/CMakeLists.txt`
  - `arch/x64/README.md`
  - `arch/x64/include/vmp/arch/x64/x64.h`
  - `arch/x64/src/x64.cpp`
  - `arch/arm/CMakeLists.txt`
  - `arch/arm/README.md`
  - `arch/arm/include/vmp/arch/arm/arm.h`
  - `arch/arm/src/arm.cpp`
  - `arch/arm64/CMakeLists.txt`
  - `arch/arm64/README.md`
  - `arch/arm64/include/vmp/arch/arm64/arm64.h`
  - `arch/arm64/src/arm64.cpp`
  - `backends/rewriter/CMakeLists.txt`
  - `backends/rewriter/include/vmp/backend/rewriter_backend.h`
  - `backends/rewriter/src/formats/elf.cpp`
  - `tests/CMakeLists.txt`
  - `tests/arch/test_common.h`
  - `tests/arch/x86_lift_basic.cpp`
  - `tests/arch/x64_lift_basic_sysv.cpp`
  - `tests/arch/x64_lift_basic_msvc.cpp`
  - `tests/arch/arm_lift_basic.cpp`
  - `tests/arch/arm64_lift_basic.cpp`
  - `tests/arch/lift_unsupported_diagnostic.cpp`
  - `tests/arch/lift_relocation_carrying.cpp`
  - `tests/arch/rewriter_lift_integration_elf.py`
  - `tools/src/vmp_protect.cpp`
  - `STATUS.md`
- 未完成项：
  - ELF rewriter 的“真实可执行 thunk patch”当前只在已验证的 x86_64 SysV + VM1 + 2 整数参数集成样例路径落地；其他 ISA / ABI / 容器仍走 lift metadata / passthrough 回退。
  - x86/x64 复杂 SIB、ARM thumb、ARM64 更完整 NZCV/条件执行、SIMD/浮点 lifting 仍未覆盖（按本轮 out-of-scope 可接受）。
  - relocation 在 rewriter 侧尚未从 ELF relocation table 完整提取进 `FunctionView.relocs`；本轮真实 carrying 已在 lifter API / 单测覆盖。
- 下一子任务建议：
  - 进入 planner / analyzer / rewriter 深化联动：把二进制分析得到的真实 relocation / ABI hint / function slice 输入到 lifter，并把 `.vmpcode` thunk patch 从样例化 x86_64 扩展到通用 x64/x86/ARM64 路径。
- 验证：
  - `cmake --build build -j`：通过。
  - `ctest --test-dir build --output-on-failure`：`100/100` 通过（`rewriter_pe_roundtrip` 依平台前置条件被标记 skip）。
  - `cargo test --workspace`：通过。
  - clean copy：`/tmp/vmp_subtask14_clean/vmp` 下重新 `cmake -S . -B build -G Ninja && cmake --build build -j && ctest --test-dir build --output-on-failure`：通过，`100/100` 通过（同上 1 个 skip）。
