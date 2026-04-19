# runtime/vm1

- 对应 plan：§6.1、§6.3、§6.4、§9、§16
- 当前状态：VM1 ISA / 寄存器型解释器 / VM1↔native 最小跨域 ABI / 文本汇编器 / runner 已实现

## VM1 寄存器模型

- 通用寄存器：`vr0..vr31`（`uint64_t`）
- 浮点寄存器：`vfr0..vfr3`（`double`）
- 控制寄存器：`pc`、`sp`
- flags：`zero` / `neg` / `carry` / `overflow`
- 私有线程栈：默认 `64 KiB`

## 调用约定

- 标量参数优先经 `vr0..vr7` 传递。
- 超过 8 个的整型参数会复制到 VM 私有栈的当前帧溢出区，callee 通过 `[sp+0]`、`[sp+8]`… 访问。
- `call` 保存调用者寄存器/flags/返回地址，跳到目标 `pc`。
- `ret` / `domain_ret` 恢复上一帧，仅保留返回值：整数在 `vr0`，浮点在 `vfr0`。

## 字节码格式

固定头：

- `magic[4] = "VM1B"`
- `version: u16`（legacy identity 模块为 `3`；启用 opcode encryption 的当前格式为 `4`）
- `flags: u16`
- `entry_pc: u32`
- `const_count: u32`
- `crc32: u32`（覆盖原始 on-disk body）
- `opcode_map_seed[16]`（仅 `version=4`）
- `code_bytes[code_size]`
- `const_pool[const_count]`
  - `kind: u8`
  - `payload_size: u32`
  - `payload[payload_size]`

当前 `const_pool` 已实现：

- `kind=1`: transient string（旧 `.const string` 兼容路径；本轮新增 `StringPool` 外部加密池）

## ISA 列表

### 系统
- `nop`
- `breakpoint`
- `trap <status>`

### 立即数 / 数据
- `ldi64 <vr>, <signed_i64>`
- `ldi_u64 <vr>, <u64>`
- `ldi_f64 <vfr>, <double>`
- `mov <dst>, <src>`
- `load_transient_string <vr>, <string_id>`
- `release_transient_string <vr>`
- DSL alias: `load_tstr <vr>, &sid42` / `release_tstr <vr>`

### 算术 / 位运算
- `add/sub/mul/div/mod <dst>, <lhs>, <rhs>`
- `and/or/xor <dst>, <lhs>, <rhs>`
- `shl/shr/sar <dst>, <lhs>, <rhs>`
- `neg <dst>, <src>`
- `not <dst>, <src>`

### 内存
- `load_mem8/16/32/64 <dst>, [<base>+<offset>]`
- `store_mem8/16/32/64 [<base>+<offset>], <src>`
- `<base>` 可为 `sp` 或任意 `vrN`

### 控制流
- `jmp <target>`
- `jeq/jne/jlt/jle/jgt/jge <lhs>, <rhs>, <target>`
- `call <target>[, <arg_count>]`
- `ret`

### 跨域
- `domain_call <domain>, <entry_id>, <int_count>[, <float_count>[, <opaque_count>]]`
- `domain_ret`
- `domain ∈ { native, vm1, vm2 }`
- `domain_call` 返回：`vr0 = ret_int`，`vfr0 = ret_float`，`vr31 = status`

## DSL 语法

- 标签：`label:`
- 跳转标签引用：`@label`
- 常量池：`.const string <id> "text"`
- 示例：

```text
entry:
  ldi_u64 vr0, 20
  call @fib, 1
  ret
fib:
  ldi_u64 vr1, 2
  jlt vr0, vr1, @base
  mov vr2, vr0
  ldi_u64 vr3, 1
  sub vr0, vr2, vr3
  call @fib, 1
  mov vr4, vr0
  ldi_u64 vr3, 2
  sub vr0, vr2, vr3
  call @fib, 1
  add vr0, vr0, vr4
  ret
base:
  ret
```

## 跨域 ABI

头文件：`include/vmp/runtime/bridge/bridge.h`

- `enum class Domain { native, vm1, vm2 }`
- `struct DomainCallArgs { vector<uint64_t> ints; vector<double> floats; vector<void*> opaque; }`
- `struct DomainCallResult { uint64_t ret_int; double ret_float; int status; }`
- `BridgeRegistry::register_native(id, fn)`
- `BridgeRegistry::register_vm1(id, Vm1Module*)`
- `BridgeRegistry::call(target, id, args, max_depth=64)`

行为：

- `max_depth` 超限抛 `BridgeException`
- 目标域抛出的普通异常会映射为 `status < 0`，并在 `last_domain_exception()` 中保留 `DomainCallException`
- VM1 解释器中的 `domain_call` 将 `BridgeException` 映射为 `VmException(VmTrapCode::bridge_error)`

## audit 集成

- `breakpoint` → 追加 `vm1_breakpoint`
- `load_tstr` 通过关联 `StringPool` 进行瞬时解密；未显式 `release_tstr` 时在 return/exception unwind 自动擦除
- `trap` → 追加 `vm1_trap`
- `unknown opcode` → 追加 `vm1_unknown_opcode`
- `stack overflow` → 追加 `vm1_stack_overflow`

以上统一走 `audit_only`，不触发 delayed-exit。

## CLI

- 汇编：`build/tools/vmp-vm1-asm input.vm1s output.vm1`
- 运行：`build/tools/vmp-vm1-run [--audit-path audit.log] [--string-pool pool.bin --string-idx pool.idx.json --key-env VMP_STRING_MASTER_KEY] [--native-print-string <id>] module.vm1 [args...]`

## Opcode encryption（subtask 23 / Owner Override #2）

- 该功能仅用于比赛要求的 CTF crackme 防护路径；授权来源为 `AGENTS.md` 中 2026-04-19 的 Owner Override #2，作用域仅限 VM dispatch / codegen / trampoline 路径。
- `vmp-vm1-asm` 默认开启 opcode encryption；`--no-encrypt-opcodes` 输出 identity 映射；`--opcode-seed <32 hex>` 或环境变量 `VMP_OPCODE_MAP_SEED` 可复现实验结果。
- `VMP_FLAG_OPCODE_ENCRYPTED = 0x0001` 置位时，assembler 会把 canonical opcode 通过 `OpcodeCryptor` 映射成按模块随机化的 on-disk opcode word；解释器在 load 时校验隐藏 const-pool marker 后再解码回 canonical 内存代码。
- 载入时若 `opcode_map_seed` 推导出的 marker 与模块携带值不匹配，会审计 `opcode_map_invalid` 并拒绝运行。

## JIT 集成（subtask 10）

- `Vm1Interpreter` 在 basic-block dispatch 前会累积 block 热度，并通过 `Vm1Jit` 查询/触发按需编译。
- 首次执行 block 时只编译不跳转；第二次开始若 entry 已激活，则通过 `JitEntry(Vm1Context*) -> next_pc` 回到解释主循环。
- 热块默认在命中 `64` 次后记录稳定 trace，稳定 `16` 次后升级为 trace super-block。
- `load_transient_string` / `release_transient_string`、`domain_call` / `domain_ret` 保持 JIT barrier 语义，不做明文缓存或跨域常量传播。
- `Vm1Module` 维护 per-block 热度计数；`Vm1Context` 提供 transient release debug snapshot，供字符串 barrier/JIT 测试验证。
