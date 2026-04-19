# runtime/vm2

- 对应 plan：§6.2 / §6.3 / §6.4 / §9 / §16
- 当前状态：VM2 独立 ISA、解释器、跨域桥接、字符串句柄、函数级 JIT、CLI 工具已接线

## ISA 摘要
- 容器头：`VMP2` magic、version、flags、entry_pc、code_size、const_pool_size、crc32、`opcode_map_seed[16]`（`version=4`）、`key_context_id[16]`
- 寄存器：
  - `r0..r31`：64-bit 整数寄存器
  - `q0..q15`：128-bit 向量寄存器（两条 `u64` lane）
  - `d0..d7`：double 寄存器
  - `p0..p7`：谓词寄存器
  - `pc/sp/lr`
- 栈：默认 128 KiB、16-byte 对齐、向下增长
- 调用：`blnk` 写入 `lr`，`bret` 通过 `lr` 返回；溢出整数参数落栈

## 指令族
- 整数：`iadd/isub/imul/idiv/imod/iand/ior/ixor/ishl/ishr/isar/ineg/inot`
- 向量：`vadd128/vsub128/vmul128/vxor128`
- 访存：`ildimm/vldimm/imov/imemld8/16/32/64/imemst8/16/32/64/vmemld128/vmemst128`
- 控制：`jmp/jp/jnp/blnk/bret/pcall/pret`
- 系统：`nop/brk/ftrap`
- 跨域：`xcall/xret`
- 字符串：`tsload/tsrelease`

## 跨域 ABI
复用 `runtime/vm1/include/vmp/runtime/bridge/bridge.h`：
- `native ↔ vm2`
- `vm1 ↔ vm2`
- `vm2 ↔ vm2`
- 默认 `max_depth = 64`

## 字符串句柄
- `tsload` 通过 `StringPool` 解密瞬时字符串并返回 VM2 handle
- `tsrelease` 显式释放 handle
- `bret/xret/异常 unwind` 自动清理未释放 handle
- 若模块 `key_context_id` 非零，`Vm2Context` 当前 key id 不匹配会触发 `string_pool_error`

## JIT 集成
- 入口：`runtime/jit/include/vmp/runtime/jit/vm2_jit.h`
- 粒度：仅函数级；热度来自函数入口（`entry_pc` 与 `blnk/pcall` 目标）
- 默认阈值：`32` 次函数入口命中后尝试编译
- 缓存：每模块默认 `4 MiB`
- 完整性：每个已编译函数都带 `HMAC-SHA256(module_id || entry_pc || compiled_machine_code)` 标签；解释器每次跳入 trampoline 前验证，不通过则自失效并回退解释执行
- 失效：`key_rotated` / `integrity_failed` / detector 事件 / 模块 key-context 变化都会清空对应 VM2 JIT 项
- 约束：不消除 predicate 更新；`tsload/tsrelease` 仍是 barrier；不把 VM2 函数入口降级成 native 逻辑

## DSL / 工具
- 汇编：`runtime/vm2/asm/`
- 组装：`build/tools/vmp-vm2-asm input.vm2s output.vm2`
- 运行：`build/tools/vmp-vm2-run [--jit=off|c|x64] [--audit-path path] [--string-pool ... --string-idx ... --key-env ENV] module.vm2 [args...]`

## Opcode encryption（subtask 23 / Owner Override #2）

- 该功能仅用于比赛要求的 CTF crackme 防护路径；授权来源为 `AGENTS.md` 中 2026-04-19 的 Owner Override #2，作用域仅限 VM dispatch / codegen / trampoline 路径。
- `vmp-vm2-asm` 默认开启 opcode encryption；`--no-encrypt-opcodes` 输出 identity 映射；`--opcode-seed <32 hex>` 或环境变量 `VMP_OPCODE_MAP_SEED` 可复现实验结果。
- `VMP_FLAG_OPCODE_ENCRYPTED = 0x0001` 置位时，assembler 会把 canonical opcode 通过 `OpcodeCryptor` 映射成按模块随机化的 on-disk opcode word；loader 在校验隐藏 const-pool marker 后恢复 canonical 内存代码，再交给解释器/JIT 使用。
- `key_context_id` 继续作为模块级 HKDF salt；若 `opcode_map_seed` 推导出的 marker 不匹配，会审计 `opcode_map_invalid` 并拒绝运行。
