#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_rolling_opcode;
namespace roll2 = vmp::runtime::cryptor::vm2;

int main() {
  auto key_context = fixed_key_context_ptr();
  auto module = make_vm2_module(R"(
entry:
  ildimm r1, 20
  iadd r0, r0, r1
  bret
)", bytes16(0x91), bytes16(0xA1));
  auto key_probe = vmp::runtime::vm2::Vm2Context(module);
  key_probe.key_context = key_context;
  module.key_context_id = key_probe.current_key_context_id();

  auto& jit = vmp::runtime::jit::Vm2Jit::instance();
  jit.reset_for_tests();
  {
    EnvGuard backend_guard("VMP_JIT_BACKEND", "off");
    const auto result = run_vm2(module, 1, {1}, nullptr, key_context);
    require(result.ret_int == 21u, "vm2 interpreter baseline mismatch");
  }

  {
    EnvGuard backend_guard("VMP_JIT_BACKEND", "x64");
    vmp::runtime::vm2::Vm2Context context(module);
    context.key_context = key_context;
    context.r[0] = 1u;
    (void)jit.compile_if_needed(module, context, module.entry_pc, 64u);
  }
  require(jit.module_entry_count(module.id()) > 0u, "expected compiled vm2 jit entries");
  const auto epoch0 = roll2::current_epoch_id(module);
  roll2::notify_key_rotation(module, vec16(0xE0));
  require(roll2::current_epoch_id(module) == epoch0 + 1u, "vm2 epoch should advance after key rotation");
  require(jit.module_entry_count(module.id()) == 0u, "vm2 jit cache should evict old epoch-tagged entries");
  {
    EnvGuard backend_guard("VMP_JIT_BACKEND", "x64");
    vmp::runtime::vm2::Vm2Context context(module);
    context.key_context = key_context;
    context.r[0] = 1u;
    (void)jit.compile_if_needed(module, context, module.entry_pc, 64u);
  }
  require(jit.module_entry_count(module.id()) > 0u, "vm2 jit should recompile after epoch rotation");
  require(jit.entry_epoch_id(module.id(), module.entry_pc) == roll2::current_epoch_id(module), "vm2 jit entry epoch mismatch");
  {
    EnvGuard backend_guard("VMP_JIT_BACKEND", "off");
    const auto rerun = run_vm2(module, 1, {1}, nullptr, key_context);
    require(rerun.ret_int == 21u, "vm2 rerun mismatch");
  }
  std::cout << "rolling_opcode_vm2_jit_epoch_tag_evict OK\n";
}
