#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_rolling_opcode;
namespace roll1 = vmp::runtime::cryptor::vm1;

int main() {
  auto& jit = vmp::runtime::jit::Vm1Jit::instance();
  jit.reset_for_tests();

  auto module = make_vm1_module(R"(
entry:
  ldi_u64 vr0, 7
  ret
)", 0x81);

  {
    EnvGuard backend_guard("VMP_JIT_BACKEND", "off");
    require(run_vm1(module) == 7u, "interpreter baseline failed");
  }

  {
    EnvGuard backend_guard("VMP_JIT_BACKEND", "c");
    vmp::runtime::jit::Vm1Jit::instance().compile_if_needed(module, module.entry_pc, 1u);
  }
  require(jit.module_entry_count(module.id()) > 0u, "expected compiled vm1 jit entries");
  roll1::notify_key_rotation(module, vec16(0xD0));
  require(jit.module_entry_count(module.id()) == 0u, "vm1 jit cache should be fully evicted on epoch bump");
  {
    EnvGuard backend_guard("VMP_JIT_BACKEND", "c");
    vmp::runtime::jit::Vm1Jit::instance().compile_if_needed(module, module.entry_pc, 1u);
  }
  require(jit.has_entry(module.id(), module.entry_pc), "vm1 jit should recompile for the new epoch");
  {
    EnvGuard backend_guard("VMP_JIT_BACKEND", "off");
    require(run_vm1(module) == 7u, "post-rotation vm1 run failed");
  }
  std::cout << "rolling_opcode_vm1_jit_evicts_on_epoch_bump OK\n";
}
