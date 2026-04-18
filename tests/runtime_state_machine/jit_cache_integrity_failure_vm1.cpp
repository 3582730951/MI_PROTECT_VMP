#include "test_common.h"
#include "../runtime_vm1_jit/test_common.h"

#include <iostream>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/jit/vm1_jit.h>
#include <vmp/runtime/state/state.h>
#include <vmp/runtime/vm1/vm1.h>

using namespace vmp::tests::runtime_state_machine;
namespace vm1jit = vmp::tests::runtime_vm1_jit;

int main() {
  const auto audit_path = temp_path("vm1_jit_integrity", ".log");
  vmp::runtime::audit::AuditWriter writer(audit_path);
  auto& state = vmp::runtime::state::RuntimeState::instance();
  state.shutdown();
  state.init_once(&writer, {"linux", "test", false, 2000});

  vm1jit::EnvGuard backend_guard("VMP_JIT_BACKEND", vm1jit::host_supports_x64_backend() ? "x64" : "c");
  auto& jit = vmp::runtime::jit::Vm1Jit::instance();
  jit.reset_for_tests();
  jit.set_audit_writer(&writer);

  auto module = vmp::runtime::vm1::assemble_module_text("ldi_u64 vr0, 7\nret\n");
  for (int i = 0; i < 3; ++i) {
    vmp::runtime::vm1::Vm1Context ctx(module);
    vmp::runtime::vm1::Vm1Interpreter interp;
    require(interp.execute(ctx).ret_int == 7, "initial execution failed");
  }
  require(jit.has_entry(module.id(), module.entry_pc), "expected compiled jit entry");
  require(jit.debug_patch_code_byte(module.id(), module.entry_pc, 0, 0x90), "failed to tamper jit entry");
  vmp::runtime::vm1::Vm1Context ctx(module);
  vmp::runtime::vm1::Vm1Interpreter interp;
  require(interp.execute(ctx).ret_int == 7, "fallback execution failed");
  writer.flush();
  const auto log = read_all(audit_path);
  require(log.find("jit_cache_integrity_failure") != std::string::npos, "missing vm1 jit integrity audit");
  require(!jit.has_entry(module.id(), module.entry_pc), "entry should be evicted after integrity failure");
  std::cout << "jit_cache_integrity_failure_vm1 OK\n";
}
