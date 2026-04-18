#include "test_common.h"
#include "../runtime_vm1_jit/test_common.h"

#include <chrono>
#include <iostream>
#include <thread>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/jit/vm1_jit.h>
#include <vmp/runtime/state/state.h>
#include <vmp/runtime/strings/keyctx.h>
#include <vmp/runtime/vm1/vm1.h>

using namespace vmp::tests::runtime_state_machine;
namespace vm1jit = vmp::tests::runtime_vm1_jit;

int main() {
  const auto audit_path = temp_path("terminating_wipe", ".log");
  vmp::runtime::audit::AuditWriter writer(audit_path);
  auto& state = vmp::runtime::state::RuntimeState::instance();
  state.shutdown();
  vmp::runtime::state::RuntimeConfig cfg{"linux", "terminating", false, 50};
  cfg.exit_fn = [](int) {};
  state.init_once(&writer, cfg);

  vm1jit::EnvGuard backend_guard("VMP_JIT_BACKEND", vm1jit::host_supports_x64_backend() ? "x64" : "c");
  auto& jit = vmp::runtime::jit::Vm1Jit::instance();
  jit.reset_for_tests();
  jit.set_audit_writer(&writer);
  auto module = vmp::runtime::vm1::assemble_module_text("ldi_u64 vr0, 9\nret\n");
  for (int i = 0; i < 3; ++i) {
    vmp::runtime::vm1::Vm1Context ctx(module);
    vmp::runtime::vm1::Vm1Interpreter interp;
    (void)interp.execute(ctx);
  }
  require(jit.has_entry(module.id(), module.entry_pc), "expected vm1 jit entry before termination");

  auto key = vm1jit::fixed_key_context();
  (void)key.derive_subkey("vm1_jit_integrity");
  require(!key.debug_cached_subkeys_zeroed(), "key slots should not be zeroed yet");
  state.observe(vmp::runtime::state::RuntimeEventKind::shutdown_requested);
  std::this_thread::sleep_for(std::chrono::milliseconds(120));
  writer.flush();
  require(!jit.has_entry(module.id(), module.entry_pc), "jit cache should be cleared on terminating");
  require(vmp::runtime::strings::debug_all_key_context_slots_zeroed(), "key slots should be wiped");
  const auto log = read_all(audit_path);
  require(log.find("terminating_done") != std::string::npos, "missing terminating_done");
  std::cout << "terminating_invalidates_jit_and_wipes_keys OK\n";
}
