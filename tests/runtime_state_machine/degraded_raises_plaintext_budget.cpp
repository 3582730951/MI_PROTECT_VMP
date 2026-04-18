#include "test_common.h"
#include "../runtime_vm1_jit/test_common.h"

#include <iostream>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/audit/reaction.h>
#include <vmp/runtime/state/state.h>

using namespace vmp::tests::runtime_state_machine;
namespace vm1jit = vmp::tests::runtime_vm1_jit;

int main() {
  const auto audit_path = temp_path("plaintext_budget", ".log");
  vmp::runtime::audit::AuditWriter writer(audit_path);
  vmp::runtime::audit::ReactionDispatcher dispatcher(writer, vmp::runtime::audit::ReactionPolicy::audit_only);
  auto& state = vmp::runtime::state::RuntimeState::instance();
  state.shutdown();
  state.init_once(&writer, {"linux", "budget", false, 5000});
  state.observe(vmp::runtime::state::RuntimeEventKind::integrity_failed, {"region_x", "region=region_x"});
  auto pool = vm1jit::make_string_pool({{1, "secret"}});
  pool->set_audit_dispatcher(&dispatcher);
  bool threw = false;
  try {
    (void)pool->decrypt(1);
  } catch (...) {
    threw = true;
  }
  writer.flush();
  require(threw, "decrypt should fail in degraded mode");
  const auto log = read_all(audit_path);
  require(log.find("plaintext_budget_violation") != std::string::npos, "missing plaintext_budget_violation");
  std::cout << "degraded_raises_plaintext_budget OK\n";
}
