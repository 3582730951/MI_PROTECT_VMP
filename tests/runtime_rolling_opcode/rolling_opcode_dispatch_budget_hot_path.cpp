#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_rolling_opcode;
namespace roll1 = vmp::runtime::cryptor::vm1;

int main() {
  EnvGuard backend_guard("VMP_JIT_BACKEND", "off");
  const auto audit_path = temp_path("rolling_dispatch_budget", ".log");
  vmp::runtime::audit::AuditWriter writer(audit_path);
  vmp::runtime::cryptor::RollingOpcodeRegistry::instance().set_audit_writer(&writer);

  auto module = make_vm1_module(R"(
entry:
  ldi_u64 vr0, 0
  ldi_u64 vr1, 262144
  ldi_u64 vr2, 1
  ldi_u64 vr3, 0
loop:
  add vr0, vr0, vr2
  sub vr1, vr1, vr2
  jne vr1, vr3, @loop
  ret
)", 0x41);

  require(run_vm1(module) == 262144u, "vm1 hot-path result mismatch");
  require(roll1::current_epoch_id(module) >= 1u, "dispatch budget fallback did not bump epoch");
  writer.flush();
  const auto log = read_all(audit_path);
  require(log.find("reason=dispatch_budget") != std::string::npos, "missing dispatch_budget audit reason");
  std::cout << "rolling_opcode_dispatch_budget_hot_path OK\n";
}
