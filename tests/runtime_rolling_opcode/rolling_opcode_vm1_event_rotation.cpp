#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_rolling_opcode;
namespace roll1 = vmp::runtime::cryptor::vm1;

int main() {
  const auto audit_path = temp_path("rolling_vm1_events", ".log");
  vmp::runtime::audit::AuditWriter writer(audit_path);
  vmp::runtime::cryptor::RollingOpcodeRegistry::instance().set_audit_writer(&writer);

  auto module = make_vm1_module(R"(
entry:
  ldi_u64 vr0, 42
  ret
)", 0x31);

  require(run_vm1(module) == 42u, "initial vm1 run failed");
  const auto epoch0 = roll1::current_epoch_id(module);
  roll1::notify_key_rotation(module, vec16(0xA0));
  require(run_vm1(module) == 42u, "vm1 run after key rotation failed");
  roll1::notify_integrity_event(module);
  require(run_vm1(module) == 42u, "vm1 run after integrity event failed");
  writer.flush();

  require(roll1::current_epoch_id(module) == epoch0 + 2u, "expected two epoch bumps");
  const auto log = read_all(audit_path);
  require(log.find("opcode_epoch_rotated") != std::string::npos, "missing opcode_epoch_rotated audit");
  require(log.find("reason=key_rotation") != std::string::npos, "missing key_rotation audit reason");
  require(log.find("reason=integrity_event") != std::string::npos, "missing integrity_event audit reason");
  std::cout << "rolling_opcode_vm1_event_rotation OK\n";
}
