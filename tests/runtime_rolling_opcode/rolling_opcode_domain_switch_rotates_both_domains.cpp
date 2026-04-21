#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_rolling_opcode;
namespace bridge = vmp::runtime::bridge;
namespace roll1 = vmp::runtime::cryptor::vm1;
namespace roll2 = vmp::runtime::cryptor::vm2;

int main() {
  const auto audit_path = temp_path("rolling_domain_switch", ".log");
  vmp::runtime::audit::AuditWriter writer(audit_path);
  vmp::runtime::cryptor::RollingOpcodeRegistry::instance().set_audit_writer(&writer);

  bridge::BridgeRegistry registry;
  auto vm2_module = make_vm2_module(R"(
entry:
  ildimm r1, 10
  iadd r0, r0, r1
  xret
)", bytes16(0x51), bytes16(0x61));
  registry.register_vm2(200, &vm2_module);

  auto vm1_module = make_vm1_module(R"(
entry:
  domain_call vm2, 200, 1
  ret
)", 0x71);

  const auto before_vm1 = roll1::current_epoch_id(vm1_module);
  const auto before_vm2 = roll2::current_epoch_id(vm2_module);
  require(run_vm1(vm1_module, &registry) == 10u, "vm1->vm2 result mismatch");
  writer.flush();

  require(roll1::current_epoch_id(vm1_module) > before_vm1, "vm1 epoch not bumped on domain switch");
  require(roll2::current_epoch_id(vm2_module) > before_vm2, "vm2 epoch not bumped on domain switch");
  const auto log = read_all(audit_path);
  require(log.find("reason=domain_switch") != std::string::npos, "missing domain_switch audit reason");
  std::cout << "rolling_opcode_domain_switch_rotates_both_domains OK\n";
}
