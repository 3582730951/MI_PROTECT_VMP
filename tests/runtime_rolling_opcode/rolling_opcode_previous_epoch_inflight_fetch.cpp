#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_rolling_opcode;
namespace roll1 = vmp::runtime::cryptor::vm1;

int main() {
  auto module = make_vm1_module(R"(
entry:
  ldi_u64 vr0, 0x1122334455667788
  ret
)", 0x21);
  roll1::ensure_registered(module);
  const auto epoch0 = roll1::current_epoch_id(module);
  auto scope = roll1::begin_dispatch(module);
  roll1::notify_integrity_event(module);
  require(roll1::current_epoch_id(module) == epoch0 + 1u, "integrity event should bump epoch");
  require(roll1::fetch_byte(module, 0u) == module.code[0], "old in-flight fetch should decode canonical opcode byte 0");
  require(roll1::fetch_byte(module, 1u) == module.code[1], "old in-flight fetch should decode canonical opcode byte 1");
  scope = {};
  auto scope_new = roll1::begin_dispatch(module);
  require(roll1::fetch_byte(module, 0u) == module.code[0], "new dispatch should decode canonical opcode byte 0");
  require(roll1::fetch_byte(module, 1u) == module.code[1], "new dispatch should decode canonical opcode byte 1");
  std::cout << "rolling_opcode_previous_epoch_inflight_fetch OK\n";
}
