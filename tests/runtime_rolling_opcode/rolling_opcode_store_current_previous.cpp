#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_rolling_opcode;
namespace roll1 = vmp::runtime::cryptor::vm1;

int main() {
  auto module = make_vm1_module(R"(
entry:
  ldi_u64 vr0, 7
  ret
)");
  roll1::ensure_registered(module);
  const auto epoch0 = roll1::current_epoch_id(module);
  const auto storage0 = roll1::debug_forward_storage(module);
  roll1::notify_key_rotation(module, vec16(0x90));
  require(roll1::current_epoch_id(module) == epoch0 + 1u, "epoch did not advance");
  require(roll1::previous_epoch_id(module).has_value(), "previous epoch missing");
  require(*roll1::previous_epoch_id(module) == epoch0, "wrong previous epoch id");
  require(storage0 != roll1::debug_forward_storage(module), "forward storage should be re-encrypted");
  std::cout << "rolling_opcode_store_current_previous OK\n";
}
