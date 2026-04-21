#include <cstdint>
#include <iostream>

#include <vmp/runtime/vm1/vm1.h>
#include <vmp/runtime/vm2/vm2.h>

int main() {
  auto vm1_module = vmp::runtime::vm1::assemble_module_text("ldi_u64 vr0, 7\nldi_u64 vr1, 5\nadd vr0, vr0, vr1\nret\n");
  auto vm2_module = vmp::runtime::vm2::assemble_module_text("ildimm r0, 7\nildimm r1, 5\niadd r0, r0, r1\nbret\n");

  vmp::runtime::vm1::Vm1Context vm1_ctx(vm1_module);
  vmp::runtime::vm2::Vm2Context vm2_ctx(vm2_module);
  const auto vm1_ret = vmp::runtime::vm1::Vm1Interpreter{}.execute(vm1_ctx).ret_int;
  const auto vm2_ret = vmp::runtime::vm2::Vm2Interpreter{}.execute(vm2_ctx).ret_int;
  std::cout << "vm1=" << vm1_ret << " vm2=" << vm2_ret << '\n';
  return vm1_ret == 12 && vm2_ret == 12 ? 0 : 1;
}
