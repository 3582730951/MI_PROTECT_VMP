#pragma once

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <vmp/arch/common/lifting.h>
#include <vmp/runtime/vm1/vm1.h>
#include <vmp/runtime/vm2/vm2.h>

namespace vmp::tests::arch {

inline void require(bool cond, const std::string& msg) {
  if (!cond) throw std::runtime_error(msg);
}

inline std::uint64_t run_vm1_abi(const vmp::runtime::vm1::Vm1Module& module,
                                 vmp::arch::common::CallingConvention cc,
                                 const std::vector<std::uint64_t>& args) {
  using namespace vmp::runtime::vm1;
  Vm1Context ctx(module);
  switch (cc) {
    case vmp::arch::common::CallingConvention::cdecl_x86:
    case vmp::arch::common::CallingConvention::stdcall_x86: {
      ctx.sp = 64;
      ctx.set_stack_top(128);
      ctx.write_memory<std::uint32_t>(ctx.sp + 0, 0);
      for (std::size_t i = 0; i < args.size(); ++i) {
        ctx.write_memory<std::uint32_t>(ctx.sp + 4 + static_cast<std::uint64_t>(i * 4), static_cast<std::uint32_t>(args[i]));
      }
      ctx.vr[4] = ctx.sp;
      break;
    }
    case vmp::arch::common::CallingConvention::sysv_x64:
    case vmp::arch::common::CallingConvention::msvc_x64:
    case vmp::arch::common::CallingConvention::aapcs32:
    case vmp::arch::common::CallingConvention::aapcs64:
      for (std::size_t i = 0; i < args.size() && i < 8; ++i) ctx.vr[i] = args[i];
      break;
  }
  Vm1Interpreter interp;
  return interp.execute(ctx).ret_int;
}

inline std::uint64_t run_vm2_abi(const vmp::runtime::vm2::Vm2Module& module,
                                 vmp::arch::common::CallingConvention cc,
                                 const std::vector<std::uint64_t>& args) {
  using namespace vmp::runtime::vm2;
  Vm2Context ctx(module);
  switch (cc) {
    case vmp::arch::common::CallingConvention::sysv_x64:
    case vmp::arch::common::CallingConvention::msvc_x64:
    case vmp::arch::common::CallingConvention::aapcs32:
    case vmp::arch::common::CallingConvention::aapcs64:
      for (std::size_t i = 0; i < args.size() && i < 8; ++i) ctx.r[i] = args[i];
      break;
    default:
      throw std::runtime_error("run_vm2_abi: unsupported calling convention");
  }
  Vm2Interpreter interp;
  return interp.execute(ctx).ret_int;
}

}  // namespace vmp::tests::arch
