#include "test_common.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <vmp/arch/arm/arm.h>
#include <vmp/arch/arm64/arm64.h>
#include <vmp/arch/x64/x64.h>
#include <vmp/arch/x86/x86.h>

namespace {
std::uint64_t fnv1a64(const std::vector<std::uint8_t>& bytes) {
  std::uint64_t hash = 1469598103934665603ull;
  for (std::uint8_t byte : bytes) {
    hash ^= byte;
    hash *= 1099511628211ull;
  }
  return hash;
}

template <typename Lifter>
void require_hash(const Lifter& lifter,
                  const vmp::arch::common::FunctionView& view,
                  std::uint64_t expected,
                  const std::string& name) {
  const auto lifted = lifter.lift(view);
  vmp::tests::arch::require(lifted.ok(), name + ": lift failed");
  const auto actual = fnv1a64(lifted.module.serialize());
  vmp::tests::arch::require(actual == expected, name + ": serialized hash changed");
}
}  // namespace

int main() {
  try {
    using namespace vmp::arch;
    common::FunctionView x86_view;
    x86_view.base_addr = 0x1000;
    x86_view.cc = common::CallingConvention::cdecl_x86;
    x86_view.endian = common::ArchEndianness::little;
    x86_view.code = {0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x03, 0x45, 0x0C, 0x5D, 0xC3};

    common::FunctionView x64_sysv_view;
    x64_sysv_view.base_addr = 0x2000;
    x64_sysv_view.cc = common::CallingConvention::sysv_x64;
    x64_sysv_view.endian = common::ArchEndianness::little;
    x64_sysv_view.code = {0x48, 0x89, 0xF8, 0x48, 0x01, 0xF0, 0xC3};

    common::FunctionView x64_msvc_view;
    x64_msvc_view.base_addr = 0x3000;
    x64_msvc_view.cc = common::CallingConvention::msvc_x64;
    x64_msvc_view.endian = common::ArchEndianness::little;
    x64_msvc_view.code = {0x48, 0x89, 0xC8, 0x48, 0x01, 0xD0, 0xC3};

    common::FunctionView arm_view;
    arm_view.base_addr = 0x4000;
    arm_view.cc = common::CallingConvention::aapcs32;
    arm_view.endian = common::ArchEndianness::little;
    arm_view.code = {0x01, 0x00, 0x80, 0xE0, 0x1E, 0xFF, 0x2F, 0xE1};

    common::FunctionView arm64_view;
    arm64_view.base_addr = 0x5000;
    arm64_view.cc = common::CallingConvention::aapcs64;
    arm64_view.endian = common::ArchEndianness::little;
    arm64_view.code = {0x00, 0x00, 0x01, 0x8B, 0xC0, 0x03, 0x5F, 0xD6};

    require_hash(x86::X86Lifter{}, x86_view, 0x0c7cc2afffb46f8eull, "x86_lift_basic");
    require_hash(x64::X64Lifter(common::TargetDomain::vm1), x64_sysv_view, 0x2f506b1b83010bd3ull, "x64_lift_basic_sysv");
    require_hash(x64::X64Lifter(common::TargetDomain::vm1), x64_msvc_view, 0xd8234036809fbe9bull, "x64_lift_basic_msvc");
    require_hash(arm::ArmLifter{}, arm_view, 0xa682b0d41b8da745ull, "arm_lift_basic");
    require_hash(arm64::Arm64Lifter{}, arm64_view, 0xa682b0d41b8da745ull, "arm64_lift_basic");
    std::cout << "lift_basic_hash_regression OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "lift_basic_hash_regression failed: " << ex.what() << '\n';
    return 1;
  }
}
