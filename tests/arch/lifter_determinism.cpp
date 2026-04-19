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
void require_deterministic(const Lifter& lifter,
                           const vmp::arch::common::FunctionView& view,
                           const std::string& label) {
  const auto first = lifter.lift(view);
  const auto second = lifter.lift(view);
  vmp::tests::arch::require(first.ok(), label + ": first lift failed");
  vmp::tests::arch::require(second.ok(), label + ": second lift failed");
  const auto bytes_a = first.module.serialize();
  const auto bytes_b = second.module.serialize();
  vmp::tests::arch::require(bytes_a == bytes_b, label + ": byte streams differ");
  vmp::tests::arch::require(fnv1a64(bytes_a) == fnv1a64(bytes_b), label + ": hash differs");
}
}  // namespace

int main() {
  try {
    using namespace vmp::arch;
    common::FunctionView x86_view{0x6100,
                                  {0x55, 0x89, 0xE5, 0x8B, 0x4D, 0x08, 0x8B, 0x5D, 0x0C, 0xB8, 0x00, 0x00, 0x00, 0x00,
                                   0xBA, 0x00, 0x00, 0x00, 0x00, 0x39, 0xD1, 0x7E, 0x0D, 0xBE, 0x01, 0x00, 0x00, 0x00,
                                   0x01, 0xD8, 0x29, 0xF1, 0x39, 0xD1, 0x7F, 0xF8, 0x5D, 0xC3},
                                  std::nullopt,
                                  common::CallingConvention::cdecl_x86,
                                  common::ArchEndianness::little};
    common::FunctionView x64_view{0x7100,
                                  {0x48, 0x89, 0xF9, 0x48, 0x89, 0xF3, 0x31, 0xC0, 0x31, 0xD2, 0x48, 0x39, 0xD1, 0x7E,
                                   0x11, 0x41, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x01, 0xD8, 0x4C, 0x29, 0xC1, 0x48,
                                   0x39, 0xD1, 0x7F, 0xF5, 0xC3},
                                  std::nullopt,
                                  common::CallingConvention::sysv_x64,
                                  common::ArchEndianness::little};
    common::FunctionView arm_view{0x8100,
                                  {0x02, 0x20, 0x22, 0xE0, 0x00, 0x40, 0xA0, 0xE1, 0x00, 0x00, 0x20, 0xE0, 0x02, 0x00,
                                   0x54, 0xE1, 0x04, 0x00, 0x00, 0xDA, 0x10, 0x30, 0x9F, 0xE5, 0x01, 0x00, 0x80, 0xE0,
                                   0x03, 0x40, 0x44, 0xE0, 0x02, 0x00, 0x54, 0xE1, 0xFB, 0xFF, 0xFF, 0xCA, 0x1E, 0xFF,
                                   0x2F, 0xE1, 0x01, 0x00, 0x00, 0x00},
                                  std::nullopt,
                                  common::CallingConvention::aapcs32,
                                  common::ArchEndianness::little};
    common::FunctionView arm64_view{0x9100,
                                    {0x42, 0x00, 0x02, 0xCA, 0x04, 0x00, 0x02, 0x8B, 0x40, 0x00, 0x02, 0x8B, 0x9F, 0x00,
                                     0x02, 0xEB, 0xCD, 0x00, 0x00, 0x54, 0xE3, 0x00, 0x00, 0x58, 0x00, 0x00, 0x01, 0x8B,
                                     0x84, 0x00, 0x03, 0xCB, 0x9F, 0x00, 0x02, 0xEB, 0xAC, 0xFF, 0xFF, 0x54, 0xC0, 0x03,
                                     0x5F, 0xD6, 0x1F, 0x20, 0x03, 0xD5, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                    std::nullopt,
                                    common::CallingConvention::aapcs64,
                                    common::ArchEndianness::little};
    require_deterministic(x86::X86Lifter{}, x86_view, "x86");
    require_deterministic(x64::X64Lifter(common::TargetDomain::vm1), x64_view, "x64");
    require_deterministic(arm::ArmLifter{}, arm_view, "arm");
    require_deterministic(arm64::Arm64Lifter{}, arm64_view, "arm64");
    std::cout << "lifter_determinism OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "lifter_determinism failed: " << ex.what() << '\n';
    return 1;
  }
}
