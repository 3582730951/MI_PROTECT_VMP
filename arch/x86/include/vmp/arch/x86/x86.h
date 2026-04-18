#pragma once

#include <vmp/arch/common/lifting.h>

namespace vmp::arch::x86 {

class X86Lifter final : public vmp::arch::common::IsaLifter {
 public:
  std::string isa_name() const override;
  bool can_lift(const vmp::arch::common::FunctionView& view) const override;
  vmp::arch::common::LiftedFunction lift(const vmp::arch::common::FunctionView& view) const override;
};

struct ArchFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::arch::x86
