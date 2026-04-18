#pragma once

#include <vmp/arch/common/lifting.h>

namespace vmp::arch::x64 {

class X64Lifter final : public vmp::arch::common::IsaLifter {
 public:
  explicit X64Lifter(vmp::arch::common::TargetDomain domain = vmp::arch::common::TargetDomain::vm1)
      : domain_(domain) {}

  std::string isa_name() const override;
  bool can_lift(const vmp::arch::common::FunctionView& view) const override;
  vmp::arch::common::LiftedFunction lift(const vmp::arch::common::FunctionView& view) const override;

 private:
  vmp::arch::common::TargetDomain domain_;
};

struct ArchFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::arch::x64
