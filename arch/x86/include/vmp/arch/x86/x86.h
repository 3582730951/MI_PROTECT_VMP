#pragma once

namespace vmp::arch::x86 {

struct ArchFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::arch::x86
