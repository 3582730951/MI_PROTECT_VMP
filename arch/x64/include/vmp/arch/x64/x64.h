#pragma once

namespace vmp::arch::x64 {

struct ArchFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::arch::x64
