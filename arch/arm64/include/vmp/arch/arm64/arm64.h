#pragma once

namespace vmp::arch::arm64 {

struct ArchFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::arch::arm64
