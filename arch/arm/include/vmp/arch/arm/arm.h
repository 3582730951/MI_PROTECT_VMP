#pragma once

namespace vmp::arch::arm {

struct ArchFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::arch::arm
