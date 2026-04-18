#pragma once

namespace vmp::loader::linux_platform {

struct LoaderFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::loader::linux_platform
