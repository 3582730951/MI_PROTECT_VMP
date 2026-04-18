#pragma once

namespace vmp::loader::windows {

struct LoaderFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::loader::windows
