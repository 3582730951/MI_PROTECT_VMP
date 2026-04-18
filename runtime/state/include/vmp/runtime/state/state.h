#pragma once

namespace vmp::runtime::state {

struct Facade {
  const char* status() const noexcept;
};

}  // namespace vmp::runtime::state
