#pragma once

namespace vmp::runtime::audit {

struct Facade {
  const char* status() const noexcept;
};

}  // namespace vmp::runtime::audit
