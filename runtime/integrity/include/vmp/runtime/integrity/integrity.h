#pragma once

#include <vmp/runtime/integrity/region.h>

namespace vmp::runtime::integrity {

struct Facade {
  const char* status() const noexcept;
};

}  // namespace vmp::runtime::integrity
