#pragma once

namespace vmp::bindings::cpp {

struct PluginFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::bindings::cpp
