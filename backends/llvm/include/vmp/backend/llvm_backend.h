#pragma once

namespace vmp::backend::llvm {

struct LlvmBackendFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::backend::llvm
