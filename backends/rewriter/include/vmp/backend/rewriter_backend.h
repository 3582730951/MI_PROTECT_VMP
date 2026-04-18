#pragma once

namespace vmp::backend::rewriter {

struct RewriterBackendFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::backend::rewriter
