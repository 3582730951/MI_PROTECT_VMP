#include "test_common.h"

#include <iostream>

#include <vmp/runtime/env_integrity/monitor.h>

using namespace vmp::tests::runtime_env_integrity;

namespace {

void test_handler(int) {}

}  // namespace

int main() {
  try {
    const auto audit_path = temp_path("env_exception_chain", ".log");
    vmp::runtime::env_integrity::EnvIntegrityMonitor monitor(bytes16(0x11), audit_path);
    monitor.exception_handlers().register_signal(SIGUSR1, "dispatcher_sigusr1");

    const auto clean = monitor.verify_sensitive_domain("vm1");
    require(clean.exception_handlers_ok, "baseline signal snapshot should verify cleanly");
    require(clean.ok, "baseline verification should be globally clean");

    {
      ScopedSignalHandler scoped(SIGUSR1, test_handler);
      const auto dirty = monitor.verify_sensitive_domain("vm1");
      require(!dirty.exception_handlers_ok, "new handler must invalidate exception baseline");
      require(!dirty.ok, "tampered handler must fail sensitive-domain verification");
      require(read_all(audit_path).find("exception_chain_modified") != std::string::npos,
              "exception_chain_modified audit missing");
    }

    std::cout << "env_exception_baseline_detects_new_handler OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "env_exception_baseline_detects_new_handler failed: " << ex.what() << '\n';
    return 1;
  }
}
