#include "test_common.h"

#include <iostream>

#include <vmp/runtime/env_integrity/monitor.h>

using namespace vmp::tests::runtime_env_integrity;

namespace {

void unrelated_handler(int) {}

}  // namespace

int main() {
  try {
    const auto audit_path = temp_path("env_exception_whitelist", ".log");
    vmp::runtime::env_integrity::EnvIntegrityMonitor monitor(bytes16(0x21), audit_path);
    monitor.exception_handlers().register_signal(SIGUSR1, "dispatcher_sigusr1");

    ScopedSignalHandler scoped(SIGUSR2, unrelated_handler);
    const auto result = monitor.verify_sensitive_domain("vm2");
    require(result.exception_handlers_ok, "untracked signal should not invalidate whitelist snapshot");
    require(result.ok, "untracked signal should not fail verification");
    require(read_all(audit_path).find("exception_chain_modified") == std::string::npos,
            "whitelist should suppress audit noise for unrelated signals");

    std::cout << "env_exception_whitelist_ignores_untracked_signal OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "env_exception_whitelist_ignores_untracked_signal failed: " << ex.what() << '\n';
    return 1;
  }
}
