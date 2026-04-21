#include "test_common.h"

#include <iostream>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/audit/reaction.h>
#include <vmp/runtime/env_integrity/monitor.h>

#include "../runtime_vm1/test_common.h"
#include "../runtime_vm2/test_common.h"

using namespace vmp::tests::runtime_env_integrity;

namespace {

void vm_guard_handler(int) {}

}  // namespace

int main() {
  try {
    const auto audit_path = temp_path("env_vm_sensitive", ".log");

    vmp::runtime::audit::AuditWriter writer(audit_path);
    vmp::runtime::audit::ReactionDispatcher dispatcher(writer, vmp::runtime::audit::ReactionPolicy::audit_only);

    const auto clean_vm1 = vmp::tests::runtime_vm1::run_text("ldi_u64 vr0, 7\nret\n", {}, nullptr, &dispatcher);
    require(clean_vm1.ret_int == 7, "vm1 baseline execution failed");

    vmp::runtime::env_integrity::EnvIntegrityMonitor monitor(bytes16(0x41), audit_path);
    monitor.exception_handlers().register_signal(SIGUSR1, "vm_sensitive_sigusr1");

    {
      vmp::runtime::env_integrity::DefaultMonitorOverride guard(monitor);
      ScopedSignalHandler scoped(SIGUSR1, vm_guard_handler);

      const auto vm1_result = vmp::tests::runtime_vm1::run_text("ldi_u64 vr0, 9\nret\n", {}, nullptr, &dispatcher);
      require(vm1_result.ret_int == 9, "vm1 result changed unexpectedly");

      const auto vm2_result = vmp::tests::runtime_vm2::run_text("ildimm r0, 5\nbret\n", {}, nullptr, &dispatcher);
      require(vm2_result.ret_int == 5, "vm2 result changed unexpectedly");
    }

    const auto log = read_all(audit_path);
    require(log.find("exception_chain_modified") != std::string::npos,
            "vm sensitive-domain entry did not emit exception_chain_modified");

    std::cout << "env_vm_sensitive_domain_entry_checks_monitor OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "env_vm_sensitive_domain_entry_checks_monitor failed: " << ex.what() << '\n';
    return 1;
  }
}
