#include <algorithm>
#include <filesystem>
#include <iostream>
#include <vector>

#include <vmp/runtime/stack_probe/probe.h>
#include <vmp/runtime/trampoline/trampoline.h>

#include "../runtime_dispatcher_hardening/test_common.h"
#include "../runtime_vm1/test_common.h"
#include "../runtime_vm2/test_common.h"
#include "test_common.h"

int main() {
  using namespace vmp::runtime::stack_probe;
  using namespace vmp::runtime::trampoline;
  namespace det = vmp::tests::runtime_stack_probe;
  namespace tramp = vmp::tests::runtime_dispatcher_hardening;

  const auto audit_path = det::temp_path("stack_probe_integration_sites", ".log");
  std::filesystem::remove(audit_path);

  std::vector<ProbeInvocation> invocations;
  ProbeDependencies deps;
  deps.trigger_decider = [](std::uint16_t, std::uint64_t) {
    return false;
  };
  deps.invocation_observer = [&invocations](const ProbeInvocation& invocation) {
    invocations.push_back(invocation);
  };

  StackProbeManager probe(audit_path, deps);
  DefaultStackProbeOverride override(probe);

  const KeyContextId key_context{{
      0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
      0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
  }};
  tramp::ExecutableBuffer target_region(tramp::pattern(0x30, 64));
  TokenManager manager;
  const auto entry = manager.register_entry(key_context, 0x405000u, target_region.address(), "gamma");
  StackFunctionTable table(manager.entries(), key_context, audit_path);
  Dispatcher dispatcher(table);
  det::require(dispatcher.dispatch_verbose(entry.token).integrity_ok, "dispatcher should still resolve target");

  (void)vmp::tests::runtime_vm1::run_text("ldi_u64 vr0, 1\nret\n");
  (void)vmp::tests::runtime_vm2::run_text("ildimm r0, 1\nbret\n");

  auto saw_site = [&](ProbeTriggerSite site) {
    return std::any_of(invocations.begin(), invocations.end(), [&](const ProbeInvocation& invocation) {
      return invocation.site == site;
    });
  };

  det::require(saw_site(ProbeTriggerSite::dispatcher_entry), "dispatcher entry should invoke stack probe");
  det::require(saw_site(ProbeTriggerSite::trampoline_target_prologue), "trampoline target prologue should invoke stack probe");
  det::require(saw_site(ProbeTriggerSite::vm1_handler_dispatch), "vm1 handler dispatch should invoke stack probe");
  det::require(saw_site(ProbeTriggerSite::vm2_handler_dispatch), "vm2 handler dispatch should invoke stack probe");

  const auto expected_selector = static_cast<std::uint16_t>(token_low64(entry.token) & 0x0fffu);
  det::require(std::any_of(invocations.begin(), invocations.end(), [&](const ProbeInvocation& invocation) {
                 return invocation.site == ProbeTriggerSite::dispatcher_entry &&
                        invocation.token_low12 == expected_selector;
               }),
               "dispatcher probe should use token low-12 selector");

  std::cout << "stack_probe_integration_sites OK\n";
  return 0;
}
