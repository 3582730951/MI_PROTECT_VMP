#include <chrono>
#include <filesystem>
#include <iostream>
#include <vector>

#include <vmp/runtime/stack_probe/probe.h>

#include "test_common.h"

int main() {
  using namespace vmp::runtime::stack_probe;
  using namespace vmp::tests::runtime_stack_probe;

  const auto audit_path = temp_path("stack_probe_libunwind_fallback_deleted_mapping", ".log");
  std::filesystem::remove(audit_path);

  ProbeDependencies deps;
  deps.frame_pointer_walker = []() {
    return std::vector<std::uintptr_t>{};
  };
  deps.libunwind_walker = []() {
    return std::vector<std::uintptr_t>{0x401234u};
  };
  deps.maps_reader = []() {
    return std::string("00400000-00402000 r-xp 00000000 08:01 4242 /tmp/vmp_probe_deleted.so (deleted)\n");
  };

  StackProbeManager probe(audit_path, deps);
  int exit_calls = 0;
  probe.reaction_dispatcher().set_exit_fn([&exit_calls]() { ++exit_calls; });
  probe.reaction_dispatcher().set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) { fn(); });
  probe.reaction_dispatcher().set_delay_selector([]() { return std::chrono::milliseconds(0); });

  ProbeRequest request;
  request.token_low12 = 0u;
  request.site = ProbeTriggerSite::vm1_handler_dispatch;

  const auto result = probe.maybe_probe(request);
  require(result.triggered, "selector zero should trigger on initial counter value");
  require(!result.used_frame_pointer_walk, "empty FP walk should not be reported as used");
  require(result.used_libunwind_fallback, "empty FP walk should fall back to libunwind");
  require(result.event_emitted, "deleted executable mapping should emit an audit event");
  require(result.suspicious_frames.size() == 1u, "deleted mapping should surface one suspicious frame");
  require(result.suspicious_frames.front().mapping.deleted, "mapping should be flagged as deleted");
  require(exit_calls == 1, "deleted mapping should route through delayed exit reaction");

  const auto audit_text = read_all(audit_path);
  require(audit_text.find("anon_executable_frame") != std::string::npos,
          "anon_executable_frame audit event missing for deleted mapping");
  require(audit_text.find("(deleted)") != std::string::npos,
          "audit note should preserve deleted mapping description");
  require(audit_text.find("probe_trigger_site=vm1_handler_dispatch") != std::string::npos,
          "audit note should include vm1 trigger site");

  std::cout << "stack_probe_libunwind_fallback_deleted_mapping OK\n";
  return 0;
}
