#include <chrono>
#include <filesystem>
#include <iostream>
#include <vector>

#include <vmp/runtime/stack_probe/probe.h>

#include "test_common.h"

int main() {
  using namespace vmp::runtime::stack_probe;
  using namespace vmp::tests::runtime_stack_probe;

  const auto audit_path = temp_path("stack_probe_trigger_gate_and_anon_exec_event", ".log");
  std::filesystem::remove(audit_path);

  ProbeDependencies deps;
  deps.frame_pointer_walker = []() {
    return std::vector<std::uintptr_t>{0x70000010u};
  };
  deps.maps_reader = []() {
    return std::string("70000000-70001000 r-xp 00000000 00:00 0\n");
  };

  StackProbeManager probe(audit_path, deps);
  int exit_calls = 0;
  probe.reaction_dispatcher().set_exit_fn([&exit_calls]() { ++exit_calls; });
  probe.reaction_dispatcher().set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) { fn(); });
  probe.reaction_dispatcher().set_delay_selector([]() { return std::chrono::milliseconds(0); });

  ProbeRequest request;
  request.token_low12 = 1u;
  request.site = ProbeTriggerSite::dispatcher_entry;

  const auto first = probe.maybe_probe(request);
  require(!first.triggered, "first probe should not trigger when counter low-12 != selector");

  const auto second = probe.maybe_probe(request);
  require(second.triggered, "second probe should trigger once counter low-12 matches selector");
  require(second.used_frame_pointer_walk, "triggered probe should prefer frame-pointer walk");
  require(!second.used_libunwind_fallback, "frame-pointer walk should avoid libunwind fallback");
  require(second.event_emitted, "anonymous executable frame should emit an audit event");
  require(second.suspicious_frames.size() == 1u, "exactly one suspicious frame expected");
  require(second.suspicious_frames.front().mapping.anonymous, "suspicious frame should be classified as anonymous");
  require(exit_calls == 1, "anon executable frame should route through delayed exit reaction");

  const auto audit_text = read_all(audit_path);
  require(audit_text.find("anon_executable_frame") != std::string::npos,
          "anon_executable_frame audit event missing");
  require(audit_text.find("probe_trigger_site=dispatcher_entry") != std::string::npos,
          "audit note should include dispatcher trigger site");
  require(audit_text.find("mapping_description=[anonymous") != std::string::npos,
          "audit note should include anonymous mapping description");

  std::cout << "stack_probe_trigger_gate_and_anon_exec_event OK\n";
  return 0;
}
