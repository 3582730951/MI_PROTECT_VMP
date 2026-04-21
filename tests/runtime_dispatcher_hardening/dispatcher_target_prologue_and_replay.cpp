#include <chrono>
#include <filesystem>
#include <iostream>

#include <vmp/runtime/trampoline/trampoline.h>

#include "test_common.h"

int main() {
  using namespace vmp::runtime::trampoline;
  using namespace vmp::tests::runtime_dispatcher_hardening;

  const auto audit_path = temp_path("dispatcher_target_prologue_and_replay", ".log");
  std::filesystem::remove(audit_path);

  const KeyContextId key_context{{
      0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
      0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
  }};

  ExecutableBuffer target_region(pattern(0x55, 64));

  TokenManager manager;
  const auto entry = manager.register_entry(key_context, 0x402000u, target_region.address(), "beta");
  StackFunctionTable table(manager.entries(), key_context, audit_path);

  int exit_calls = 0;
  table.reaction_dispatcher().set_exit_fn([&exit_calls]() { ++exit_calls; });
  table.reaction_dispatcher().set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) { fn(); });
  table.reaction_dispatcher().set_delay_selector([]() { return std::chrono::milliseconds(0); });

  Dispatcher dispatcher(table);
  const auto ticket = dispatcher.issue_dispatch_ticket(entry.token);
  require(ticket.dispatch_seq != 0, "ticket should carry a dispatch sequence");

  const auto ok = dispatcher.dispatch_verbose(ticket);
  require(ok.integrity_ok, "ticket dispatch should pass integrity");
  require(ok.replay_ok, "fresh ticket should not trip replay protection");
  require(ok.target_prologue_ok, "fresh target bytes should match fingerprint");
  require(ok.dispatch_seq == ticket.dispatch_seq, "result should expose consumed dispatch seq");

  const auto replay = dispatcher.dispatch_verbose(ticket);
  require(!replay.integrity_ok, "replayed ticket must fail integrity");
  require(!replay.replay_ok, "replayed ticket must be rejected");
  require(exit_calls == 1, "replayed ticket should trigger delayed exit");

  target_region.patch(1, static_cast<std::uint8_t>(target_region.data()[1] ^ 0x5au));
  const auto tampered = dispatcher.dispatch_verbose(entry.token);
  require(!tampered.integrity_ok, "tampered target prologue must fail integrity");
  require(!tampered.target_prologue_ok, "tampered target prologue must be reported");
  require(exit_calls == 2, "target prologue tamper should trigger delayed exit");

  const auto audit_text = read_all(audit_path);
  require(audit_text.find("replay_detected") != std::string::npos,
          "replay_detected audit event missing");
  require(audit_text.find("target_prologue_tampered") != std::string::npos,
          "target_prologue_tampered audit event missing");

  std::cout << "dispatcher_target_prologue_and_replay OK\n";
  return 0;
}
