#include <chrono>
#include <filesystem>
#include <iostream>

#include <vmp/runtime/trampoline/trampoline.h>

#include "test_common.h"

int main() {
  using namespace vmp::runtime::trampoline;
  using namespace vmp::tests::runtime_dispatcher_hardening;

  const auto audit_path = temp_path("dispatcher_self_hash_detects_tamper", ".log");
  std::filesystem::remove(audit_path);

  const KeyContextId key_context{{
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  }};

  ExecutableBuffer dispatcher_region(pattern(0x40, 64));
  ExecutableBuffer target_region(pattern(0x80, 64));

  TokenManager manager;
  const auto entry = manager.register_entry(key_context, 0x401000u, target_region.address(), "alpha");
  StackFunctionTable table(manager.entries(), key_context, audit_path);

  int exit_calls = 0;
  table.reaction_dispatcher().set_exit_fn([&exit_calls]() { ++exit_calls; });
  table.reaction_dispatcher().set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) { fn(); });
  table.reaction_dispatcher().set_delay_selector([]() { return std::chrono::milliseconds(0); });

  DispatcherOptions options;
  options.self_hash_region = {dispatcher_region.data(), dispatcher_region.size()};
  Dispatcher dispatcher(table, options);

  const auto ok = dispatcher.dispatch_verbose(entry.token);
  require(ok.integrity_ok, "clean dispatch should pass integrity");
  require(ok.dispatcher_self_hash_ok, "clean dispatch should pass self hash");
  require(ok.token_found, "clean dispatch should resolve token");
  require(exit_calls == 0, "clean dispatch must not trigger exit");

  dispatcher_region.patch(0, static_cast<std::uint8_t>(dispatcher_region.data()[0] ^ 0xffu));
  const auto tampered = dispatcher.dispatch_verbose(entry.token);
  require(!tampered.integrity_ok, "tampered dispatcher region must fail integrity");
  require(!tampered.dispatcher_self_hash_ok, "tampered dispatcher region must fail self hash");
  require(exit_calls == 1, "tampered dispatcher region should trigger delayed exit");
  require(read_all(audit_path).find("dispatcher_tampered") != std::string::npos,
          "dispatcher_tampered audit event missing");

  std::cout << "dispatcher_self_hash_detects_tamper OK\n";
  return 0;
}
