#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <vmp/runtime/trampoline/trampoline.h>

namespace {

void require(bool condition, const char* message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to open audit log");
  }
  return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

}  // namespace

int main() {
  using namespace vmp::runtime::trampoline;

  const auto audit_path = std::filesystem::temp_directory_path() / "vmp_trampoline_audit_test.log";
  std::filesystem::remove(audit_path);

  const KeyContextId key_context{
      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
      0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
  };

  TokenManager manager;
  const auto alpha = manager.register_entry(key_context, 0x401000u, 0x900000u, "alpha");
  const auto beta = manager.register_entry(key_context, 0x402000u, 0x900100u, "beta");
  StackFunctionTable table(manager.entries(), key_context, audit_path);

  int exit_calls = 0;
  table.reaction_dispatcher().set_exit_fn([&exit_calls]() { ++exit_calls; });
  table.reaction_dispatcher().set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) { fn(); });
  table.reaction_dispatcher().set_delay_selector([]() { return std::chrono::milliseconds(0); });

  const Dispatcher dispatcher(table);
  const auto ok = dispatcher.dispatch_verbose(alpha.token);
  require(ok.integrity_ok, "expected integrity check to succeed");
  require(ok.token_found, "expected token lookup to succeed");
  require(ok.resolved_address == alpha.relocated_address, "resolved address mismatch");
  require(exit_calls == 0, "valid lookup must not trigger exit path");

  const auto missing = dispatcher.dispatch_verbose(token_from_low64(0xfeedfacefeedfaceull));
  require(missing.integrity_ok, "missing token should still verify table integrity");
  require(!missing.token_found, "missing token unexpectedly resolved");
  require(exit_calls == 1, "missing token should trigger delayed exit hook");
  require(read_text(audit_path).find("invalid_token_access") != std::string::npos,
          "invalid_token_access audit event missing");

  bool tamper_detected = false;
  table.with_materialized_view([&](StackFunctionTableView& view) {
    view.records[1].relocated_address ^= 0x10u;
    tamper_detected = !table.verify_view(view);
  });
  require(tamper_detected, "tampered stack table should fail HMAC verification");

  std::cout << "stack_function_table_audits_and_hmac OK\n";
  return 0;
}
