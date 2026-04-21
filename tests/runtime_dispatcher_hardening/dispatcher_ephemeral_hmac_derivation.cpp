#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <vector>

#include <vmp/runtime/trampoline/trampoline.h>

#include "test_common.h"

int main() {
  using namespace vmp::runtime::trampoline;
  using namespace vmp::tests::runtime_dispatcher_hardening;

  const auto audit_path = temp_path("dispatcher_ephemeral_hmac_derivation", ".log");
  std::filesystem::remove(audit_path);

  const KeyContextId key_context{{
      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
      0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
  }};

  ExecutableBuffer target_region(pattern(0x90, 64));

  TokenManager manager;
  const auto entry = manager.register_entry(key_context, 0x403000u, target_region.address(), "gamma");
  StackFunctionTable table(manager.entries(), key_context, audit_path);

  std::vector<HmacBytes> derived_keys;
  std::vector<HmacBytes> scrubbed_keys;
  std::size_t nonce_index = 0;
  const std::uint64_t nonces[] = {0x1111111111111111ull, 0x2222222222222222ull};

  DispatcherOptions options;
  options.test_hooks.nonce_provider = [&]() {
    require(nonce_index < 2, "nonce provider exhausted");
    return nonces[nonce_index++];
  };
  options.test_hooks.stack_canary_provider = []() { return static_cast<std::uintptr_t>(0xaabbccddeeff0011ull); };
  options.test_hooks.return_address_provider = []() { return static_cast<std::uintptr_t>(0x0123456789abcdefull); };
  options.test_hooks.derived_key_observer = [&derived_keys](const HmacBytes& key) { derived_keys.push_back(key); };
  options.test_hooks.zeroized_key_observer = [&scrubbed_keys](const HmacBytes& key) { scrubbed_keys.push_back(key); };

  Dispatcher dispatcher(table, options);
  const auto first = dispatcher.dispatch_verbose(entry.token);
  const auto second = dispatcher.dispatch_verbose(entry.token);

  require(first.integrity_ok && second.integrity_ok, "ephemeral HMAC dispatches should succeed");
  require(derived_keys.size() == 2, "expected 2 derived ephemeral keys");
  require(scrubbed_keys.size() == 2, "expected 2 scrubbed ephemeral keys");
  require(derived_keys[0] != derived_keys[1], "ephemeral HMAC key must vary per dispatch nonce");
  require(derived_keys[0] != StackFunctionTable::derive_hmac_key(key_context),
          "ephemeral HMAC key must not reuse fixed table key");
  require(std::all_of(scrubbed_keys[0].begin(), scrubbed_keys[0].end(), [](std::uint8_t byte) { return byte == 0; }),
          "first ephemeral HMAC key should be zeroized");
  require(std::all_of(scrubbed_keys[1].begin(), scrubbed_keys[1].end(), [](std::uint8_t byte) { return byte == 0; }),
          "second ephemeral HMAC key should be zeroized");
  require(first.dispatch_seq + 1 == second.dispatch_seq, "dispatch_seq should advance monotonically");

  std::cout << "dispatcher_ephemeral_hmac_derivation OK\n";
  return 0;
}
