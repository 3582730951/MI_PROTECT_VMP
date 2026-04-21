#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_crypto_revision;

int main() {
  namespace roll1 = vmp::runtime::cryptor::vm1;
  using namespace vmp::runtime::trampoline;

  const KeyContextId key_context{
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };

  const auto token = TokenManager::derive_token(key_context, 0x401000u, "alpha");
  require(token == expected_token_v2(key_context, 0x401000u, "alpha"), "token HKDF v2 namespace mismatch");
  require(token.size() == 16u, "token must be 128-bit");

  const auto static_hmac = StackFunctionTable::derive_hmac_key(key_context);
  require(static_hmac == expected_static_hmac_key_v2(key_context), "static HMAC namespace mismatch");

  TokenManager manager;
  const auto entry = manager.register_entry(key_context, 0x401000u, 0x900000u, "alpha");
  StackFunctionTable table(manager.entries(), key_context);
  std::array<std::uint8_t, 32> observed_ephemeral{};
  DispatcherOptions options;
  options.test_hooks.stack_canary_provider = []() { return 0x1111222233334444ull; };
  options.test_hooks.return_address_provider = []() { return 0x5555666677778888ull; };
  options.test_hooks.nonce_provider = []() { return 0x9999aaaabbbbccccull; };
  options.test_hooks.derived_key_observer = [&](const HmacBytes& key) { observed_ephemeral = key; };
  Dispatcher dispatcher(table, options);
  (void)dispatcher.dispatch_verbose(entry.token);
  require(observed_ephemeral == expected_ephemeral_hmac_key_v2(
                                 key_context,
                                 0x1111222233334444ull,
                                 0x5555666677778888ull,
                                 0x9999aaaabbbbccccull),
          "ephemeral HMAC namespace mismatch");

  const std::vector<std::uint8_t> salt(16, 0x44);
  std::vector<std::uint8_t> master(32);
  for (std::size_t i = 0; i < master.size(); ++i) {
    master[i] = static_cast<std::uint8_t>(0x71 + i);
  }
  vmp::runtime::strings::KeyContext key_ctx(
      vmp::runtime::strings::MasterKeyHandle([master]() { return master; }),
      salt);
  const auto string_key = key_ctx.derive_subkey("string-pool");
  require(string_key.bytes() == expected_string_key_v2(salt, master), "string HKDF namespace mismatch");

  auto module = make_vm1_module(R"(
entry:
  ldi_u64 vr0, 42
  ret
)", 0x31);
  auto descriptor = roll1::describe_module(module);
  auto& registry = vmp::runtime::cryptor::RollingOpcodeRegistry::instance();
  registry.reset_for_tests();
  registry.ensure_module(descriptor);
  const auto key_override = vec16(0xA0);
  registry.rotate_module(descriptor, vmp::runtime::cryptor::RotationReason::key_rotation, key_override);
  const auto store = registry.map_store(descriptor);
  require(store.current.derived_from_key_ctx == expected_rolling_prk_v2(
                                                descriptor,
                                                1u,
                                                vmp::runtime::cryptor::RotationReason::key_rotation,
                                                key_override),
          "rolling opcode PRK namespace mismatch");
  require(store.current.epoch_seed == expected_rolling_seed_v2(
                                        descriptor,
                                        1u,
                                        vmp::runtime::cryptor::RotationReason::key_rotation,
                                        key_override),
          "rolling opcode epoch seed namespace mismatch");

  std::cout << "crypto_revision_hkdf_namespaces OK\n";
  return 0;
}
