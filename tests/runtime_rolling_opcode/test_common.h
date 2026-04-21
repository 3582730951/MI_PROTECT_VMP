#pragma once

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/audit/reaction.h>
#include <vmp/runtime/bridge/bridge.h>
#include <vmp/runtime/cryptor/rolling_opcode_vm1.h>
#include <vmp/runtime/cryptor/rolling_opcode_vm2.h>
#include <vmp/runtime/jit/vm1_jit.h>
#include <vmp/runtime/jit/vm2_jit.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/keyctx.h>
#include <vmp/runtime/vm1/vm1.h>
#include <vmp/runtime/vm2/vm2.h>

namespace vmp::tests::runtime_rolling_opcode {

inline void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

struct EnvGuard {
  std::string name;
  std::string original;
  bool had_original = false;

  EnvGuard(std::string name_in, std::string value) : name(std::move(name_in)) {
    if (const char* current = std::getenv(name.c_str()); current != nullptr) {
      had_original = true;
      original = current;
    }
#if defined(_WIN32)
    _putenv_s(name.c_str(), value.c_str());
#else
    ::setenv(name.c_str(), value.c_str(), 1);
#endif
  }

  ~EnvGuard() {
#if defined(_WIN32)
    _putenv_s(name.c_str(), had_original ? original.c_str() : "");
#else
    if (had_original) {
      ::setenv(name.c_str(), original.c_str(), 1);
    } else {
      ::unsetenv(name.c_str());
    }
#endif
  }
};

inline std::filesystem::path temp_path(const std::string& stem, const std::string& ext) {
  return std::filesystem::temp_directory_path() /
         (stem + "_" + std::to_string(::getpid()) + "_" + std::to_string(std::rand()) + ext);
}

inline std::string read_all(const std::filesystem::path& path) {
  std::ifstream input(path);
  std::ostringstream oss;
  oss << input.rdbuf();
  return oss.str();
}

inline std::array<std::uint8_t, 16> bytes16(std::uint8_t base) {
  std::array<std::uint8_t, 16> out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(base + static_cast<std::uint8_t>(i));
  }
  return out;
}

inline std::vector<std::uint8_t> vec16(std::uint8_t base) {
  const auto data = bytes16(base);
  return std::vector<std::uint8_t>(data.begin(), data.end());
}

inline vmp::runtime::vm1::Vm1Module make_vm1_module(std::string_view text, std::uint8_t seed_base = 0x10) {
  vmp::runtime::vm1::AssembleOptions options;
  options.encrypt_opcodes = true;
  options.opcode_seed = bytes16(seed_base);
  return vmp::runtime::vm1::assemble_module_text(text, options);
}

inline std::shared_ptr<vmp::runtime::strings::KeyContext> fixed_key_context_ptr(
    std::vector<std::uint8_t> salt = std::vector<std::uint8_t>(16, 0x44)) {
  std::vector<std::uint8_t> master(32);
  for (std::size_t i = 0; i < master.size(); ++i) {
    master[i] = static_cast<std::uint8_t>(0x71 + i);
  }
  return std::make_shared<vmp::runtime::strings::KeyContext>(
      vmp::runtime::strings::MasterKeyHandle([master]() { return master; }), std::move(salt));
}

inline vmp::runtime::vm2::Vm2Module make_vm2_module(std::string_view program_body,
                                                     const std::array<std::uint8_t, 16>& seed,
                                                     const std::array<std::uint8_t, 16>& keyctx) {
  std::ostringstream text;
  text << ".keyctx 0x";
  for (auto byte : keyctx) {
    text << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
  }
  text << "\n" << program_body;
  vmp::runtime::vm2::AssembleOptions options;
  options.encrypt_opcodes = true;
  options.opcode_seed = seed;
  auto module = vmp::runtime::vm2::assemble_module_text(text.str(), options);
  module.key_context_id = keyctx;
  return module;
}

inline std::uint64_t run_vm1(vmp::runtime::vm1::Vm1Module& module,
                             vmp::runtime::bridge::BridgeRegistry* registry = nullptr) {
  vmp::runtime::vm1::Vm1Context context(module);
  context.bridge_registry = registry;
  vmp::runtime::vm1::Vm1Interpreter interpreter;
  return interpreter.execute(context).ret_int;
}

inline vmp::runtime::vm2::ExecutionResult run_vm2(vmp::runtime::vm2::Vm2Module& module,
                                                  int runs,
                                                  const std::vector<std::uint64_t>& args = {},
                                                  vmp::runtime::bridge::BridgeRegistry* registry = nullptr,
                                                  std::shared_ptr<vmp::runtime::strings::KeyContext> key_context = nullptr) {
  vmp::runtime::vm2::ExecutionResult result{};
  for (int i = 0; i < runs; ++i) {
    vmp::runtime::vm2::Vm2Context context(module);
    for (std::size_t reg = 0; reg < args.size() && reg < 8; ++reg) {
      context.r[reg] = args[reg];
    }
    context.bridge_registry = registry;
    context.key_context = key_context;
    vmp::runtime::vm2::Vm2Interpreter interpreter;
    result = interpreter.execute(context);
  }
  return result;
}

}  // namespace vmp::tests::runtime_rolling_opcode
