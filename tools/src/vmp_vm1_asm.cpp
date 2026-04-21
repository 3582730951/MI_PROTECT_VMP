#include <array>
#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <vmp/runtime/vm1/vm1.h>

namespace {
std::string slurp(const std::string& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to open asm input: " + path);
  }
  return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

std::vector<std::uint8_t> slurp_bytes(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("failed to open module input: " + path);
  }
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

std::string hex_u32(std::uint32_t value) {
  std::ostringstream oss;
  oss << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << value;
  return oss.str();
}

std::array<std::uint8_t, vmp::runtime::vm1::kOpcodeMapSeedSize> parse_seed_hex(const std::string& hex) {
  if (hex.size() != vmp::runtime::vm1::kOpcodeMapSeedSize * 2u) {
    throw std::runtime_error("opcode seed must be exactly 32 hex chars");
  }
  auto nibble = [](char ch) -> std::uint8_t {
    if (ch >= '0' && ch <= '9') return static_cast<std::uint8_t>(ch - '0');
    if (ch >= 'a' && ch <= 'f') return static_cast<std::uint8_t>(10 + ch - 'a');
    if (ch >= 'A' && ch <= 'F') return static_cast<std::uint8_t>(10 + ch - 'A');
    throw std::runtime_error("opcode seed contains non-hex characters");
  };
  std::array<std::uint8_t, vmp::runtime::vm1::kOpcodeMapSeedSize> out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>((nibble(hex[i * 2]) << 4u) | nibble(hex[i * 2 + 1]));
  }
  return out;
}

struct Options {
  bool crc_only = false;
  bool encrypt_opcodes = true;
  bool reverse_layout = false;
  std::optional<std::array<std::uint8_t, vmp::runtime::vm1::kOpcodeMapSeedSize>> opcode_seed;
  std::string input_path;
  std::string output_path;
};

Options parse_args(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--crc-only") {
      options.crc_only = true;
    } else if (arg == "--encrypt-opcodes") {
      options.encrypt_opcodes = true;
    } else if (arg == "--no-encrypt-opcodes") {
      options.encrypt_opcodes = false;
    } else if (arg == "--reverse-layout") {
      options.reverse_layout = true;
    } else if (arg == "--no-reverse-layout") {
      options.reverse_layout = false;
    } else if (arg == "--opcode-seed") {
      if (i + 1 >= argc) {
        throw std::runtime_error("--opcode-seed requires <32-hex-char-seed>");
      }
      options.opcode_seed = parse_seed_hex(argv[++i]);
    } else if (!arg.empty() && arg[0] == '-') {
      throw std::runtime_error("unknown argument: " + arg);
    } else if (options.input_path.empty()) {
      options.input_path = arg;
    } else if (options.output_path.empty()) {
      options.output_path = arg;
    } else {
      throw std::runtime_error("too many positional arguments");
    }
  }

  if (options.crc_only) {
    if (options.input_path.empty() || !options.output_path.empty()) {
      throw std::runtime_error("usage: vmp-vm1-asm --crc-only <module.vm1>");
    }
    return options;
  }

  if (options.input_path.empty() || options.output_path.empty()) {
    throw std::runtime_error("usage: vmp-vm1-asm [--encrypt-opcodes|--no-encrypt-opcodes] [--reverse-layout|--no-reverse-layout] [--opcode-seed <32-hex>] <input.vm1s> <output.vm1>");
  }
  if (!options.opcode_seed.has_value()) {
    if (const char* env_seed = std::getenv("VMP_OPCODE_MAP_SEED"); env_seed != nullptr && *env_seed != '\0') {
      options.opcode_seed = parse_seed_hex(env_seed);
    }
  }
  return options;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    const auto options = parse_args(argc, argv);
    if (options.crc_only) {
      const auto bytes = slurp_bytes(options.input_path);
      std::cout << hex_u32(vmp::runtime::vm1::serialized_body_crc32(bytes)) << "\n";
      return 0;
    }
    vmp::runtime::vm1::AssembleOptions assemble_options;
    assemble_options.encrypt_opcodes = options.encrypt_opcodes;
    if (options.reverse_layout) {
      assemble_options.module_flags = static_cast<std::uint16_t>(assemble_options.module_flags | vmp::runtime::vm1::VMP_FLAG_REVERSE_ORDER);
    }
    assemble_options.opcode_seed = options.opcode_seed;
    const auto module = vmp::runtime::vm1::assemble_module_text(slurp(options.input_path), assemble_options);
    module.save_to_file(options.output_path);
    std::cout << "assembled " << options.input_path << " -> " << options.output_path << "\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "vmp-vm1-asm failed: " << ex.what() << '\n';
    return 1;
  }
}
