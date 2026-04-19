#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <vmp/runtime/integrity/crc32.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/vm1/vm1.h>
#include <vmp/runtime/vm2/vm2.h>

namespace {

struct Options {
  std::filesystem::path input;
  bool tamper = false;
  bool dump_opcode_map = false;
  std::size_t tamper_offset = 0;
  std::uint8_t tamper_byte = 0;
};

std::vector<std::uint8_t> slurp(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("failed to open input: " + path.string());
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

void write_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream output(path, std::ios::binary);
  if (!output) {
    throw std::runtime_error("failed to create output: " + path.string());
  }
  output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

std::string hex_u32(std::uint32_t value) {
  std::ostringstream oss;
  oss << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << value;
  return oss.str();
}

std::string sha256_hex(const std::vector<std::uint8_t>& bytes) {
  return vmp::runtime::strings::hex_encode(vmp::runtime::strings::sha256(bytes));
}

Options parse_args(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--dump-opcode-map") {
      options.dump_opcode_map = true;
    } else if (arg == "--tamper") {
      if (i + 1 >= argc) {
        throw std::runtime_error("--tamper requires <offset>:<byte>");
      }
      const std::string spec = argv[++i];
      const auto colon = spec.find(':');
      if (colon == std::string::npos) {
        throw std::runtime_error("tamper spec must be <offset>:<byte>");
      }
      options.tamper = true;
      options.tamper_offset = static_cast<std::size_t>(std::stoull(spec.substr(0, colon), nullptr, 0));
      options.tamper_byte = static_cast<std::uint8_t>(std::stoul(spec.substr(colon + 1), nullptr, 16));
    } else if (!arg.empty() && arg[0] == '-') {
      throw std::runtime_error("unknown option: " + arg);
    } else if (!options.input.empty()) {
      throw std::runtime_error("only one input path is supported");
    } else {
      options.input = arg;
    }
  }
  if (options.input.empty()) {
    throw std::runtime_error("usage: vmp-integrity-probe [--dump-opcode-map] [--tamper <offset>:<byte>] <binary|module>");
  }
  return options;
}

void validate_module_if_needed(const std::filesystem::path& path) {
  const auto ext = path.extension().string();
  if (ext == ".vm1") {
    (void)vmp::runtime::vm1::Vm1Module::load_from_file(path.string());
  } else if (ext == ".vm2") {
    (void)vmp::runtime::vm2::Vm2Module::load_from_file(path.string());
  }
}

std::string hex_bytes(const std::uint8_t* data, std::size_t size) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < size; ++i) {
    oss << std::setw(2) << static_cast<unsigned>(data[i]);
  }
  return oss.str();
}

std::string hex_words(const std::vector<std::uint16_t>& words) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < words.size(); ++i) {
    if (i != 0) {
      oss << ' ';
    }
    oss << std::setw(4) << words[i];
  }
  return oss.str();
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const auto options = parse_args(argc, argv);
    if (options.dump_opcode_map) {
      const auto ext = options.input.extension().string();
      if (ext == ".vm1") {
        const auto module = vmp::runtime::vm1::Vm1Module::load_from_file(options.input.string());
        const auto cryptor = (module.module_flags & vmp::runtime::vm1::VMP_FLAG_OPCODE_ENCRYPTED) != 0
                                 ? vmp::runtime::vm1::OpcodeCryptor::from_seed({}, module.opcode_map_seed)
                                 : vmp::runtime::vm1::OpcodeCryptor::identity();
        std::cout << "vm=vm1\n";
        std::cout << "flags=0x" << std::hex << std::setw(4) << std::setfill('0') << module.module_flags << std::dec << '\n';
        std::cout << "opcode_seed=" << hex_bytes(module.opcode_map_seed.data(), module.opcode_map_seed.size()) << '\n';
        std::cout << "P=" << hex_words(cryptor.encoded_words()) << '\n';
        std::cout << "Q=" << hex_words(cryptor.decoded_words()) << '\n';
        return 0;
      }
      if (ext == ".vm2") {
        const auto module = vmp::runtime::vm2::Vm2Module::load_from_file(options.input.string());
        const auto cryptor = (module.module_flags & vmp::runtime::vm2::VMP_FLAG_OPCODE_ENCRYPTED) != 0
                                 ? vmp::runtime::vm2::OpcodeCryptor::from_seed(module.key_context_id, module.opcode_map_seed)
                                 : vmp::runtime::vm2::OpcodeCryptor::identity();
        std::cout << "vm=vm2\n";
        std::cout << "flags=0x" << std::hex << std::setw(4) << std::setfill('0') << module.module_flags << std::dec << '\n';
        std::cout << "opcode_seed=" << hex_bytes(module.opcode_map_seed.data(), module.opcode_map_seed.size()) << '\n';
        std::cout << "key_context_id=" << hex_bytes(module.key_context_id.data(), module.key_context_id.size()) << '\n';
        std::cout << "P=" << hex_words(cryptor.encoded_words()) << '\n';
        std::cout << "Q=" << hex_words(cryptor.decoded_words()) << '\n';
        return 0;
      }
      throw std::runtime_error("--dump-opcode-map only supports .vm1 and .vm2 modules");
    }

    const auto original_bytes = slurp(options.input);
    validate_module_if_needed(options.input);

    const auto original_crc32 = vmp::runtime::integrity::crc32_compute(original_bytes.data(), original_bytes.size());
    const auto original_sha256 = sha256_hex(original_bytes);

    std::cout << "path=" << options.input.string() << '\n';
    std::cout << "crc32=" << hex_u32(original_crc32) << '\n';
    std::cout << "sha256=" << original_sha256 << '\n';

    if (!options.tamper) {
      return 0;
    }

    if (options.tamper_offset >= original_bytes.size()) {
      throw std::runtime_error("tamper offset out of range");
    }

    auto tampered = original_bytes;
    tampered[options.tamper_offset] = options.tamper_byte;
    const auto tampered_path = std::filesystem::temp_directory_path() /
                               ("vmp_integrity_probe_" + options.input.filename().string());
    write_file(tampered_path, tampered);

    std::string module_error;
    try {
      validate_module_if_needed(tampered_path);
    } catch (const std::exception& ex) {
      module_error = ex.what();
    }

    const auto tampered_crc32 = vmp::runtime::integrity::crc32_compute(tampered.data(), tampered.size());
    const auto tampered_sha256 = sha256_hex(tampered);
    const bool mismatch = (tampered_crc32 != original_crc32) || (tampered_sha256 != original_sha256) || !module_error.empty();

    std::cout << "tamper_copy=" << tampered_path.string() << '\n';
    std::cout << "tampered_crc32=" << hex_u32(tampered_crc32) << '\n';
    std::cout << "tampered_sha256=" << tampered_sha256 << '\n';
    if (!module_error.empty()) {
      std::cout << "module_validation_error=" << module_error << '\n';
    }
    std::cout << "mismatch=" << (mismatch ? 1 : 0) << '\n';
    return mismatch ? 3 : 0;
  } catch (const std::exception& ex) {
    std::cerr << "vmp-integrity-probe failed: " << ex.what() << '\n';
    return 1;
  }
}
