#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <vmp/runtime/integrity/crc32.h>
#include <vmp/runtime/vm1/vm1.h>

namespace {

struct Options {
  bool convert_to_reverse = false;
  bool convert_to_forward = false;
  std::string module_path;
};

std::vector<std::uint8_t> length_bytes(const std::vector<std::uint16_t>& lengths) {
  std::vector<std::uint8_t> out;
  out.reserve(lengths.size() * sizeof(std::uint16_t));
  for (const auto length : lengths) {
    out.push_back(static_cast<std::uint8_t>(length & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((length >> 8u) & 0xFFu));
  }
  return out;
}

std::uint32_t length_checksum(const std::vector<std::uint16_t>& lengths) {
  const auto bytes = length_bytes(lengths);
  return vmp::runtime::integrity::crc32_compute(bytes.data(), bytes.size());
}

Options parse_args(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--convert-to-reverse") {
      options.convert_to_reverse = true;
    } else if (arg == "--convert-to-forward") {
      options.convert_to_forward = true;
    } else if (!arg.empty() && arg[0] == '-') {
      throw std::runtime_error("unknown argument: " + arg);
    } else if (options.module_path.empty()) {
      options.module_path = arg;
    } else {
      throw std::runtime_error("too many positional arguments");
    }
  }
  if (options.module_path.empty()) {
    throw std::runtime_error("usage: vmp-vm1-layout [--convert-to-reverse|--convert-to-forward] <module.vm1>");
  }
  if (options.convert_to_reverse && options.convert_to_forward) {
    throw std::runtime_error("choose at most one of --convert-to-reverse or --convert-to-forward");
  }
  return options;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const auto options = parse_args(argc, argv);
    auto module = vmp::runtime::vm1::Vm1Module::load_from_file(options.module_path);
    if (options.convert_to_reverse) {
      module.module_flags = static_cast<std::uint16_t>(module.module_flags | vmp::runtime::vm1::VMP_FLAG_REVERSE_ORDER);
      module.save_to_file(options.module_path);
      module = vmp::runtime::vm1::Vm1Module::load_from_file(options.module_path);
    } else if (options.convert_to_forward) {
      module.module_flags = static_cast<std::uint16_t>(module.module_flags & ~vmp::runtime::vm1::VMP_FLAG_REVERSE_ORDER);
      module.save_to_file(options.module_path);
      module = vmp::runtime::vm1::Vm1Module::load_from_file(options.module_path);
    }

    const auto lengths = vmp::runtime::vm1::instruction_lengths(module);
    std::cout << "layout=" << (((module.module_flags & vmp::runtime::vm1::VMP_FLAG_REVERSE_ORDER) != 0u) ? "reverse" : "forward")
              << " instruction_count=" << lengths.size()
              << " length_table_checksum=0x" << std::hex << std::uppercase << length_checksum(lengths) << std::dec << "\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "vmp-vm1-layout failed: " << ex.what() << '\n';
    return 1;
  }
}
