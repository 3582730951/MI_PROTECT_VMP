#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <vmp/runtime/vm1/vm1.h>
#include <vmp/runtime/vm2/vm2.h>

namespace vmp::tests::runtime_reverse_layout {

inline void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

inline void require_int(std::uint64_t actual, std::uint64_t expected, const std::string& label) {
  if (actual != expected) {
    throw std::runtime_error(label + ": expected=" + std::to_string(expected) + " actual=" + std::to_string(actual));
  }
}

inline std::filesystem::path repo_path(const std::string& relative) {
  return std::filesystem::path(VMP_TEST_SOURCE_DIR) / relative;
}

inline std::string read_text(const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to open " + path.string());
  }
  std::ostringstream oss;
  oss << input.rdbuf();
  return oss.str();
}

inline std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("failed to open " + path.string());
  }
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

template <typename Module>
inline std::vector<std::uint8_t> mirror_instruction_blocks(const std::vector<std::uint8_t>& forward_code,
                                                           const Module& module) {
  std::vector<std::uint8_t> mirrored;
  mirrored.reserve(forward_code.size());
  std::size_t forward_pc = 0;
  std::vector<std::vector<std::uint8_t>> blocks;
  blocks.reserve(module.reverse_insn_lengths.size());
  for (std::uint16_t length : module.reverse_insn_lengths) {
    require(length != 0u, "zero instruction length");
    require(forward_pc + length <= forward_code.size(), "length table exceeds code size");
    blocks.emplace_back(forward_code.begin() + static_cast<std::ptrdiff_t>(forward_pc),
                        forward_code.begin() + static_cast<std::ptrdiff_t>(forward_pc + length));
    forward_pc += length;
  }
  require(forward_pc == forward_code.size(), "length table sum must equal code size");
  for (auto it = blocks.rbegin(); it != blocks.rend(); ++it) {
    mirrored.insert(mirrored.end(), it->begin(), it->end());
  }
  return mirrored;
}

struct Vm1ImageView {
  std::uint16_t version = 0;
  std::uint16_t flags = 0;
  std::uint32_t code_size = 0;
  std::size_t code_offset = 0;
  std::vector<std::uint8_t> code;
};

inline Vm1ImageView parse_vm1_image(const std::vector<std::uint8_t>& image) {
  require(image.size() >= 24u, "vm1 image too small");
  require(std::string(image.begin(), image.begin() + 4) == "VM1B", "vm1 bad magic");
  Vm1ImageView view;
  view.version = static_cast<std::uint16_t>(image[4]) | static_cast<std::uint16_t>(image[5] << 8u);
  view.flags = static_cast<std::uint16_t>(image[6]) | static_cast<std::uint16_t>(image[7] << 8u);
  view.code_size = static_cast<std::uint32_t>(image[12]) |
                   (static_cast<std::uint32_t>(image[13]) << 8u) |
                   (static_cast<std::uint32_t>(image[14]) << 16u) |
                   (static_cast<std::uint32_t>(image[15]) << 24u);
  view.code_offset = view.version == vmp::runtime::vm1::kVm1Version ? 40u : 24u;
  require(view.code_offset + view.code_size <= image.size(), "vm1 code section truncated");
  view.code.assign(image.begin() + static_cast<std::ptrdiff_t>(view.code_offset),
                   image.begin() + static_cast<std::ptrdiff_t>(view.code_offset + view.code_size));
  return view;
}

struct Vm2ImageView {
  std::uint16_t version = 0;
  std::uint16_t flags = 0;
  std::uint32_t code_size = 0;
  std::size_t code_offset = 0;
  std::vector<std::uint8_t> code;
};

inline Vm2ImageView parse_vm2_image(const std::vector<std::uint8_t>& image) {
  require(image.size() >= 24u + vmp::runtime::vm2::kVm2KeyContextIdSize, "vm2 image too small");
  require(std::string(image.begin(), image.begin() + 4) == "VMP2", "vm2 bad magic");
  Vm2ImageView view;
  view.version = static_cast<std::uint16_t>(image[4]) | static_cast<std::uint16_t>(image[5] << 8u);
  view.flags = static_cast<std::uint16_t>(image[6]) | static_cast<std::uint16_t>(image[7] << 8u);
  view.code_size = static_cast<std::uint32_t>(image[12]) |
                   (static_cast<std::uint32_t>(image[13]) << 8u) |
                   (static_cast<std::uint32_t>(image[14]) << 16u) |
                   (static_cast<std::uint32_t>(image[15]) << 24u);
  view.code_offset = view.version == vmp::runtime::vm2::kVm2Version ? 40u : 24u;
  require(view.code_offset + view.code_size <= image.size(), "vm2 code section truncated");
  view.code.assign(image.begin() + static_cast<std::ptrdiff_t>(view.code_offset),
                   image.begin() + static_cast<std::ptrdiff_t>(view.code_offset + view.code_size));
  return view;
}

inline std::uint64_t execute_vm1(const vmp::runtime::vm1::Vm1Module& module, std::uint64_t arg0) {
  vmp::runtime::vm1::Vm1Context context(module);
  context.vr[0] = arg0;
  vmp::runtime::vm1::Vm1Interpreter interpreter;
  return interpreter.execute(context).ret_int;
}

inline std::uint64_t execute_vm2(const vmp::runtime::vm2::Vm2Module& module, std::uint64_t arg0) {
  vmp::runtime::vm2::Vm2Context context(module);
  context.r[0] = arg0;
  vmp::runtime::vm2::Vm2Interpreter interpreter;
  return interpreter.execute(context).ret_int;
}

inline std::uint64_t sum_lengths(const std::vector<std::uint16_t>& lengths) {
  return std::accumulate(lengths.begin(), lengths.end(), std::uint64_t{0});
}

}  // namespace vmp::tests::runtime_reverse_layout
