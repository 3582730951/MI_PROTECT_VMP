#pragma once

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace vmp::tests::runtime_env_detectors {

inline void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

inline std::filesystem::path temp_path(const std::string& stem, const std::string& ext) {
#if defined(_WIN32)
  const auto pid = static_cast<long>(::_getpid());
#else
  const auto pid = static_cast<long>(::getpid());
#endif
  return std::filesystem::temp_directory_path() /
         (stem + "_" + std::to_string(pid) + "_" + std::to_string(std::rand()) + ext);
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

}  // namespace vmp::tests::runtime_env_detectors
