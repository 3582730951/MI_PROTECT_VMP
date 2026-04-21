#pragma once

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace vmp::tests::runtime_stack_probe {

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

}  // namespace vmp::tests::runtime_stack_probe
