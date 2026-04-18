#pragma once

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>

namespace vmp::tests::runtime_state_machine {

inline void require(bool cond, const std::string& msg) {
  if (!cond) throw std::runtime_error(msg);
}

inline std::filesystem::path temp_path(const std::string& stem, const std::string& ext) {
  return std::filesystem::temp_directory_path() /
         (stem + "_" + std::to_string(::getpid()) + "_" + std::to_string(std::rand()) + ext);
}

inline std::string read_all(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream oss;
  oss << in.rdbuf();
  return oss.str();
}

inline std::string shell_quote(const std::string& s) {
  std::string out = "'";
  for (char ch : s) out += (ch == '\'' ? "'\\''" : std::string(1, ch));
  out += "'";
  return out;
}

}  // namespace vmp::tests::runtime_state_machine
