#pragma once

#include <stdexcept>
#include <string>

#include <vmp/runtime/obfuscation/mba.h>
#include <vmp/runtime/vm1/vm1.h>
#include <vmp/runtime/vm2/vm2.h>

namespace vmp::tests::runtime_bogus_flow {

inline void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

inline std::size_t count_label_defs(std::string_view text, std::string_view prefix) {
  std::size_t count = 0;
  std::size_t start = 0;
  while (start < text.size()) {
    const auto end = text.find('\n', start);
    const auto line = text.substr(start, end == std::string_view::npos ? text.size() - start : end - start);
    if (line.rfind(prefix, 0) == 0) {
      ++count;
    }
    if (end == std::string_view::npos) {
      break;
    }
    start = end + 1;
  }
  return count;
}

inline std::size_t count_substring(std::string_view text, std::string_view needle) {
  if (needle.empty()) {
    return 0;
  }
  std::size_t count = 0;
  std::size_t pos = 0;
  while ((pos = text.find(needle, pos)) != std::string_view::npos) {
    ++count;
    pos += needle.size();
  }
  return count;
}

inline std::string extract_first_labeled_block(std::string_view text,
                                               std::string_view begin_prefix,
                                               std::string_view end_prefix) {
  const auto begin = text.find(begin_prefix);
  if (begin == std::string_view::npos) {
    return {};
  }
  const auto end = text.find(end_prefix, begin + begin_prefix.size());
  if (end == std::string_view::npos || end <= begin) {
    return {};
  }
  return std::string(text.substr(begin, end - begin));
}

inline std::size_t count_opcode_lines(std::string_view text, std::string_view opcode_prefix) {
  std::size_t count = 0;
  std::size_t start = 0;
  while (start < text.size()) {
    const auto end = text.find('\n', start);
    auto line = text.substr(start, end == std::string_view::npos ? text.size() - start : end - start);
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
      line.remove_prefix(1);
    }
    if (line.rfind(opcode_prefix, 0) == 0) {
      ++count;
    }
    if (end == std::string_view::npos) {
      break;
    }
    start = end + 1;
  }
  return count;
}

}  // namespace vmp::tests::runtime_bogus_flow
