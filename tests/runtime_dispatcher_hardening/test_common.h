#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace vmp::tests::runtime_dispatcher_hardening {

inline void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

inline std::filesystem::path temp_path(const std::string& stem, const std::string& ext) {
  return std::filesystem::temp_directory_path() /
         (stem + "_" + std::to_string(static_cast<long long>(::getpid())) + ext);
}

inline std::string read_all(const std::filesystem::path& path) {
  std::ifstream input(path);
  std::ostringstream oss;
  oss << input.rdbuf();
  return oss.str();
}

class ExecutableBuffer {
 public:
  explicit ExecutableBuffer(std::vector<std::uint8_t> bytes) : size_(bytes.size()) {
#if defined(_WIN32)
    storage_ = static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, size_, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (storage_ == nullptr) {
      throw std::runtime_error("VirtualAlloc failed");
    }
#else
    storage_ = static_cast<std::uint8_t*>(::mmap(nullptr,
                                                 size_,
                                                 PROT_READ | PROT_WRITE | PROT_EXEC,
                                                 MAP_PRIVATE | MAP_ANONYMOUS,
                                                 -1,
                                                 0));
    if (storage_ == MAP_FAILED) {
      throw std::runtime_error("mmap failed");
    }
#endif
    std::memcpy(storage_, bytes.data(), bytes.size());
  }

  ~ExecutableBuffer() {
#if defined(_WIN32)
    if (storage_ != nullptr) {
      ::VirtualFree(storage_, 0, MEM_RELEASE);
    }
#else
    if (storage_ != nullptr && storage_ != MAP_FAILED) {
      ::munmap(storage_, size_);
    }
#endif
  }

  ExecutableBuffer(const ExecutableBuffer&) = delete;
  ExecutableBuffer& operator=(const ExecutableBuffer&) = delete;

  std::uintptr_t address() const noexcept { return reinterpret_cast<std::uintptr_t>(storage_); }
  const std::uint8_t* data() const noexcept { return storage_; }
  std::size_t size() const noexcept { return size_; }

  void patch(std::size_t offset, std::uint8_t value) {
    require(offset < size_, "patch offset out of range");
    storage_[offset] = value;
  }

 private:
  std::uint8_t* storage_ = nullptr;
  std::size_t size_ = 0;
};

inline std::vector<std::uint8_t> pattern(std::uint8_t seed, std::size_t size) {
  std::vector<std::uint8_t> out(size);
  for (std::size_t i = 0; i < size; ++i) {
    out[i] = static_cast<std::uint8_t>(seed + static_cast<std::uint8_t>(i));
  }
  return out;
}

}  // namespace vmp::tests::runtime_dispatcher_hardening
