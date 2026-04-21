#if defined(_WIN32)

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <windows.h>

namespace vmp::runtime::trusted_oracle::windows_syscall {
namespace {

struct StubCache {
  std::mutex mutex;
  std::unordered_map<std::string, void*> stubs;
};

StubCache& cache() {
  static StubCache value;
  return value;
}

std::uint32_t resolve_syscall_number(const char* name) {
  HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    ntdll = ::LoadLibraryW(L"ntdll.dll");
  }
  if (ntdll == nullptr) {
    return 0;
  }
  auto* bytes = static_cast<const std::uint8_t*>(::GetProcAddress(ntdll, name));
  if (bytes == nullptr) {
    return 0;
  }
  for (std::size_t i = 0; i + 8 < 32; ++i) {
    if (bytes[i] == 0x4c && bytes[i + 1] == 0x8b && bytes[i + 2] == 0xd1 && bytes[i + 3] == 0xb8) {
      std::uint32_t number = 0;
      std::memcpy(&number, bytes + i + 4, sizeof(number));
      return number;
    }
  }
  return 0;
}

void* build_stub(std::uint32_t syscall_number) {
  std::array<std::uint8_t, 11> code{{0x4c, 0x8b, 0xd1, 0xb8, 0, 0, 0, 0, 0x0f, 0x05, 0xc3}};
  std::memcpy(code.data() + 4, &syscall_number, sizeof(syscall_number));
  void* page = ::VirtualAlloc(nullptr, code.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (page == nullptr) {
    return nullptr;
  }
  std::memcpy(page, code.data(), code.size());
  ::FlushInstructionCache(::GetCurrentProcess(), page, code.size());
  return page;
}

}  // namespace

void* resolve_stub(const char* name) {
  auto& value = cache();
  std::lock_guard<std::mutex> lock(value.mutex);
  if (auto it = value.stubs.find(name); it != value.stubs.end()) {
    return it->second;
  }
  const auto number = resolve_syscall_number(name);
  if (number == 0) {
    value.stubs.emplace(name, nullptr);
    return nullptr;
  }
  void* stub = build_stub(number);
  value.stubs.emplace(name, stub);
  return stub;
}

}  // namespace vmp::runtime::trusted_oracle::windows_syscall

#endif
