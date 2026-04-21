#include <vmp/runtime/trusted_oracle/oracle.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <future>
#include <iomanip>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <utility>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/trusted_oracle/syscall_nr.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
#include <dlfcn.h>
#include <signal.h>
#include <time.h>
#endif

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/ptrace.h>
#include <sys/wait.h>
#endif

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

#if defined(_WIN32)
namespace vmp::runtime::trusted_oracle::windows_syscall {
void* resolve_stub(const char* name);
}  // namespace vmp::runtime::trusted_oracle::windows_syscall
#endif

#if defined(__linux__) && defined(__x86_64__)
extern "C" std::intptr_t vmp_trusted_oracle_linux_x64_syscall6(std::uint64_t,
                                                               std::uintptr_t,
                                                               std::uintptr_t,
                                                               std::uintptr_t,
                                                               std::uintptr_t,
                                                               std::uintptr_t,
                                                               std::uintptr_t);
#elif defined(__linux__) && defined(__aarch64__)
extern "C" std::intptr_t vmp_trusted_oracle_linux_arm64_syscall6(std::uint64_t,
                                                                  std::uintptr_t,
                                                                  std::uintptr_t,
                                                                  std::uintptr_t,
                                                                  std::uintptr_t,
                                                                  std::uintptr_t,
                                                                  std::uintptr_t);
#elif defined(__APPLE__) && defined(__aarch64__)
extern "C" std::intptr_t vmp_trusted_oracle_ios_arm64_syscall6(std::uint64_t,
                                                                std::uintptr_t,
                                                                std::uintptr_t,
                                                                std::uintptr_t,
                                                                std::uintptr_t,
                                                                std::uintptr_t,
                                                                std::uintptr_t);
#endif

namespace vmp::runtime::trusted_oracle {
namespace {

using Clock = std::chrono::steady_clock;
constexpr const char* kModuleName = "trusted_oracle";
constexpr std::size_t kMaxSyscallErrno = 4095;
constexpr std::uintptr_t kAtFdcwd = static_cast<std::uintptr_t>(-100);
constexpr std::uintptr_t kKernelSigsetSize = 8;
constexpr std::array<const char*, 9> kDefaultApiNames{{
    "open",
    "read",
    "close",
    "ptrace",
    "clock_gettime",
    "getrandom",
    "sigaction",
    "prctl",
    "pthread_create",
}};

struct BootstrapSample {
  std::string name;
  const void* address = nullptr;
  std::array<std::uint8_t, kApiPrologueWidth> bytes{};
  std::size_t width = 0;
};

struct BootstrapRegistry {
  std::once_flag once;
  std::vector<BootstrapSample> samples;
};

BootstrapRegistry& bootstrap_registry() {
  static BootstrapRegistry registry;
  return registry;
}

std::string bool_text(bool value) { return value ? "true" : "false"; }

bool key_is_zero(const KeyContextId& key) {
  return std::all_of(key.begin(), key.end(), [](std::uint8_t byte) { return byte == 0; });
}

KeyContextId normalize_key_context(KeyContextId key) {
  if (!key_is_zero(key)) {
    return key;
  }
  const auto digest = vmp::runtime::strings::sha256(vmp::runtime::strings::to_bytes("vmp.trusted_oracle.default_keyctx.v1"));
  std::copy_n(digest.begin(), key.size(), key.begin());
  return key;
}

std::string hex_bytes(std::string_view label, const std::vector<std::uint8_t>& bytes) {
  std::ostringstream oss;
  oss << label << "=" << vmp::runtime::strings::hex_encode(bytes);
  return oss.str();
}

std::vector<std::uint8_t> read_region_bytes(const void* address, std::size_t width) {
  if (address == nullptr || width == 0) {
    return {};
  }
  std::vector<std::uint8_t> out(width, 0);
  std::memcpy(out.data(), address, width);
  return out;
}

const void* resolve_symbol(const char* name) {
#if defined(_WIN32)
  HMODULE modules[] = {
      ::GetModuleHandleW(L"kernel32.dll"),
      ::GetModuleHandleW(L"ntdll.dll"),
      ::GetModuleHandleW(L"ucrtbase.dll"),
      ::GetModuleHandleW(L"msvcrt.dll"),
  };
  for (HMODULE module : modules) {
    if (module == nullptr) {
      continue;
    }
    if (auto* proc = reinterpret_cast<const void*>(::GetProcAddress(module, name)); proc != nullptr) {
      return proc;
    }
  }
  return nullptr;
#elif defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
  return dlsym(RTLD_DEFAULT, name);
#else
  (void)name;
  return nullptr;
#endif
}

void bootstrap_capture() {
  auto& registry = bootstrap_registry();
  std::call_once(registry.once, [&]() {
    for (const char* name : kDefaultApiNames) {
      if (const void* address = resolve_symbol(name); address != nullptr) {
        BootstrapSample sample;
        sample.name = name;
        sample.address = address;
        sample.width = kApiPrologueWidth;
        const auto bytes = read_region_bytes(address, sample.width);
        std::copy(bytes.begin(), bytes.end(), sample.bytes.begin());
        registry.samples.push_back(std::move(sample));
      }
    }
  });
}

const std::vector<BootstrapSample>& bootstrap_samples() {
  bootstrap_capture();
  return bootstrap_registry().samples;
}

#if defined(__linux__) || defined(__ANDROID__)
extern "C" __attribute__((visibility("default"), constructor(102))) void vmp_trusted_oracle_bootstrap_ctor(void);
extern "C" __attribute__((visibility("default"), constructor(102))) void vmp_trusted_oracle_bootstrap_ctor(void) {
  bootstrap_capture();
}
using vmp_trusted_oracle_ctor_fn = void (*)(void);
__attribute__((used, section(".init_array"))) static vmp_trusted_oracle_ctor_fn vmp_trusted_oracle_bootstrap_fallback =
    vmp_trusted_oracle_bootstrap_ctor;
#elif defined(__APPLE__)
extern "C" __attribute__((visibility("default"), constructor(102))) void vmp_trusted_oracle_bootstrap_ctor(void) {
  bootstrap_capture();
}
#endif

std::uint64_t as_ns(const DirectTimespec& ts) {
  return static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ull + static_cast<std::uint64_t>(ts.tv_nsec);
}

std::uint64_t read_counter() {
#if defined(__x86_64__) || defined(_M_X64)
  unsigned aux = 0;
  return __rdtscp(&aux);
#elif defined(__aarch64__)
  std::uint64_t value = 0;
  asm volatile("mrs %0, cntvct_el0" : "=r"(value));
  return value;
#else
  return 0;
#endif
}

bool fill_hardware_random(std::size_t size, std::vector<std::uint8_t>& out) {
  out.assign(size, 0);
#if defined(__x86_64__) || defined(_M_X64)
  auto rdrand64 = [](unsigned long long* value) -> int {
    unsigned char ok = 0;
    asm volatile("rdrand %0; setc %1" : "=r"(*value), "=qm"(ok));
    return static_cast<int>(ok);
  };
  auto rdseed64 = [](unsigned long long* value) -> int {
    unsigned char ok = 0;
    asm volatile("rdseed %0; setc %1" : "=r"(*value), "=qm"(ok));
    return static_cast<int>(ok);
  };
  std::size_t produced = 0;
  while (produced < size) {
    unsigned long long value = 0;
    int ok = rdrand64(&value);
    if (ok == 0) {
      ok = rdseed64(&value);
    }
    if (ok == 0) {
      out.clear();
      return false;
    }
    const auto to_copy = std::min<std::size_t>(sizeof(value), size - produced);
    std::memcpy(out.data() + produced, &value, to_copy);
    produced += to_copy;
  }
  return true;
#else
  out.clear();
  return false;
#endif
}

bool all_zero(const std::vector<std::uint8_t>& bytes) {
  return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t byte) { return byte == 0; });
}

std::set<std::uint64_t> enumerate_task_tids() {
  std::set<std::uint64_t> tids;
#if defined(__linux__) || defined(__ANDROID__)
  const std::filesystem::path task_dir("/proc/self/task");
  std::error_code ec;
  for (std::filesystem::directory_iterator it(task_dir, ec), end; !ec && it != end; it.increment(ec)) {
    if (const auto name = it->path().filename().string(); !name.empty()) {
      try {
        tids.insert(static_cast<std::uint64_t>(std::stoull(name)));
      } catch (...) {
      }
    }
  }
#endif
  return tids;
}

std::uint64_t wait_for_new_tid(const std::set<std::uint64_t>& before) {
  for (int attempt = 0; attempt < 100; ++attempt) {
    const auto now = enumerate_task_tids();
    for (auto tid : now) {
      if (before.find(tid) == before.end()) {
        return tid;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return 0;
}

int parse_tracer_pid(std::string_view status) {
  constexpr std::string_view needle = "TracerPid:";
  const auto pos = status.find(needle);
  if (pos == std::string_view::npos) {
    return -1;
  }
  std::size_t i = pos + needle.size();
  while (i < status.size() && (status[i] == ' ' || status[i] == '\t')) {
    ++i;
  }
  int value = 0;
  while (i < status.size() && status[i] >= '0' && status[i] <= '9') {
    value = (value * 10) + (status[i] - '0');
    ++i;
  }
  return value;
}

std::string read_file_direct(const char* path) {
  const int fd = DirectSyscall::open_readonly(path);
  if (fd < 0) {
    return {};
  }
  std::string out;
  std::array<char, 512> buffer{};
  for (;;) {
    const auto got = DirectSyscall::read(fd, buffer.data(), buffer.size());
    if (got <= 0) {
      break;
    }
    out.append(buffer.data(), static_cast<std::size_t>(got));
  }
  (void)DirectSyscall::close(fd);
  return out;
}

std::intptr_t normalize_linux_ret(std::intptr_t value) noexcept {
#if defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
  if (value < 0 && value >= -static_cast<std::intptr_t>(kMaxSyscallErrno)) {
    errno = static_cast<int>(-value);
    return -1;
  }
#else
  (void)value;
#endif
  return value;
}

std::array<std::uint8_t, 16> derive_aes_key(const KeyContextId& key_context_id,
                                            std::string_view name,
                                            std::string_view label) {
  std::vector<std::uint8_t> salt(key_context_id.begin(), key_context_id.end());
  auto ikm = vmp::runtime::strings::to_bytes(std::string(name) + ":" + std::string(label));
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(salt, ikm);
  const auto okm = vmp::runtime::strings::hkdf_expand_sha256(prk,
                                                             vmp::runtime::strings::to_bytes("vmp.trusted_oracle.aes.v1"),
                                                             16);
  std::array<std::uint8_t, 16> out{};
  std::copy(okm.begin(), okm.end(), out.begin());
  vmp::runtime::strings::secure_memzero(salt.data(), salt.size());
  vmp::runtime::strings::secure_memzero(ikm.data(), ikm.size());
  return out;
}

std::array<std::uint8_t, 176> aes_expand_key(const std::array<std::uint8_t, 16>& key) {
  static constexpr std::array<std::uint8_t, 256> kSbox{{
      0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
      0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
      0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
      0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
      0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
      0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
      0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
      0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
      0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
      0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
      0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
      0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
      0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
      0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
      0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
      0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
  }};
  static constexpr std::array<std::uint8_t, 10> kRcon{{0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36}};

  std::array<std::uint8_t, 176> schedule{};
  std::copy(key.begin(), key.end(), schedule.begin());
  std::size_t bytes_generated = 16;
  std::size_t rcon_idx = 0;
  std::array<std::uint8_t, 4> temp{};
  while (bytes_generated < schedule.size()) {
    for (std::size_t i = 0; i < 4; ++i) {
      temp[i] = schedule[bytes_generated - 4 + i];
    }
    if ((bytes_generated % 16) == 0) {
      const auto rotate = temp[0];
      temp[0] = kSbox[temp[1]] ^ kRcon[rcon_idx++];
      temp[1] = kSbox[temp[2]];
      temp[2] = kSbox[temp[3]];
      temp[3] = kSbox[rotate];
    }
    for (std::size_t i = 0; i < 4; ++i) {
      schedule[bytes_generated] = static_cast<std::uint8_t>(schedule[bytes_generated - 16] ^ temp[i]);
      ++bytes_generated;
    }
  }
  return schedule;
}

std::uint8_t xtime(std::uint8_t value) {
  return static_cast<std::uint8_t>((value << 1u) ^ ((value & 0x80u) ? 0x1bu : 0x00u));
}

std::array<std::uint8_t, 16> aes_encrypt_block(const std::array<std::uint8_t, 16>& key,
                                               const std::array<std::uint8_t, 16>& input) {
  static constexpr std::array<std::uint8_t, 256> kSbox{{
      0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
      0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
      0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
      0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
      0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
      0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
      0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
      0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
      0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
      0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
      0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
      0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
      0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
      0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
      0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
      0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
  }};

  auto state = input;
  const auto schedule = aes_expand_key(key);
  auto add_round_key = [&](std::size_t round) {
    for (std::size_t i = 0; i < state.size(); ++i) {
      state[i] ^= schedule[round * 16 + i];
    }
  };
  auto sub_bytes = [&]() {
    for (auto& byte : state) {
      byte = kSbox[byte];
    }
  };
  auto shift_rows = [&]() {
    std::array<std::uint8_t, 16> copy = state;
    state[1] = copy[5]; state[5] = copy[9]; state[9] = copy[13]; state[13] = copy[1];
    state[2] = copy[10]; state[6] = copy[14]; state[10] = copy[2]; state[14] = copy[6];
    state[3] = copy[15]; state[7] = copy[3]; state[11] = copy[7]; state[15] = copy[11];
  };
  auto mix_columns = [&]() {
    for (int col = 0; col < 4; ++col) {
      const int base = col * 4;
      const auto s0 = state[base + 0];
      const auto s1 = state[base + 1];
      const auto s2 = state[base + 2];
      const auto s3 = state[base + 3];
      const auto x0 = xtime(s0);
      const auto x1 = xtime(s1);
      const auto x2 = xtime(s2);
      const auto x3 = xtime(s3);
      state[base + 0] = static_cast<std::uint8_t>(x0 ^ (x1 ^ s1) ^ s2 ^ s3);
      state[base + 1] = static_cast<std::uint8_t>(s0 ^ x1 ^ (x2 ^ s2) ^ s3);
      state[base + 2] = static_cast<std::uint8_t>(s0 ^ s1 ^ x2 ^ (x3 ^ s3));
      state[base + 3] = static_cast<std::uint8_t>((x0 ^ s0) ^ s1 ^ s2 ^ x3);
    }
  };

  add_round_key(0);
  for (std::size_t round = 1; round < 10; ++round) {
    sub_bytes();
    shift_rows();
    mix_columns();
    add_round_key(round);
  }
  sub_bytes();
  shift_rows();
  add_round_key(10);
  return state;
}

std::vector<std::uint8_t> xor_aes_ctr_crypt(const KeyContextId& key_context_id,
                                            std::string_view name,
                                            std::string_view label,
                                            const std::vector<std::uint8_t>& input) {
  const auto key = derive_aes_key(key_context_id, name, label);
  const auto nonce = derive_aes_key(key_context_id, name, std::string(label) + ".nonce");
  std::vector<std::uint8_t> out(input.size(), 0);
  for (std::size_t block = 0; block * 16 < input.size(); ++block) {
    std::array<std::uint8_t, 16> counter_block = nonce;
    std::uint64_t counter = static_cast<std::uint64_t>(block);
    for (int i = 0; i < 8; ++i) {
      counter_block[15 - i] ^= static_cast<std::uint8_t>((counter >> (i * 8)) & 0xffu);
    }
    const auto keystream = aes_encrypt_block(key, counter_block);
    const auto offset = block * 16;
    const auto block_len = std::min<std::size_t>(16, input.size() - offset);
    for (std::size_t i = 0; i < block_len; ++i) {
      out[offset + i] = static_cast<std::uint8_t>(input[offset + i] ^ keystream[i]);
    }
  }
  return out;
}

struct PrologueEntry {
  std::string name;
  const std::uint8_t* address = nullptr;
  std::size_t width = 0;
  std::vector<std::uint8_t> resident_cipher;
  std::vector<std::uint8_t> ephemeral_cipher;
  Clock::time_point last_refresh{};
};

void set_writer_exit_noop(vmp::runtime::audit::ReactionDispatcher& dispatcher) {
  dispatcher.set_exit_fn([]() {});
  dispatcher.set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) {
    if (fn) {
      fn();
    }
  });
  dispatcher.set_delay_selector([]() { return std::chrono::milliseconds(0); });
}

std::string current_bytes_note(std::string_view name,
                               bool resident_matches,
                               bool ephemeral_matches,
                               bool divergent) {
  std::ostringstream oss;
  oss << "api=" << name << " resident_matches=" << bool_text(resident_matches)
      << " ephemeral_matches=" << bool_text(ephemeral_matches)
      << " divergent=" << bool_text(divergent);
  return oss.str();
}

}  // namespace

struct PrologueBaselineStore::Impl {
  explicit Impl(KeyContextId key_context_id_in,
                std::filesystem::path audit_path_in,
                std::chrono::seconds refresh_interval_in)
      : key_context_id(normalize_key_context(key_context_id_in)),
        audit_path(audit_path_in.empty() ? vmp::runtime::audit::AuditWriter::default_path() : std::move(audit_path_in)),
        refresh_interval(refresh_interval_in),
        writer(audit_path),
        dispatcher(writer, vmp::runtime::audit::ReactionPolicy::audit_only) {
    set_writer_exit_noop(dispatcher);
  }

  void register_seed(std::string name, const void* address, const std::vector<std::uint8_t>& baseline) {
    PrologueEntry entry;
    entry.name = std::move(name);
    entry.address = static_cast<const std::uint8_t*>(address);
    entry.width = baseline.size();
    entry.resident_cipher = xor_aes_ctr_crypt(key_context_id, entry.name, "resident", baseline);
    entry.ephemeral_cipher = xor_aes_ctr_crypt(key_context_id, entry.name, "ephemeral", baseline);
    entry.last_refresh = Clock::now();

    auto it = std::find_if(entries.begin(), entries.end(), [&](const PrologueEntry& existing) {
      return existing.name == entry.name;
    });
    if (it == entries.end()) {
      entries.push_back(std::move(entry));
    } else {
      secure_erase(it->resident_cipher);
      secure_erase(it->ephemeral_cipher);
      *it = std::move(entry);
    }
  }

  void secure_erase(std::vector<std::uint8_t>& bytes) {
    vmp::runtime::strings::secure_memzero(bytes.data(), bytes.size());
    bytes.assign(bytes.size(), 0);
  }

  std::vector<std::uint8_t> decrypt_copy(const PrologueEntry& entry, std::string_view label) const {
    const auto& cipher = (label == "resident") ? entry.resident_cipher : entry.ephemeral_cipher;
    return xor_aes_ctr_crypt(key_context_id, entry.name, label, cipher);
  }

  void refresh_if_due(PrologueEntry& entry) {
    const auto now = Clock::now();
    if (!force_refresh && (now - entry.last_refresh) < refresh_interval) {
      return;
    }
    auto plain = decrypt_copy(entry, "resident");
    auto next = xor_aes_ctr_crypt(key_context_id, entry.name, "ephemeral", plain);
    secure_erase(entry.ephemeral_cipher);
    entry.ephemeral_cipher = std::move(next);
    entry.last_refresh = now;
    force_refresh = false;
    vmp::runtime::strings::secure_memzero(plain.data(), plain.size());
  }

  KeyContextId key_context_id{};
  std::filesystem::path audit_path;
  std::chrono::seconds refresh_interval{60};
  vmp::runtime::audit::AuditWriter writer;
  vmp::runtime::audit::ReactionDispatcher dispatcher;
  std::vector<PrologueEntry> entries;
  bool defaults_registered = false;
  bool force_refresh = false;
};

PrologueBaselineStore::PrologueBaselineStore(KeyContextId key_context_id,
                                             std::filesystem::path audit_path,
                                             std::chrono::seconds refresh_interval)
    : impl_(std::make_unique<Impl>(key_context_id, std::move(audit_path), refresh_interval)) {}

PrologueBaselineStore::~PrologueBaselineStore() = default;

void PrologueBaselineStore::register_region(std::string name, const void* address, std::size_t width) {
  if (address == nullptr || width == 0) {
    throw std::runtime_error("trusted_oracle: register_region requires non-null address and width");
  }
  impl_->register_seed(std::move(name), address, read_region_bytes(address, width));
}

void PrologueBaselineStore::register_default_apis() {
  if (impl_->defaults_registered) {
    return;
  }
  for (const auto& sample : bootstrap_samples()) {
    impl_->register_seed(sample.name,
                         sample.address,
                         std::vector<std::uint8_t>(sample.bytes.begin(), sample.bytes.begin() + static_cast<std::ptrdiff_t>(sample.width)));
  }
  impl_->defaults_registered = true;
}

std::size_t PrologueBaselineStore::monitored_count() const noexcept { return impl_->entries.size(); }

BaselineVerification PrologueBaselineStore::verify_region(std::string_view name) {
  auto it = std::find_if(impl_->entries.begin(), impl_->entries.end(), [&](const PrologueEntry& entry) {
    return entry.name == name;
  });
  if (it == impl_->entries.end()) {
    throw std::runtime_error("trusted_oracle: unknown baseline region");
  }

  impl_->refresh_if_due(*it);
  auto resident_plain = impl_->decrypt_copy(*it, "resident");
  auto ephemeral_plain = impl_->decrypt_copy(*it, "ephemeral");
  const auto current = read_region_bytes(it->address, it->width);

  BaselineVerification result;
  result.resident_matches = (resident_plain == current);
  result.ephemeral_matches = (ephemeral_plain == current);
  result.current_matches = result.resident_matches && result.ephemeral_matches;
  result.divergent = (resident_plain != ephemeral_plain);
  result.ok = result.current_matches && !result.divergent;
  if (!result.ok) {
    result.event_type = "api_prologue_tampered";
    result.note = current_bytes_note(it->name, result.resident_matches, result.ephemeral_matches, result.divergent);
    impl_->writer.append(vmp::runtime::audit::make_event(result.event_type, result.note, 0, kModuleName));
  }

  vmp::runtime::strings::secure_memzero(resident_plain.data(), resident_plain.size());
  vmp::runtime::strings::secure_memzero(ephemeral_plain.data(), ephemeral_plain.size());
  return result;
}

BaselineVerification PrologueBaselineStore::verify_all() {
  BaselineVerification summary;
  summary.ok = true;
  for (const auto& entry : impl_->entries) {
    auto result = verify_region(entry.name);
    if (!result.ok) {
      return result;
    }
  }
  return summary;
}

void PrologueBaselineStore::force_refresh_for_tests() { impl_->force_refresh = true; }

vmp::runtime::audit::ReactionDispatcher& PrologueBaselineStore::reaction_dispatcher() noexcept { return impl_->dispatcher; }

TrustedOracle::TrustedOracle(KeyContextId key_context_id, std::filesystem::path audit_path)
    : audit_path_(audit_path.empty() ? vmp::runtime::audit::AuditWriter::default_path() : std::move(audit_path)),
      writer_(audit_path_),
      dispatcher_(writer_, vmp::runtime::audit::ReactionPolicy::audit_only),
      baselines_(normalize_key_context(key_context_id), audit_path_) {
  set_writer_exit_noop(dispatcher_);
  baselines_.register_default_apis();
}

PrologueBaselineStore& TrustedOracle::prologue_baselines() noexcept { return baselines_; }
const PrologueBaselineStore& TrustedOracle::prologue_baselines() const noexcept { return baselines_; }
vmp::runtime::audit::ReactionDispatcher& TrustedOracle::reaction_dispatcher() noexcept { return dispatcher_; }

void TrustedOracle::record_event(std::string event_type, std::string note) {
  writer_.append(vmp::runtime::audit::make_event(std::move(event_type), std::move(note), 0, kModuleName));
}

VoteOutcome TrustedOracle::evaluate_ptrace_status(const PtraceReadings& readings) {
  VoteOutcome out;
  out.fact_name = "ptrace_attached";
  const bool status_attached = readings.status_sampled && readings.tracer_pid > 0;
  const bool traceme_attached = readings.traceme_attempted && !readings.traceme_allowed;
  out.fact_value = status_attached || traceme_attached;
  out.divergent = readings.status_sampled && readings.traceme_attempted && (status_attached != traceme_attached);
  if (out.divergent) {
    out.event_type = "oracle_divergence";
    std::ostringstream oss;
    oss << "fact=ptrace_attached tracer_pid=" << readings.tracer_pid
        << " traceme_allowed=" << bool_text(readings.traceme_allowed)
        << " traceme_errno=" << readings.traceme_errno;
    out.note = oss.str();
    record_event(out.event_type, out.note);
  }
  return out;
}

VoteOutcome TrustedOracle::evaluate_time_sources(const TimeReadings& readings) {
  VoteOutcome out;
  out.fact_name = "time_source";
  const bool suspicious = (readings.monotonic_delta_ns > readings.max_clock_delta_ns) ||
                          (readings.monotonic_delta_ns > 0 && readings.counter_delta == 0);
  out.fact_value = suspicious;
  out.divergent = suspicious;
  if (out.divergent) {
    out.event_type = "oracle_divergence";
    std::ostringstream oss;
    oss << "fact=time_source counter_delta=" << readings.counter_delta
        << " monotonic_delta_ns=" << readings.monotonic_delta_ns
        << " threshold_ns=" << readings.max_clock_delta_ns;
    out.note = oss.str();
    record_event(out.event_type, out.note);
  }
  return out;
}

VoteOutcome TrustedOracle::evaluate_random_sources(const RandomReadings& readings) {
  VoteOutcome out;
  out.fact_name = "random_source";
  const bool syscall_health = readings.syscall_sampled && readings.syscall_ok && !all_zero(readings.syscall_bytes);
  const bool hardware_health = !readings.hardware_sampled || (readings.hardware_ok && !all_zero(readings.hardware_bytes));
  out.fact_value = syscall_health && hardware_health;
  out.divergent = readings.syscall_sampled && readings.hardware_sampled && (syscall_health != hardware_health);
  if (out.divergent) {
    out.event_type = "oracle_divergence";
    std::ostringstream oss;
    oss << "fact=random_source syscall_ok=" << bool_text(syscall_health)
        << " hardware_ok=" << bool_text(hardware_health);
    out.note = oss.str();
    record_event(out.event_type, out.note);
  }
  return out;
}

PtraceReadings TrustedOracle::sample_ptrace_status() {
  if (ptrace_cached_) {
    return ptrace_cache_;
  }
  PtraceReadings out;
#if defined(__linux__) || defined(__ANDROID__)
  const auto status = read_file_direct("/proc/self/status");
  if (!status.empty()) {
    out.status_sampled = true;
    out.tracer_pid = parse_tracer_pid(status);
  }

  out.traceme_attempted = true;
  const pid_t child = ::fork();
  if (child == 0) {
    errno = 0;
    const auto rc = DirectSyscall::ptrace(static_cast<std::uintptr_t>(PTRACE_TRACEME), 0, 0, 0);
    const int code = (rc == 0) ? 0 : ((errno == EPERM) ? 1 : 2);
    _exit(code);
  }
  if (child > 0) {
    int status_code = 0;
    if (::waitpid(child, &status_code, 0) == child && WIFEXITED(status_code)) {
      const int exit_code = WEXITSTATUS(status_code);
      out.traceme_allowed = (exit_code == 0);
      out.traceme_errno = (exit_code == 1) ? EPERM : ((exit_code == 2) ? EIO : 0);
    } else {
      out.traceme_allowed = false;
      out.traceme_errno = EIO;
    }
  } else {
    out.traceme_allowed = false;
    out.traceme_errno = errno;
  }
#endif
  ptrace_cache_ = out;
  ptrace_cached_ = true;
  return out;
}

TimeReadings TrustedOracle::sample_time_sources() const {
  TimeReadings out;
  DirectTimespec before{};
  DirectTimespec after{};
  const auto counter_before = read_counter();
  if (DirectSyscall::clock_gettime(
#if defined(CLOCK_MONOTONIC)
          CLOCK_MONOTONIC,
#else
          1,
#endif
          &before) == 0 &&
      DirectSyscall::clock_gettime(
#if defined(CLOCK_MONOTONIC)
          CLOCK_MONOTONIC,
#else
          1,
#endif
          &after) == 0) {
    out.monotonic_delta_ns = as_ns(after) - as_ns(before);
  }
  const auto counter_after = read_counter();
  out.counter_delta = counter_after >= counter_before ? (counter_after - counter_before) : 0;
  return out;
}

RandomReadings TrustedOracle::sample_random_sources(std::size_t size) const {
  RandomReadings out;
  out.syscall_bytes.assign(size, 0);
  const auto got = DirectSyscall::getrandom(out.syscall_bytes.data(), out.syscall_bytes.size(), 0);
  out.syscall_sampled = true;
  out.syscall_ok = got == static_cast<std::ptrdiff_t>(size);
  if (!out.syscall_ok) {
    out.syscall_bytes.clear();
  }
  out.hardware_ok = fill_hardware_random(size, out.hardware_bytes);
  out.hardware_sampled = out.hardware_ok;
  return out;
}

VoteOutcome TrustedOracle::probe_ptrace_status() { return evaluate_ptrace_status(sample_ptrace_status()); }
VoteOutcome TrustedOracle::probe_time_sources() { return evaluate_time_sources(sample_time_sources()); }
VoteOutcome TrustedOracle::probe_random_sources(std::size_t size) { return evaluate_random_sources(sample_random_sources(size)); }

ThreadVerificationResult TrustedOracle::verify_detector_thread(const ThreadVerificationOptions& options) {
  ThreadVerificationResult result;
  const auto before = enumerate_task_tids();
  std::promise<void> entered;
  auto entered_future = entered.get_future();
  std::promise<void> release;
  auto release_future = release.get_future().share();
  std::atomic<std::uint64_t> observed_tid{0};

  std::thread worker([&]() {
    const auto provider = options.observed_tid_provider ? options.observed_tid_provider : []() {
      return DirectSyscall::gettid();
    };
    observed_tid.store(provider(), std::memory_order_release);
    entered.set_value();
    release_future.wait();
  });

  entered_future.wait();
  result.expected_tid = wait_for_new_tid(before);
  result.observed_tid = observed_tid.load(std::memory_order_acquire);
  result.matched = result.expected_tid != 0 && result.expected_tid == result.observed_tid;
  release.set_value();
  worker.join();

  if (!result.matched) {
    result.event_type = "thread_creation_hijacked";
    std::ostringstream oss;
    oss << "expected_tid=" << result.expected_tid << " observed_tid=" << result.observed_tid;
    result.note = oss.str();
    record_event(result.event_type, result.note);
  }
  return result;
}

std::intptr_t DirectSyscall::raw(std::uint64_t number,
                                 std::uintptr_t a0,
                                 std::uintptr_t a1,
                                 std::uintptr_t a2,
                                 std::uintptr_t a3,
                                 std::uintptr_t a4,
                                 std::uintptr_t a5) noexcept {
#if defined(__linux__) && defined(__x86_64__)
  return vmp_trusted_oracle_linux_x64_syscall6(number, a0, a1, a2, a3, a4, a5);
#elif defined(__linux__) && defined(__aarch64__)
  return vmp_trusted_oracle_linux_arm64_syscall6(number, a0, a1, a2, a3, a4, a5);
#elif defined(__APPLE__) && defined(__aarch64__)
  return vmp_trusted_oracle_ios_arm64_syscall6(number, a0, a1, a2, a3, a4, a5);
#else
  (void)number;
  (void)a0;
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;
  errno = ENOSYS;
  return -1;
#endif
}

int DirectSyscall::open_readonly(const char* path) noexcept {
#if defined(__linux__) || defined(__ANDROID__)
  const auto flags = static_cast<std::uintptr_t>(O_RDONLY | O_CLOEXEC);
  if constexpr (sysnr::kHasOpenAtFallback) {
    return static_cast<int>(normalize_linux_ret(raw(sysnr::kOpenAt, kAtFdcwd, reinterpret_cast<std::uintptr_t>(path), flags, 0, 0, 0)));
  }
  return static_cast<int>(normalize_linux_ret(raw(sysnr::kOpen, reinterpret_cast<std::uintptr_t>(path), flags, 0, 0, 0, 0)));
#else
  const int fd = ::open(path, O_RDONLY);
  return fd;
#endif
}

std::ptrdiff_t DirectSyscall::read(int fd, void* buffer, std::size_t count) noexcept {
#if defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
  return static_cast<std::ptrdiff_t>(normalize_linux_ret(raw(sysnr::kRead,
                                                             static_cast<std::uintptr_t>(fd),
                                                             reinterpret_cast<std::uintptr_t>(buffer),
                                                             count,
                                                             0,
                                                             0,
                                                             0)));
#else
  return -1;
#endif
}

int DirectSyscall::close(int fd) noexcept {
#if defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
  return static_cast<int>(normalize_linux_ret(raw(sysnr::kClose, static_cast<std::uintptr_t>(fd), 0, 0, 0, 0, 0)));
#else
  return -1;
#endif
}

long DirectSyscall::ptrace(std::uintptr_t request,
                           std::uintptr_t pid,
                           std::uintptr_t addr,
                           std::uintptr_t data) noexcept {
#if defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
  return static_cast<long>(normalize_linux_ret(raw(sysnr::kPtrace, request, pid, addr, data, 0, 0)));
#else
  return -1;
#endif
}

int DirectSyscall::clock_gettime(int clock_id, DirectTimespec* out) noexcept {
#if defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
  return static_cast<int>(normalize_linux_ret(raw(sysnr::kClockGettime,
                                                  static_cast<std::uintptr_t>(clock_id),
                                                  reinterpret_cast<std::uintptr_t>(out),
                                                  0,
                                                  0,
                                                  0,
                                                  0)));
#else
  (void)clock_id;
  (void)out;
  return -1;
#endif
}

std::ptrdiff_t DirectSyscall::getrandom(void* buffer, std::size_t count, unsigned flags) noexcept {
#if defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
  return static_cast<std::ptrdiff_t>(normalize_linux_ret(raw(sysnr::kGetrandom,
                                                             reinterpret_cast<std::uintptr_t>(buffer),
                                                             count,
                                                             flags,
                                                             0,
                                                             0,
                                                             0)));
#else
  (void)buffer;
  (void)count;
  (void)flags;
  return -1;
#endif
}

int DirectSyscall::sigaction(int signum, const void* action, void* old_action) noexcept {
#if defined(__linux__) || defined(__ANDROID__)
  return static_cast<int>(normalize_linux_ret(raw(sysnr::kRtSigaction,
                                                  static_cast<std::uintptr_t>(signum),
                                                  reinterpret_cast<std::uintptr_t>(action),
                                                  reinterpret_cast<std::uintptr_t>(old_action),
                                                  kKernelSigsetSize,
                                                  0,
                                                  0)));
#else
  (void)signum;
  (void)action;
  (void)old_action;
  return -1;
#endif
}

int DirectSyscall::prctl(int option,
                         unsigned long arg2,
                         unsigned long arg3,
                         unsigned long arg4,
                         unsigned long arg5) noexcept {
#if defined(__linux__) || defined(__ANDROID__)
  return static_cast<int>(normalize_linux_ret(raw(sysnr::kPrctl,
                                                  static_cast<std::uintptr_t>(option),
                                                  static_cast<std::uintptr_t>(arg2),
                                                  static_cast<std::uintptr_t>(arg3),
                                                  static_cast<std::uintptr_t>(arg4),
                                                  static_cast<std::uintptr_t>(arg5),
                                                  0)));
#else
  (void)option;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  (void)arg5;
  return -1;
#endif
}

int DirectSyscall::arch_prctl(int code, std::uintptr_t* value) noexcept {
#if defined(__linux__) && defined(__x86_64__)
  return static_cast<int>(normalize_linux_ret(
      raw(sysnr::kArchPrctl, static_cast<std::uintptr_t>(code), reinterpret_cast<std::uintptr_t>(value), 0, 0, 0, 0)));
#else
  (void)code;
  (void)value;
  errno = ENOSYS;
  return -1;
#endif
}

std::uint64_t DirectSyscall::gettid() noexcept {
#if defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
  return static_cast<std::uint64_t>(normalize_linux_ret(raw(sysnr::kGettid, 0, 0, 0, 0, 0, 0)));
#elif defined(_WIN32)
  return static_cast<std::uint64_t>(::GetCurrentThreadId());
#else
  return 0;
#endif
}

long DirectSyscall::nt_protect_current_process(void* address,
                                            std::size_t size,
                                            unsigned long new_protect,
                                            unsigned long* old_protect) noexcept {
#if defined(_WIN32)
  using NtProtectVirtualMemoryFn = long (WINAPI*)(HANDLE, void**, std::size_t*, unsigned long, unsigned long*);
  auto* stub = windows_syscall::resolve_stub("NtProtectVirtualMemory");
  if (stub == nullptr) {
    return -1;
  }
  auto* fn = reinterpret_cast<NtProtectVirtualMemoryFn>(stub);
  void* base = address;
  std::size_t region = size;
  return fn(reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1)), &base, &region, new_protect, old_protect);
#else
  (void)address;
  (void)size;
  (void)new_protect;
  (void)old_protect;
  return -1;
#endif
}

long DirectSyscall::nt_query_virtual_memory_current_process(const void* address,
                                                            void* buffer,
                                                            std::size_t length,
                                                            std::size_t* result_length) noexcept {
#if defined(_WIN32)
  using NtQueryVirtualMemoryFn = long (WINAPI*)(HANDLE, const void*, int, void*, std::size_t, std::size_t*);
  auto* stub = windows_syscall::resolve_stub("NtQueryVirtualMemory");
  if (stub == nullptr) {
    return -1;
  }
  auto* fn = reinterpret_cast<NtQueryVirtualMemoryFn>(stub);
  return fn(reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-1)), address, 0, buffer, length, result_length);
#else
  (void)address;
  (void)buffer;
  (void)length;
  (void)result_length;
  return -1;
#endif
}

}  // namespace vmp::runtime::trusted_oracle
