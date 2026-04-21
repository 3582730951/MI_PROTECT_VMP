#include <vmp/runtime/jit/jit.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <list>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_set>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#if defined(__APPLE__) && (defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE)
#define VMP_JIT_C_BACKEND_DISABLED 1
#endif

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/cryptor/jit_epoch.h>
#include <vmp/runtime/cryptor/rolling_opcode_vm1.h>
#include <vmp/runtime/state/state.h>
#include <vmp/runtime/trusted_oracle/oracle.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/keyctx.h>
#include <vmp/runtime/vm1/isa.h>
#include <vmp/runtime/vm1/vm1.h>

namespace vmp::runtime::jit {
namespace {

using vmp::runtime::vm1::Opcode;
using vmp::runtime::vm1::Vm1Module;

constexpr std::size_t kX64StubSize = 2 + 8 + 2 + 8 + 2 + 1;

#if !defined(_WIN32)
using Vm1BlockExecFn = std::uint32_t (*)(vmp::runtime::vm1::Vm1Context*, std::uint32_t);
using Vm1TraceExecFn = std::uint32_t (*)(vmp::runtime::vm1::Vm1Context*, const std::uint32_t*, std::size_t);
extern "C" std::uint32_t vmp_vm1_jit_execute_block(vmp::runtime::vm1::Vm1Context*, std::uint32_t) __attribute__((weak));
extern "C" std::uint32_t vmp_vm1_jit_execute_trace(vmp::runtime::vm1::Vm1Context*, const std::uint32_t*, std::size_t) __attribute__((weak));

extern "C" std::uint32_t vmp_vm1_jit_block_trampoline(vmp::runtime::vm1::Vm1Context* context, std::uint32_t start_pc) {
  auto* fn = reinterpret_cast<Vm1BlockExecFn>(vmp_vm1_jit_execute_block);
  if (fn == nullptr) {
    return 0;
  }
  return fn(context, start_pc);
}

extern "C" std::uint32_t vmp_vm1_jit_trace_trampoline(vmp::runtime::vm1::Vm1Context* context,
                                                         const std::uint32_t* pcs,
                                                         std::size_t count) {
  auto* fn = reinterpret_cast<Vm1TraceExecFn>(vmp_vm1_jit_execute_trace);
  if (fn == nullptr) {
    return 0;
  }
  return fn(context, pcs, count);
}
#endif


bool env_truthy(const char* value) {
  if (value == nullptr) {
    return false;
  }
  return std::strcmp(value, "1") == 0 || std::strcmp(value, "true") == 0 || std::strcmp(value, "TRUE") == 0 ||
         std::strcmp(value, "yes") == 0;
}

std::string env_string(const char* name) {
  if (const char* value = std::getenv(name); value != nullptr) {
    return value;
  }
  return {};
}

std::size_t env_size(const char* name, std::size_t fallback) {
  if (const char* value = std::getenv(name); value != nullptr) {
    try {
      return static_cast<std::size_t>(std::stoull(value));
    } catch (...) {
      return fallback;
    }
  }
  return fallback;
}

bool host_supports_x64_backend() {
#if defined(__linux__) && defined(__x86_64__)
  return true;
#else
  return false;
#endif
}

Vm1JitBackend parse_backend_env() {
  const auto raw = env_string("VMP_JIT_BACKEND");
  if (raw == "off") {
    return Vm1JitBackend::off;
  }
  if (raw == "c") {
    return Vm1JitBackend::c;
  }
  if (raw == "x64") {
    return host_supports_x64_backend() ? Vm1JitBackend::x64 : Vm1JitBackend::c;
  }
  if (host_supports_x64_backend()) {
    return Vm1JitBackend::x64;
  }
  return Vm1JitBackend::c;
}

const char* backend_name(Vm1JitBackend backend) {
  switch (backend) {
    case Vm1JitBackend::off: return "off";
    case Vm1JitBackend::c: return "c";
    case Vm1JitBackend::x64: return "x64";
  }
  return "off";
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& code, std::size_t& pc) {
  if (pc + 2 > code.size()) {
    throw std::runtime_error("jit decode: truncated u16");
  }
  const auto value = static_cast<std::uint16_t>(code[pc]) |
                     static_cast<std::uint16_t>(code[pc + 1] << 8u);
  pc += 2;
  return value;
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& code, std::size_t& pc) {
  if (pc + 4 > code.size()) {
    throw std::runtime_error("jit decode: truncated u32");
  }
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(code[pc + static_cast<std::size_t>(i)]) << (8 * i);
  }
  pc += 4;
  return value;
}

std::size_t decode_instruction_size(const std::vector<std::uint8_t>& code, std::size_t pc) {
  if (pc >= code.size()) {
    throw std::runtime_error("jit decode: pc out of range");
  }
  auto cursor = pc;
  const auto opcode = static_cast<Opcode>(read_u16(code, cursor));
  switch (opcode) {
    case Opcode::nop:
    case Opcode::ret:
    case Opcode::domain_ret:
    case Opcode::fence:
    case Opcode::breakpoint:
      return 2;
    case Opcode::trap:
    case Opcode::jmp:
    case Opcode::syscall_proxy:
      return 6;
    case Opcode::ldi64:
    case Opcode::ldi_u64:
    case Opcode::ldi_f64:
      return 11;
    case Opcode::mov:
    case Opcode::neg:
    case Opcode::bit_not:
    case Opcode::popcnt:
    case Opcode::clz:
    case Opcode::ctz:
    case Opcode::bswap:
    case Opcode::setcc:
    case Opcode::fsqrt:
    case Opcode::i64_to_f64:
    case Opcode::f64_to_i64:
    case Opcode::strlen:
    case Opcode::call_indirect:
      return 4;
    case Opcode::jmp_indirect:
    case Opcode::release_transient_string:
    case Opcode::transient_wipe:
      return 3;
    case Opcode::add:
    case Opcode::sub:
    case Opcode::mul:
    case Opcode::div:
    case Opcode::mod:
    case Opcode::bit_and:
    case Opcode::bit_or:
    case Opcode::bit_xor:
    case Opcode::shl:
    case Opcode::shr:
    case Opcode::sar:
    case Opcode::fadd:
    case Opcode::fsub:
    case Opcode::fmul:
    case Opcode::fdiv:
    case Opcode::vadd128:
    case Opcode::vxor128:
    case Opcode::vshuffle128:
    case Opcode::memcpy:
    case Opcode::memset:
    case Opcode::strcmp:
      return 5;
    case Opcode::cmp:
    case Opcode::test:
    case Opcode::fcmp:
      return 4;
    case Opcode::load_mem8:
    case Opcode::load_mem16:
    case Opcode::load_mem32:
    case Opcode::load_mem64:
    case Opcode::store_mem8:
    case Opcode::store_mem16:
    case Opcode::store_mem32:
    case Opcode::store_mem64:
    case Opcode::load_sext8:
    case Opcode::load_sext16:
    case Opcode::load_sext32:
    case Opcode::lea:
      return 8;
    case Opcode::jeq:
    case Opcode::jne:
    case Opcode::jlt:
    case Opcode::jle:
    case Opcode::jgt:
    case Opcode::jge:
      return 8;
    case Opcode::call:
    case Opcode::load_transient_string:
      return 7;
    case Opcode::domain_call:
      return 10;
    case Opcode::bridge_args:
      return 5;
    case Opcode::transient_read8:
      return 5;
    case Opcode::cas_u64:
      return 10;
    case Opcode::xchg_u64:
      return 9;
  }
  throw std::runtime_error("jit decode: unknown opcode");
}

bool is_terminator(Opcode opcode) {
  switch (opcode) {
    case Opcode::jmp:
    case Opcode::jeq:
    case Opcode::jne:
    case Opcode::jlt:
    case Opcode::jle:
    case Opcode::jgt:
    case Opcode::jge:
    case Opcode::call:
    case Opcode::ret:
    case Opcode::domain_call:
    case Opcode::domain_ret:
    case Opcode::trap:
      return true;
    default:
      return false;
  }
}

bool is_supported_x64_opcode(Opcode opcode) {
  switch (opcode) {
    case Opcode::nop:
    case Opcode::breakpoint:
    case Opcode::ldi64:
    case Opcode::ldi_u64:
    case Opcode::mov:
    case Opcode::add:
    case Opcode::sub:
    case Opcode::mul:
    case Opcode::div:
    case Opcode::mod:
    case Opcode::bit_and:
    case Opcode::bit_or:
    case Opcode::bit_xor:
    case Opcode::shl:
    case Opcode::shr:
    case Opcode::sar:
    case Opcode::neg:
    case Opcode::bit_not:
    case Opcode::load_mem8:
    case Opcode::load_mem16:
    case Opcode::load_mem32:
    case Opcode::load_mem64:
    case Opcode::store_mem8:
    case Opcode::store_mem16:
    case Opcode::store_mem32:
    case Opcode::store_mem64:
    case Opcode::jmp:
    case Opcode::jeq:
    case Opcode::jne:
    case Opcode::jlt:
    case Opcode::jle:
    case Opcode::jgt:
    case Opcode::jge:
    case Opcode::call:
    case Opcode::ret:
      return true;
    default:
      return false;
  }
}

bool block_is_x64_supported(const Vm1Module& module, std::uint32_t start_pc) {
  std::size_t pc = start_pc;
  while (pc < module.code.size()) {
    auto cursor = pc;
    const auto opcode = static_cast<Opcode>(read_u16(module.code, cursor));
    if (!is_supported_x64_opcode(opcode)) {
      return false;
    }
    const auto size = decode_instruction_size(module.code, pc);
    pc += size;
    if (is_terminator(opcode)) {
      return true;
    }
  }
  return true;
}

bool trace_is_x64_supported(const Vm1Module& module, const std::vector<std::uint32_t>& pcs) {
  return std::all_of(pcs.begin(), pcs.end(), [&](std::uint32_t pc) { return block_is_x64_supported(module, pc); });
}

std::string join_trace(const std::vector<std::uint32_t>& pcs) {
  std::ostringstream oss;
  for (std::size_t i = 0; i < pcs.size(); ++i) {
    if (i != 0) {
      oss << "->";
    }
    oss << pcs[i];
  }
  return oss.str();
}

void write_u64(std::uint8_t*& out, std::uint64_t value) {
  std::memcpy(out, &value, sizeof(value));
  out += sizeof(value);
}

std::string shell_escape(const std::string& value) {
  std::string out = "'";
  for (char ch : value) {
    if (ch == '\'') {
      out += "'\\''";
    } else {
      out.push_back(ch);
    }
  }
  out.push_back('\'');
  return out;
}

void ensure_directory(const std::filesystem::path& dir) {
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    throw std::runtime_error("jit: failed to create cache directory '" + dir.string() + "': " + ec.message());
  }
}

std::array<std::uint8_t, 32> fallback_master_key(std::uint64_t module_id) {
  std::array<std::uint8_t, 32> out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(((module_id >> ((i % 8) * 8)) & 0xFFu) ^ (0x51u + static_cast<unsigned>(i)));
  }
  return out;
}

std::vector<std::uint8_t> fallback_salt(std::uint64_t module_id) {
  std::vector<std::uint8_t> out(16);
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(((module_id >> ((i % 8) * 8)) & 0xFFu) ^ (0x27u + static_cast<unsigned>(i)));
  }
  return out;
}

std::array<std::uint8_t, 32> derive_integrity_key(std::uint64_t module_id) {
  const auto master = fallback_master_key(module_id);
  vmp::runtime::strings::KeyContext fallback(
      vmp::runtime::strings::MasterKeyHandle([master] { return std::vector<std::uint8_t>(master.begin(), master.end()); }),
      fallback_salt(module_id));
  auto key = fallback.derive_subkey("vm1_jit_integrity");
  return key.bytes();
}

std::array<std::uint8_t, 32> compute_integrity_tag(const std::array<std::uint8_t, 32>& key,
                                                   std::uint64_t module_id,
                                                   std::uint32_t block_start_pc,
                                                   const std::vector<std::uint8_t>& bytes) {
  std::vector<std::uint8_t> material;
  material.reserve(12 + bytes.size());
  for (int i = 0; i < 8; ++i) material.push_back(static_cast<std::uint8_t>((module_id >> (i * 8)) & 0xffu));
  for (int i = 0; i < 4; ++i) material.push_back(static_cast<std::uint8_t>((block_start_pc >> (i * 8)) & 0xffu));
  material.insert(material.end(), bytes.begin(), bytes.end());
  const auto digest = vmp::runtime::strings::hmac_sha256(std::vector<std::uint8_t>(key.begin(), key.end()), material);
  std::array<std::uint8_t, 32> out{};
  std::copy_n(digest.begin(), out.size(), out.begin());
  return out;
}

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::vector<std::uint8_t> snapshot_bytes(const void* ptr, std::size_t size) {
  std::vector<std::uint8_t> out(size);
  if (ptr != nullptr && size != 0) {
    std::memcpy(out.data(), ptr, size);
  }
  return out;
}

bool patch_memory_byte(void* ptr, std::size_t size, std::size_t offset, std::uint8_t value) {
  if (ptr == nullptr || offset >= size) {
    return false;
  }
#if defined(_WIN32)
  unsigned long old_protect = 0;
  if (vmp::runtime::trusted_oracle::DirectSyscall::nt_protect_current_process(ptr, size, PAGE_EXECUTE_READWRITE, &old_protect) != 0) {
    return false;
  }
  static_cast<std::uint8_t*>(ptr)[offset] = value;
  unsigned long restored = 0;
  return vmp::runtime::trusted_oracle::DirectSyscall::nt_protect_current_process(ptr, size, old_protect, &restored) == 0;
#else
  const auto page_size = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
  const auto base = reinterpret_cast<std::uintptr_t>(ptr) & ~(static_cast<std::uintptr_t>(page_size) - 1u);
  const auto span = (reinterpret_cast<std::uintptr_t>(ptr) + size) - base;
  if (::mprotect(reinterpret_cast<void*>(base), span, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    return false;
  }
  static_cast<std::uint8_t*>(ptr)[offset] = value;
  ::mprotect(reinterpret_cast<void*>(base), span, PROT_READ | PROT_EXEC);
  return true;
#endif
}

bool patch_file_byte(const std::filesystem::path& path, std::size_t offset, std::uint8_t value) {
  std::fstream io(path, std::ios::in | std::ios::out | std::ios::binary);
  if (!io) {
    return false;
  }
  io.seekp(static_cast<std::streamoff>(offset));
  io.put(static_cast<char>(value));
  return static_cast<bool>(io);
}

#if !defined(_WIN32)
struct MmapRegion {
  void* ptr = nullptr;
  std::size_t size = 0;

  ~MmapRegion() {
    if (ptr != nullptr) {
      ::munmap(ptr, size);
    }
  }
};
#endif

}  // namespace

struct Vm1Jit::Impl {
  bool capability_event_emitted = false;
  struct ModuleCache;

  struct TraceCandidate {
    std::vector<std::uint32_t> pcs;
    std::uint64_t stable_hits = 0;
  };

  struct Entry {
    vmp::runtime::cryptor::JitCacheKey key{};
    std::uint32_t start_pc = 0;
    std::vector<std::uint32_t> pcs;
    Vm1JitBackend backend = Vm1JitBackend::off;
    JitEntry fn = nullptr;
    std::size_t code_size = 0;
    bool is_trace = false;
    std::uint64_t activation_hit = 0;
    Vm1JitEntryStats stats{};
    std::uint64_t lru_tick = 0;
#if defined(_WIN32)
    void* code_region = nullptr;
#else
    void* code_region = nullptr;
    std::size_t code_region_size = 0;
    void* dl_handle = nullptr;
#endif
    std::filesystem::path c_source_path;
    std::filesystem::path c_so_path;
    std::uint32_t* trace_heap = nullptr;
    std::array<std::uint8_t, 32> integrity_tag{};
    void* integrity_ptr = nullptr;
    std::size_t integrity_size = 0;
    std::filesystem::path integrity_file_path;

    Entry() = default;
    Entry(const Entry&) = delete;
    Entry& operator=(const Entry&) = delete;
    Entry(Entry&& other) noexcept { *this = std::move(other); }
    Entry& operator=(Entry&& other) noexcept {
      if (this != &other) {
        key = other.key;
        start_pc = other.start_pc;
        pcs = std::move(other.pcs);
        backend = other.backend;
        fn = other.fn;
        code_size = other.code_size;
        is_trace = other.is_trace;
        activation_hit = other.activation_hit;
        stats = other.stats;
        lru_tick = other.lru_tick;
        code_region = other.code_region;
#if !defined(_WIN32)
        code_region_size = other.code_region_size;
        dl_handle = other.dl_handle;
#endif
        c_source_path = std::move(other.c_source_path);
        c_so_path = std::move(other.c_so_path);
        trace_heap = other.trace_heap;
        integrity_tag = other.integrity_tag;
        integrity_ptr = other.integrity_ptr;
        integrity_size = other.integrity_size;
        integrity_file_path = std::move(other.integrity_file_path);
        other.fn = nullptr;
        other.code_region = nullptr;
#if !defined(_WIN32)
        other.code_region_size = 0;
        other.dl_handle = nullptr;
#endif
        other.trace_heap = nullptr;
        other.integrity_ptr = nullptr;
        other.integrity_size = 0;
      }
      return *this;
    }

    ~Entry() {
#if defined(_WIN32)
      if (code_region != nullptr) {
        ::VirtualFree(code_region, 0, MEM_RELEASE);
      }
#else
      if (code_region != nullptr) {
        ::munmap(code_region, code_region_size);
      }
      if (dl_handle != nullptr) {
        ::dlclose(dl_handle);
      }
#endif
      delete[] trace_heap;
      std::error_code ignore;
      if (!c_source_path.empty()) {
        std::filesystem::remove(c_source_path, ignore);
      }
      if (!c_so_path.empty()) {
        std::filesystem::remove(c_so_path, ignore);
      }
    }
  };

  struct ModuleCache {
    std::size_t budget = 8u * 1024u * 1024u;
    std::size_t used = 0;
    std::uint64_t lru_clock = 0;
    std::unordered_map<vmp::runtime::cryptor::JitCacheKey,
                       Entry,
                       vmp::runtime::cryptor::JitCacheKeyHash>
        entries;
    std::unordered_map<std::uint32_t, TraceCandidate> trace_candidates;
    std::unordered_set<std::uint32_t> cooldown_entries;
  };

  mutable std::mutex mutex;
  Vm1JitConfig config;
  vmp::runtime::audit::AuditWriter* audit = nullptr;
  std::unordered_map<std::uint64_t, ModuleCache> modules;
  std::filesystem::path cache_dir;

  void refresh_config_from_env() {
    config.verbose = env_truthy(std::getenv("VMP_JIT_VERBOSE"));
    config.module_cache_budget_bytes = env_size("VMP_JIT_CACHE_BUDGET", config.module_cache_budget_bytes);
  }

  void emit_audit(const std::string& event_type, const std::string& note, std::uint64_t pc = 0) {
    if (audit == nullptr) {
      return;
    }
    audit->append(vmp::runtime::audit::make_event(event_type, note, pc, "vm1_jit", "", 0));
  }

  bool c_backend_available() const {
#if defined(_WIN32)
    return false;
#else
    const char* path_env = std::getenv("PATH");
    if (path_env == nullptr || *path_env == '\0') {
      return false;
    }
    std::string path_list(path_env);
    std::size_t start = 0;
    while (start <= path_list.size()) {
      const auto end = path_list.find(':', start);
      const auto item = path_list.substr(start, end == std::string::npos ? std::string::npos : end - start);
      if (!item.empty()) {
        std::error_code ec;
        auto candidate = std::filesystem::path(item) / "cc";
        if (std::filesystem::exists(candidate, ec) && !ec) {
          return true;
        }
      }
      if (end == std::string::npos) {
        break;
      }
      start = end + 1;
    }
    return false;
#endif
  }

  ModuleCache& module_cache(std::uint64_t module_id) {
    auto& cache = modules[module_id];
    cache.budget = config.module_cache_budget_bytes;
    return cache;
  }

  static vmp::runtime::cryptor::JitCacheKey make_key(std::uint64_t module_id,
                                                     std::uint32_t start_pc,
                                                     std::uint32_t epoch_id) {
    return vmp::runtime::cryptor::JitCacheKey{module_id, start_pc, epoch_id};
  }

  auto find_entry(ModuleCache& cache,
                  std::uint64_t module_id,
                  std::uint32_t start_pc,
                  std::uint32_t epoch_id) {
    return cache.entries.find(make_key(module_id, start_pc, epoch_id));
  }

  auto find_entry(const ModuleCache& cache,
                  std::uint64_t module_id,
                  std::uint32_t start_pc,
                  std::uint32_t epoch_id) const {
    return cache.entries.find(make_key(module_id, start_pc, epoch_id));
  }

  void evict_if_needed(ModuleCache& cache, std::uint64_t module_id, std::size_t incoming) {
    if (incoming > cache.budget) {
      emit_audit("jit_oom", "entry exceeds module cache budget", module_id);
      throw std::runtime_error("jit: entry exceeds module cache budget");
    }
    while (cache.used + incoming > cache.budget && !cache.entries.empty()) {
      auto victim_it = std::min_element(cache.entries.begin(), cache.entries.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.second.lru_tick < rhs.second.lru_tick;
      });
      if (victim_it == cache.entries.end()) {
        break;
      }
      cache.used -= victim_it->second.code_size;
      emit_audit("jit_oom",
                 "evict module=" + std::to_string(module_id) + " pc=" +
                     std::to_string(victim_it->second.key.entry_pc) + " epoch=" +
                     std::to_string(victim_it->second.key.epoch_id),
                 victim_it->second.key.entry_pc);
      cache.entries.erase(victim_it);
    }
  }

  Entry* find_ready_entry(ModuleCache& cache,
                          std::uint64_t module_id,
                          std::uint32_t start_pc,
                          std::uint32_t epoch_id,
                          std::uint64_t hit_count) {
    auto it = find_entry(cache, module_id, start_pc, epoch_id);
    if (it == cache.entries.end() || it->second.fn == nullptr || hit_count < it->second.activation_hit) {
      return nullptr;
    }
    std::vector<std::uint8_t> current_bytes = it->second.integrity_ptr != nullptr
                                              ? snapshot_bytes(it->second.integrity_ptr, it->second.integrity_size)
                                              : read_file_bytes(it->second.integrity_file_path);
    const auto key = derive_integrity_key(module_id);
    const auto expected = compute_integrity_tag(key, module_id, start_pc, current_bytes);
    if (expected != it->second.integrity_tag) {
      emit_audit("jit_cache_integrity_failure",
                 "module=" + std::to_string(module_id) + " pc=" + std::to_string(start_pc), start_pc);
      cache.used -= it->second.code_size;
      cache.cooldown_entries.insert(start_pc);
      cache.entries.erase(it);
      return nullptr;
    }
    it->second.lru_tick = ++cache.lru_clock;
    it->second.stats.hit_count++;
    return &it->second;
  }

  Entry compile_c_entry(const Vm1Module& module, std::uint32_t start_pc, const std::vector<std::uint32_t>& pcs, bool trace) {
#if defined(VMP_JIT_C_BACKEND_DISABLED)
    throw std::runtime_error("vmp jit c-backend unavailable on iOS");
#elif defined(_WIN32)
    throw std::runtime_error("jit c backend unavailable on windows in this build");
#else
    ensure_directory(cache_dir);
    const auto base = cache_dir / ("vm1jit_" + std::to_string(module.id()) + "_" + std::to_string(start_pc));
    const auto c_path = base.string() + (trace ? "_trace.c" : "_block.c");
    const auto so_path = base.string() + (trace ? "_trace.so" : "_block.so");

    std::ofstream out(c_path, std::ios::binary | std::ios::trunc);
    if (!out) {
      throw std::runtime_error("jit: failed to open generated C source");
    }
    out << "#include <stddef.h>\n#include <stdint.h>\n#include <dlfcn.h>\n";
    out << "struct Vm1Context;\n";
    if (trace) {
      out << "typedef uint32_t (*trace_fn_t)(struct Vm1Context*, const uint32_t*, size_t);\n";
      out << "static uint32_t pcs[] = {";
      for (std::size_t i = 0; i < pcs.size(); ++i) {
        if (i != 0) out << ',';
        out << pcs[i];
      }
      out << "};\n";
      out << "__attribute__((visibility(\"default\"))) uint32_t vmp_vm1_jit_entry(struct Vm1Context* ctx) {\n";
      out << "  static trace_fn_t fn = 0;\n";
      out << "  if (!fn) fn = (trace_fn_t)dlsym(RTLD_DEFAULT, \"vmp_vm1_jit_execute_trace\");\n";
      out << "  if (!fn) return 0;\n";
      out << "  return fn(ctx, pcs, sizeof(pcs)/sizeof(pcs[0]));\n}\n";
    } else {
      out << "typedef uint32_t (*block_fn_t)(struct Vm1Context*, uint32_t);\n";
      out << "__attribute__((visibility(\"default\"))) uint32_t vmp_vm1_jit_entry(struct Vm1Context* ctx) {\n";
      out << "  static block_fn_t fn = 0;\n";
      out << "  if (!fn) fn = (block_fn_t)dlsym(RTLD_DEFAULT, \"vmp_vm1_jit_execute_block\");\n";
      out << "  if (!fn) return 0;\n";
      out << "  return fn(ctx, " << start_pc << "u);\n}\n";
    }
    out.close();

    const std::string compile_cmd = std::string("cc -shared -O2 -fPIC -o ") + shell_escape(so_path) + " " +
                                    shell_escape(c_path) + " -ldl >/dev/null 2>&1";
    if (std::system(compile_cmd.c_str()) != 0) {
      throw std::runtime_error("jit: cc backend compile failed");
    }

    void* handle = ::dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr) {
      throw std::runtime_error(std::string("jit: dlopen failed: ") + ::dlerror());
    }
    auto* symbol = reinterpret_cast<JitEntry>(::dlsym(handle, "vmp_vm1_jit_entry"));
    if (symbol == nullptr) {
      ::dlclose(handle);
      throw std::runtime_error(std::string("jit: dlsym failed: ") + ::dlerror());
    }

    Entry entry;
    entry.start_pc = start_pc;
    entry.pcs = pcs;
    entry.backend = Vm1JitBackend::c;
    entry.fn = symbol;
    entry.code_size = std::max<std::size_t>(64, pcs.size() * sizeof(std::uint32_t));
    entry.is_trace = trace;
    entry.code_region = nullptr;
    entry.code_region_size = 0;
    entry.dl_handle = handle;
    entry.c_source_path = c_path;
    entry.c_so_path = so_path;
    entry.integrity_file_path = so_path;
    entry.integrity_size = entry.code_size;
    return entry;
#endif
  }

  Entry compile_x64_entry(const Vm1Module& module, std::uint32_t start_pc, const std::vector<std::uint32_t>& pcs, bool trace) {
#if defined(__linux__) && defined(__x86_64__)
    if ((trace && !trace_is_x64_supported(module, pcs)) || (!trace && !block_is_x64_supported(module, start_pc))) {
      throw std::runtime_error("jit: x64 backend unsupported opcode in block/trace");
    }
    const std::size_t alloc_size = 64;
    void* region = ::mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
      throw std::runtime_error("jit: mmap failed");
    }

    auto* out = static_cast<std::uint8_t*>(region);
    std::uint32_t* pcs_copy = nullptr;
    out[0] = 0x48; out[1] = 0x83; out[2] = 0xEC; out[3] = 0x08; out += 4;  // sub rsp, 8
    if (trace) {
      pcs_copy = new std::uint32_t[pcs.size()];
      std::copy(pcs.begin(), pcs.end(), pcs_copy);
      out[0] = 0x48; out[1] = 0xBE; out += 2;  // mov rsi, imm64
      write_u64(out, reinterpret_cast<std::uint64_t>(pcs_copy));
      out[0] = 0x48; out[1] = 0xBA; out += 2;  // mov rdx, imm64(count)
      write_u64(out, static_cast<std::uint64_t>(pcs.size()));
      out[0] = 0x48; out[1] = 0xB8; out += 2;  // mov rax, imm64(fn)
      write_u64(out, reinterpret_cast<std::uint64_t>(&vmp_vm1_jit_trace_trampoline));
      out[0] = 0xFF; out[1] = 0xD0; out += 2;  // call rax
      out[0] = 0x48; out[1] = 0x83; out[2] = 0xC4; out[3] = 0x08; out += 4;  // add rsp, 8
      out[0] = 0xC3;
    } else {
      out[0] = 0x48; out[1] = 0xBE; out += 2;  // mov rsi, imm64
      write_u64(out, static_cast<std::uint64_t>(start_pc));
      out[0] = 0x48; out[1] = 0xB8; out += 2;  // mov rax, imm64
      write_u64(out, reinterpret_cast<std::uint64_t>(&vmp_vm1_jit_block_trampoline));
      out[0] = 0xFF; out[1] = 0xD0; out += 2;  // call rax
      out[0] = 0x48; out[1] = 0x83; out[2] = 0xC4; out[3] = 0x08; out += 4;  // add rsp, 8
      out[0] = 0xC3;
    }
    if (::mprotect(region, alloc_size, PROT_READ | PROT_EXEC) != 0) {
      ::munmap(region, alloc_size);
      throw std::runtime_error("jit: mprotect failed");
    }

    Entry entry;
    entry.start_pc = start_pc;
    entry.pcs = pcs;
    entry.backend = Vm1JitBackend::x64;
    entry.fn = reinterpret_cast<JitEntry>(region);
    entry.code_size = alloc_size;
    entry.is_trace = trace;
    entry.code_region = region;
    entry.code_region_size = alloc_size;
    entry.trace_heap = trace ? pcs_copy : nullptr;
    entry.integrity_ptr = region;
    entry.integrity_size = alloc_size;
    return entry;
#else
    (void)module;
    (void)start_pc;
    (void)pcs;
    (void)trace;
    throw std::runtime_error("jit: x64 backend unavailable");
#endif
  }

  Entry compile_entry(const Vm1Module& module, std::uint32_t start_pc, const std::vector<std::uint32_t>& pcs, bool trace) {
    auto requested = parse_backend_env();
    const auto& runtime_state = vmp::runtime::state::RuntimeState::instance();
    if (runtime_state.jit_execmem_unavailable()) {
      if (runtime_state.config().platform == "ios") {
        requested = Vm1JitBackend::off;
      } else if (c_backend_available()) {
        requested = Vm1JitBackend::c;
      } else {
        requested = Vm1JitBackend::off;
      }
    }
    if (requested == Vm1JitBackend::off) {
      throw std::runtime_error("jit: backend disabled");
    }
    if (requested == Vm1JitBackend::x64) {
      try {
        return compile_x64_entry(module, start_pc, pcs, trace);
      } catch (const std::exception& ex) {
        emit_audit("jit_fallback_backend", ex.what(), start_pc);
        return compile_c_entry(module, start_pc, pcs, trace);
      }
    }
    return compile_c_entry(module, start_pc, pcs, trace);
  }
};

Vm1Jit& Vm1Jit::instance() {
  static Vm1Jit jit;
  return jit;
}

Vm1Jit::Vm1Jit() : impl_(new Impl{}) {
  impl_->refresh_config_from_env();
  vmp::runtime::cryptor::RollingOpcodeRegistry::instance().register_epoch_bump_callback(
      vmp::runtime::cryptor::VmDomain::vm1,
      [](std::uint64_t module_id, std::uint32_t) { Vm1Jit::instance().invalidate_module(module_id); });
#if defined(_WIN32)
  impl_->cache_dir = std::filesystem::temp_directory_path() / ("vmp-jit-" + std::to_string(::GetCurrentProcessId()));
#else
  impl_->cache_dir = std::filesystem::temp_directory_path() / ("vmp-jit-" + std::to_string(::getpid()));
#endif
}

Vm1Jit::~Vm1Jit() { delete impl_; }

Vm1JitBackend Vm1Jit::backend_requested() const {
  const auto requested = parse_backend_env();
  const auto& runtime_state = vmp::runtime::state::RuntimeState::instance();
  if (!runtime_state.jit_execmem_unavailable()) {
    return requested;
  }

  const auto platform = runtime_state.config().platform;
  if (platform == "ios") {
    if (!impl_->capability_event_emitted) {
      impl_->emit_audit("jit_execmem_unavailable", "ios capability gate forced interpreter-only path");
      impl_->capability_event_emitted = true;
    }
    return Vm1JitBackend::off;
  }

  if (impl_->c_backend_available()) {
    if (!impl_->capability_event_emitted) {
      impl_->emit_audit("jit_execmem_unavailable", "execmem unavailable; downgrading vm1 JIT to c backend");
      impl_->capability_event_emitted = true;
    }
    return Vm1JitBackend::c;
  }

  if (!impl_->capability_event_emitted) {
    impl_->emit_audit("jit_execmem_unavailable", "execmem unavailable and c backend missing; interpreter-only fallback");
    impl_->capability_event_emitted = true;
  }
  return Vm1JitBackend::off;
}

Vm1JitBackend Vm1Jit::selected_backend() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return backend_requested();
}

std::string Vm1Jit::selected_backend_name() const { return backend_name(selected_backend()); }

bool Vm1Jit::enabled() const { return selected_backend() != Vm1JitBackend::off; }

void Vm1Jit::set_audit_writer(vmp::runtime::audit::AuditWriter* writer) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->audit = writer;
}

void Vm1Jit::set_module_cache_budget_bytes(std::size_t value) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->config.module_cache_budget_bytes = value;
}

std::size_t Vm1Jit::module_cache_budget_bytes() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->config.module_cache_budget_bytes;
}

JitEntry Vm1Jit::compile_if_needed(const Vm1Module& module, std::uint32_t block_start_pc, std::uint64_t hit_count) {
  vmp::runtime::cryptor::vm1::ensure_registered(module);
  const auto epoch_id = vmp::runtime::cryptor::vm1::current_epoch_id(module);
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->refresh_config_from_env();
  if (backend_requested() == Vm1JitBackend::off) {
    return nullptr;
  }
  auto& cache = impl_->module_cache(module.id());
  if (auto* ready = impl_->find_ready_entry(cache, module.id(), block_start_pc, epoch_id, hit_count); ready != nullptr) {
    return ready->fn;
  }
  if (cache.cooldown_entries.find(block_start_pc) != cache.cooldown_entries.end()) {
    return nullptr;
  }
  if (impl_->find_entry(cache, module.id(), block_start_pc, epoch_id) != cache.entries.end()) {
    return nullptr;
  }
  try {
    auto entry = impl_->compile_entry(module, block_start_pc, {block_start_pc}, false);
    entry.key = Impl::make_key(module.id(), block_start_pc, epoch_id);
    entry.activation_hit = 2;
    entry.stats.compile_count = 1;
    entry.stats.trace = false;
    entry.stats.code_size = entry.code_size;
    {
      std::vector<std::uint8_t> bytes = entry.integrity_ptr != nullptr ? snapshot_bytes(entry.integrity_ptr, entry.integrity_size)
                                                                       : read_file_bytes(entry.integrity_file_path);
      const auto key = derive_integrity_key(module.id());
      entry.integrity_tag = compute_integrity_tag(key, module.id(), block_start_pc, bytes);
    }
    impl_->evict_if_needed(cache, module.id(), entry.code_size);
    entry.lru_tick = ++cache.lru_clock;
    cache.used += entry.code_size;
    cache.entries[entry.key] = std::move(entry);
    impl_->emit_audit("jit_compile",
                      "module=" + std::to_string(module.id()) + " pc=" + std::to_string(block_start_pc) +
                          " epoch=" + std::to_string(epoch_id),
                      block_start_pc);
  } catch (const std::exception& ex) {
    impl_->emit_audit("jit_fallback_backend", ex.what(), block_start_pc);
  }
  return nullptr;
}

void Vm1Jit::record_entry_trampoline_hit(const Vm1Module& module, std::uint32_t block_start_pc) {
  vmp::runtime::cryptor::vm1::ensure_registered(module);
  const auto epoch_id = vmp::runtime::cryptor::vm1::current_epoch_id(module);
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module.id());
  if (mod_it == impl_->modules.end()) {
    return;
  }
  auto entry_it = impl_->find_entry(mod_it->second, module.id(), block_start_pc, epoch_id);
  if (entry_it == mod_it->second.entries.end()) {
    return;
  }
  entry_it->second.stats.entry_trampoline_hits++;
}

void Vm1Jit::record_trace_observation(const Vm1Module& module, const std::vector<std::uint32_t>& block_chain) {
  if (block_chain.size() < 2) {
    return;
  }
  vmp::runtime::cryptor::vm1::ensure_registered(module);
  const auto epoch_id = vmp::runtime::cryptor::vm1::current_epoch_id(module);
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->refresh_config_from_env();
  if (backend_requested() == Vm1JitBackend::off) {
    return;
  }
  auto& cache = impl_->module_cache(module.id());
  const auto start = block_chain.front();
  if (module.block_hit_count(start) < impl_->config.trace_hot_threshold) {
    return;
  }
  auto& candidate = cache.trace_candidates[start];
  if (candidate.pcs == block_chain) {
    candidate.stable_hits++;
  } else {
    candidate.pcs = block_chain;
    candidate.stable_hits = 1;
  }
  if (candidate.stable_hits < impl_->config.trace_stable_threshold) {
    return;
  }
  auto existing = impl_->find_entry(cache, module.id(), start, epoch_id);
  if (existing != cache.entries.end() && existing->second.is_trace && existing->second.pcs == block_chain) {
    return;
  }
  try {
    auto entry = impl_->compile_entry(module, start, block_chain, true);
    entry.key = Impl::make_key(module.id(), start, epoch_id);
    entry.activation_hit = module.block_hit_count(start) + 1;
    entry.stats.compile_count = 1;
    entry.stats.trace = true;
    entry.stats.code_size = entry.code_size;
    {
      std::vector<std::uint8_t> bytes = entry.integrity_ptr != nullptr ? snapshot_bytes(entry.integrity_ptr, entry.integrity_size)
                                                                       : read_file_bytes(entry.integrity_file_path);
      const auto key = derive_integrity_key(module.id());
      entry.integrity_tag = compute_integrity_tag(key, module.id(), start, bytes);
    }
    impl_->evict_if_needed(cache, module.id(), entry.code_size);
    if (existing != cache.entries.end()) {
      cache.used -= existing->second.code_size;
      cache.entries.erase(existing);
    }
    entry.lru_tick = ++cache.lru_clock;
    cache.used += entry.code_size;
    cache.entries[entry.key] = std::move(entry);
    impl_->emit_audit("jit_trace_compile",
                      "module=" + std::to_string(module.id()) + " trace=" + join_trace(block_chain) +
                          " epoch=" + std::to_string(epoch_id),
                      start);
  } catch (const std::exception& ex) {
    impl_->emit_audit("jit_fallback_backend", ex.what(), start);
  }
}

void Vm1Jit::invalidate_all() {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->modules.clear();
  impl_->emit_audit("jit_invalidate", "all");
}

void Vm1Jit::invalidate_module(std::uint64_t module_id) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->modules.erase(module_id);
  impl_->emit_audit("jit_invalidate", "module=" + std::to_string(module_id));
}

void Vm1Jit::invalidate_entry(std::uint64_t module_id, std::uint32_t block_start_pc) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  if (mod_it == impl_->modules.end()) {
    return;
  }
  const auto epoch_id =
      vmp::runtime::cryptor::RollingOpcodeRegistry::instance().current_epoch_id(vmp::runtime::cryptor::VmDomain::vm1,
                                                                                module_id);
  auto entry_it = impl_->find_entry(mod_it->second, module_id, block_start_pc, epoch_id);
  if (entry_it == mod_it->second.entries.end()) {
    return;
  }
  mod_it->second.used -= entry_it->second.code_size;
  mod_it->second.entries.erase(entry_it);
  impl_->emit_audit("jit_invalidate",
                    "module=" + std::to_string(module_id) + " pc=" + std::to_string(block_start_pc), block_start_pc);
}

Vm1JitEntryStats Vm1Jit::entry_stats(std::uint64_t module_id, std::uint32_t block_start_pc) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  if (mod_it == impl_->modules.end()) {
    return {};
  }
  const auto epoch_id =
      vmp::runtime::cryptor::RollingOpcodeRegistry::instance().current_epoch_id(vmp::runtime::cryptor::VmDomain::vm1,
                                                                                module_id);
  auto entry_it = impl_->find_entry(mod_it->second, module_id, block_start_pc, epoch_id);
  if (entry_it == mod_it->second.entries.end()) {
    return {};
  }
  return entry_it->second.stats;
}

std::size_t Vm1Jit::module_entry_count(std::uint64_t module_id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  return mod_it == impl_->modules.end() ? 0u : mod_it->second.entries.size();
}

std::size_t Vm1Jit::module_cache_bytes(std::uint64_t module_id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  return mod_it == impl_->modules.end() ? 0u : mod_it->second.used;
}


bool Vm1Jit::has_entry(std::uint64_t module_id, std::uint32_t block_start_pc) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  if (mod_it == impl_->modules.end()) {
    return false;
  }
  const auto epoch_id =
      vmp::runtime::cryptor::RollingOpcodeRegistry::instance().current_epoch_id(vmp::runtime::cryptor::VmDomain::vm1,
                                                                                module_id);
  return impl_->find_entry(mod_it->second, module_id, block_start_pc, epoch_id) != mod_it->second.entries.end();
}

bool Vm1Jit::debug_patch_code_byte(std::uint64_t module_id, std::uint32_t block_start_pc, std::size_t offset, std::uint8_t value) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  if (mod_it == impl_->modules.end()) {
    return false;
  }
  const auto epoch_id =
      vmp::runtime::cryptor::RollingOpcodeRegistry::instance().current_epoch_id(vmp::runtime::cryptor::VmDomain::vm1,
                                                                                module_id);
  auto entry_it = impl_->find_entry(mod_it->second, module_id, block_start_pc, epoch_id);
  if (entry_it == mod_it->second.entries.end()) {
    return false;
  }
  if (entry_it->second.integrity_ptr != nullptr) {
    return patch_memory_byte(entry_it->second.integrity_ptr, entry_it->second.integrity_size, offset, value);
  }
  return patch_file_byte(entry_it->second.integrity_file_path, offset, value);
}

void Vm1Jit::reset_for_tests() {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->modules.clear();
  impl_->capability_event_emitted = false;
  impl_->refresh_config_from_env();
}

const char* Facade::status() const noexcept { return "runtime_jit_ready"; }

}  // namespace vmp::runtime::jit
