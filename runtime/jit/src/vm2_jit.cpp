#include <vmp/runtime/jit/vm2_jit.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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
#include <unistd.h>
#endif

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/cryptor/jit_epoch.h>
#include <vmp/runtime/cryptor/rolling_opcode_vm2.h>
#include <vmp/runtime/state/state.h>
#include <vmp/runtime/trusted_oracle/oracle.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/keyctx.h>
#include <vmp/runtime/vm2/vm2.h>

namespace vmp::runtime::jit {
namespace {

using vmp::runtime::vm2::Opcode;
using vmp::runtime::vm2::Vm2Context;
using vmp::runtime::vm2::Vm2Module;

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

Vm2JitBackend parse_backend_env() {
  const auto raw = env_string("VMP_JIT_BACKEND");
  if (raw == "off") {
    return Vm2JitBackend::off;
  }
  if (raw == "c") {
    return Vm2JitBackend::c;
  }
  if (raw == "x64") {
    return host_supports_x64_backend() ? Vm2JitBackend::x64 : Vm2JitBackend::c;
  }
  if (host_supports_x64_backend()) {
    return Vm2JitBackend::x64;
  }
  return Vm2JitBackend::c;
}

const char* backend_name(Vm2JitBackend backend) {
  switch (backend) {
    case Vm2JitBackend::off: return "off";
    case Vm2JitBackend::c: return "c";
    case Vm2JitBackend::x64: return "x64";
  }
  return "off";
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& code, std::size_t& pc) {
  if (pc + 2 > code.size()) {
    throw std::runtime_error("vm2_jit: truncated u16");
  }
  const auto value = static_cast<std::uint16_t>(code[pc]) | static_cast<std::uint16_t>(code[pc + 1] << 8u);
  pc += 2;
  return value;
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& code, std::size_t& pc) {
  if (pc + 4 > code.size()) {
    throw std::runtime_error("vm2_jit: truncated u32");
  }
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(code[pc + static_cast<std::size_t>(i)]) << (i * 8);
  }
  pc += 4;
  return value;
}

std::size_t decode_instruction_size(const std::vector<std::uint8_t>& code, std::size_t pc) {
  std::size_t cursor = pc;
  const auto opcode = static_cast<Opcode>(read_u16(code, cursor));
  switch (opcode) {
    case Opcode::nop:
    case Opcode::bret:
    case Opcode::pret:
    case Opcode::xret:
    case Opcode::ifence:
    case Opcode::brk:
      return 2;
    case Opcode::ftrap:
    case Opcode::jmp:
    case Opcode::syscall_proxy:
      return 6;
    case Opcode::ildimm:
    case Opcode::dldimm:
      return 11;
    case Opcode::vldimm:
    case Opcode::tsload:
      return 7;
    case Opcode::imov:
    case Opcode::ineg:
    case Opcode::inot:
    case Opcode::dmov:
    case Opcode::ipopcnt:
    case Opcode::iclz:
    case Opcode::ictz:
    case Opcode::ibswap:
    case Opcode::isetcc:
    case Opcode::istrlen:
    case Opcode::dsqrt:
    case Opcode::i64tof:
    case Opcode::f64toi:
    case Opcode::icmp:
    case Opcode::itest:
    case Opcode::dcmp:
      return 4;
    case Opcode::tsrelease:
    case Opcode::tswipe:
      return 3;
    case Opcode::iadd:
    case Opcode::isub:
    case Opcode::imul:
    case Opcode::idiv:
    case Opcode::imod:
    case Opcode::iand:
    case Opcode::ior:
    case Opcode::ixor:
    case Opcode::ishl:
    case Opcode::ishr:
    case Opcode::isar:
    case Opcode::dadd:
    case Opcode::dsub:
    case Opcode::dmul:
    case Opcode::ddiv:
    case Opcode::vadd128:
    case Opcode::vsub128:
    case Opcode::vmul128:
    case Opcode::vxor128:
    case Opcode::imemcpy:
    case Opcode::imemset:
    case Opcode::istrcmp:
      return 5;
    case Opcode::imemld8:
    case Opcode::imemld16:
    case Opcode::imemld32:
    case Opcode::imemld64:
    case Opcode::imemst8:
    case Opcode::imemst16:
    case Opcode::imemst32:
    case Opcode::imemst64:
    case Opcode::vmemld128:
    case Opcode::vmemst128:
      return 8;
    case Opcode::jp:
    case Opcode::jnp:
      return 7;
    case Opcode::blnk:
      return 7;
    case Opcode::pcall:
      return 8;
    case Opcode::xcall:
    case Opcode::icas64:
      return 10;
    case Opcode::ixchg64:
      return 9;
    case Opcode::bridgeargs:
    case Opcode::tsread8:
      return 5;
  }
  throw std::runtime_error("vm2_jit: unknown opcode");
}

struct BlockInfo {
  std::uint32_t start_pc = 0;
  std::uint32_t end_pc = 0;
  Opcode terminator = Opcode::nop;
  std::optional<std::uint32_t> branch_target;
  std::optional<std::uint32_t> fallthrough;
  bool stop_boundary = false;
};

BlockInfo decode_block(const Vm2Module& module, std::uint32_t start_pc) {
  BlockInfo info;
  info.start_pc = start_pc;
  std::size_t pc = start_pc;
  while (pc < module.code.size()) {
    const auto inst_pc = static_cast<std::uint32_t>(pc);
    const auto opcode = static_cast<Opcode>(read_u16(module.code, pc));
    switch (opcode) {
      case Opcode::jmp:
        info.terminator = opcode;
        info.branch_target = read_u32(module.code, pc);
        info.end_pc = static_cast<std::uint32_t>(pc);
        return info;
      case Opcode::jp:
      case Opcode::jnp:
        ++pc;
        info.terminator = opcode;
        info.branch_target = read_u32(module.code, pc);
        info.fallthrough = static_cast<std::uint32_t>(pc);
        info.end_pc = static_cast<std::uint32_t>(pc);
        return info;
      case Opcode::blnk:
        info.terminator = opcode;
        (void)read_u32(module.code, pc);
        ++pc;
        info.fallthrough = static_cast<std::uint32_t>(pc);
        info.end_pc = static_cast<std::uint32_t>(pc);
        return info;
      case Opcode::pcall:
        ++pc;
        info.terminator = opcode;
        (void)read_u32(module.code, pc);
        ++pc;
        info.fallthrough = static_cast<std::uint32_t>(pc);
        info.end_pc = static_cast<std::uint32_t>(pc);
        return info;
      case Opcode::bret:
      case Opcode::pret:
      case Opcode::xcall:
      case Opcode::xret:
      case Opcode::ftrap:
        pc = static_cast<std::size_t>(inst_pc) + decode_instruction_size(module.code, inst_pc);
        info.terminator = opcode;
        info.end_pc = static_cast<std::uint32_t>(pc);
        info.stop_boundary = true;
        return info;
      default:
        pc = static_cast<std::size_t>(inst_pc) + decode_instruction_size(module.code, inst_pc);
        break;
    }
  }
  info.end_pc = static_cast<std::uint32_t>(pc);
  return info;
}

std::vector<std::uint32_t> discover_function_blocks(const Vm2Module& module, std::uint32_t entry_pc) {
  std::vector<std::uint32_t> out;
  std::set<std::uint32_t> seen;
  std::vector<std::uint32_t> worklist{entry_pc};
  while (!worklist.empty()) {
    const auto pc = worklist.back();
    worklist.pop_back();
    if (!seen.insert(pc).second) {
      continue;
    }
    out.push_back(pc);
    const auto block = decode_block(module, pc);
    if (block.branch_target.has_value() && !block.stop_boundary) {
      worklist.push_back(*block.branch_target);
    }
    if (block.fallthrough.has_value() && *block.fallthrough < module.code.size()) {
      worklist.push_back(*block.fallthrough);
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

bool is_supported_x64_opcode(Opcode opcode) {
  switch (opcode) {
    case Opcode::nop:
    case Opcode::brk:
    case Opcode::ildimm:
    case Opcode::vldimm:
    case Opcode::imov:
    case Opcode::iadd:
    case Opcode::isub:
    case Opcode::imul:
    case Opcode::idiv:
    case Opcode::imod:
    case Opcode::iand:
    case Opcode::ior:
    case Opcode::ixor:
    case Opcode::ishl:
    case Opcode::ishr:
    case Opcode::isar:
    case Opcode::ineg:
    case Opcode::inot:
    case Opcode::vadd128:
    case Opcode::vsub128:
    case Opcode::vmul128:
    case Opcode::vxor128:
    case Opcode::imemld8:
    case Opcode::imemld16:
    case Opcode::imemld32:
    case Opcode::imemld64:
    case Opcode::imemst8:
    case Opcode::imemst16:
    case Opcode::imemst32:
    case Opcode::imemst64:
    case Opcode::vmemld128:
    case Opcode::vmemst128:
    case Opcode::jmp:
    case Opcode::jp:
    case Opcode::jnp:
    case Opcode::blnk:
    case Opcode::pcall:
    case Opcode::bret:
      return true;
    default:
      return false;
  }
}

bool function_is_x64_supported(const Vm2Module& module, const std::vector<std::uint32_t>& blocks) {
  for (const auto block_pc : blocks) {
    std::size_t pc = block_pc;
    while (pc < module.code.size()) {
      const auto inst_pc = pc;
      const auto opcode = static_cast<Opcode>(read_u16(module.code, pc));
      if (!is_supported_x64_opcode(opcode)) {
        return false;
      }
      const auto size = decode_instruction_size(module.code, inst_pc);
      pc = inst_pc + size;
      if (opcode == Opcode::jmp || opcode == Opcode::jp || opcode == Opcode::jnp || opcode == Opcode::blnk ||
          opcode == Opcode::pcall || opcode == Opcode::bret || opcode == Opcode::pret || opcode == Opcode::xcall ||
          opcode == Opcode::xret || opcode == Opcode::ftrap) {
        break;
      }
    }
  }
  return true;
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
    throw std::runtime_error("vm2_jit: failed to create cache directory '" + dir.string() + "': " + ec.message());
  }
}

std::array<std::uint8_t, 32> fallback_master_key(std::uint64_t module_id) {
  std::array<std::uint8_t, 32> out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(((module_id >> ((i % 8) * 8)) & 0xFFu) ^ (0xA5u + static_cast<unsigned>(i)));
  }
  return out;
}

std::vector<std::uint8_t> fallback_salt(std::uint64_t module_id) {
  std::vector<std::uint8_t> out(16);
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(((module_id >> ((i % 8) * 8)) & 0xFFu) ^ (0x3Cu + static_cast<unsigned>(i)));
  }
  return out;
}

std::array<std::uint8_t, 32> derive_integrity_key(const Vm2Context& context, std::uint64_t module_id) {
  if (context.key_context != nullptr) {
    auto key = context.key_context->derive_subkey("vm2_jit_integrity");
    return key.bytes();
  }
  const auto master = fallback_master_key(module_id);
  vmp::runtime::strings::KeyContext fallback(
      vmp::runtime::strings::MasterKeyHandle([master] { return std::vector<std::uint8_t>(master.begin(), master.end()); }),
      fallback_salt(module_id));
  auto key = fallback.derive_subkey("vm2_jit_integrity");
  return key.bytes();
}

std::array<std::uint8_t, 16> current_key_context_tag(const Vm2Context& context, std::uint64_t module_id) {
  if (context.key_context != nullptr) {
    auto subkey = context.key_context->derive_subkey("vm2-key-context-id");
    const auto digest =
        vmp::runtime::strings::sha256(std::vector<std::uint8_t>(subkey.bytes().begin(), subkey.bytes().end()));
    std::array<std::uint8_t, 16> out{};
    std::copy_n(digest.begin(), out.size(), out.begin());
    return out;
  }
  const auto master = fallback_master_key(module_id);
  const auto digest = vmp::runtime::strings::sha256(std::vector<std::uint8_t>(master.begin(), master.end()));
  std::array<std::uint8_t, 16> out{};
  std::copy_n(digest.begin(), out.size(), out.begin());
  return out;
}

std::array<std::uint8_t, 32> compute_integrity_tag(const std::array<std::uint8_t, 32>& key,
                                                   std::uint64_t module_id,
                                                   std::uint32_t entry_pc,
                                                   const std::vector<std::uint8_t>& machine_code) {
  std::vector<std::uint8_t> material;
  material.reserve(12 + machine_code.size());
  append_u64(material, module_id);
  append_u32(material, entry_pc);
  material.insert(material.end(), machine_code.begin(), machine_code.end());
  const auto digest = vmp::runtime::strings::hmac_sha256(std::vector<std::uint8_t>(key.begin(), key.end()), material);
  std::array<std::uint8_t, 32> out{};
  std::copy_n(digest.begin(), out.size(), out.begin());
  return out;
}

std::vector<std::uint8_t> snapshot_code_bytes(const void* ptr, std::size_t size) {
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

#if !defined(_WIN32)
using Vm2ExecFn = std::uint32_t (*)(Vm2Context*, std::uint32_t);
extern "C" std::uint32_t vmp_vm2_jit_execute_function(Vm2Context*, std::uint32_t) __attribute__((weak));
extern "C" std::uint32_t vmp_vm2_jit_function_trampoline(Vm2Context* context, std::uint32_t entry_pc) {
  auto* fn = reinterpret_cast<Vm2ExecFn>(vmp_vm2_jit_execute_function);
  if (fn == nullptr) {
    return 0;
  }
  return fn(context, entry_pc);
}
#endif

void write_u64(std::uint8_t*& out, std::uint64_t value) {
  std::memcpy(out, &value, sizeof(value));
  out += sizeof(value);
}

}  // namespace

struct Vm2Jit::Impl {
  bool capability_event_emitted = false;
  struct Entry {
    vmp::runtime::cryptor::JitCacheKey key{};
    std::uint32_t entry_pc = 0;
    std::vector<std::uint32_t> blocks;
    Vm2JitBackend backend = Vm2JitBackend::off;
    Vm2JitEntry fn = nullptr;
    Vm2JitEntryStats stats{};
    std::size_t code_size = 0;
    std::uint64_t lru_tick = 0;
    std::array<std::uint8_t, 32> integrity_tag{};
    std::array<std::uint8_t, 16> key_context_tag{};
    void* integrity_ptr = nullptr;
    std::size_t integrity_size = 0;
#if defined(_WIN32)
    void* code_region = nullptr;
#else
    void* code_region = nullptr;
    std::size_t code_region_size = 0;
    void* dl_handle = nullptr;
#endif
    std::filesystem::path c_source_path;
    std::filesystem::path c_so_path;
  };

  struct ModuleCache {
    const Vm2Module* module = nullptr;
    std::size_t budget = 4u * 1024u * 1024u;
    std::size_t used = 0;
    std::uint64_t lru_clock = 0;
    std::array<std::uint8_t, 16> key_context_tag{};
    std::unordered_map<vmp::runtime::cryptor::JitCacheKey,
                       Entry,
                       vmp::runtime::cryptor::JitCacheKeyHash>
        entries;
    std::unordered_set<std::uint32_t> cooldown_entries;
  };

  mutable std::mutex mutex;
  Vm2JitConfig config;
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
    audit->append(vmp::runtime::audit::make_event(event_type, note, pc, "vm2_jit", "", 0));
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
                                                     std::uint32_t entry_pc,
                                                     std::uint32_t epoch_id) {
    return vmp::runtime::cryptor::JitCacheKey{module_id, entry_pc, epoch_id};
  }

  auto find_entry(ModuleCache& cache,
                  std::uint64_t module_id,
                  std::uint32_t entry_pc,
                  std::uint32_t epoch_id) {
    return cache.entries.find(make_key(module_id, entry_pc, epoch_id));
  }

  auto find_entry(const ModuleCache& cache,
                  std::uint64_t module_id,
                  std::uint32_t entry_pc,
                  std::uint32_t epoch_id) const {
    return cache.entries.find(make_key(module_id, entry_pc, epoch_id));
  }

  void destroy_entry(Entry& entry) {
#if defined(_WIN32)
    if (entry.code_region != nullptr) {
      ::VirtualFree(entry.code_region, 0, MEM_RELEASE);
    }
#else
    if (entry.code_region != nullptr) {
      ::munmap(entry.code_region, entry.code_region_size);
    }
    if (entry.dl_handle != nullptr) {
      ::dlclose(entry.dl_handle);
    }
#endif
    std::error_code ignore;
    if (!entry.c_source_path.empty()) {
      std::filesystem::remove(entry.c_source_path, ignore);
    }
    if (!entry.c_so_path.empty()) {
      std::filesystem::remove(entry.c_so_path, ignore);
    }
  }

  void erase_entry(const Vm2Module* module, ModuleCache& cache, std::uint32_t entry_pc, Vm2JitLifecycleState terminal_state,
                   const char* audit_type) {
    auto it = std::find_if(cache.entries.begin(), cache.entries.end(), [&](const auto& item) {
      return item.second.key.entry_pc == entry_pc;
    });
    if (it == cache.entries.end()) {
      return;
    }
    it->second.stats.state = terminal_state;
    cache.used -= it->second.code_size;
    if (module != nullptr) {
      module->clear_function_jit_entry(entry_pc);
    }
    if (audit_type != nullptr) {
      emit_audit(audit_type, "module=" + std::to_string(module != nullptr ? module->id() : 0u) + " pc=" + std::to_string(entry_pc),
                 entry_pc);
    }
    destroy_entry(it->second);
    cache.entries.erase(it);
  }

  void evict_if_needed(const Vm2Module& module, ModuleCache& cache, std::size_t incoming) {
    if (incoming > cache.budget) {
      emit_audit("vm2_jit_oom", "entry exceeds module cache budget", module.id());
      throw std::runtime_error("vm2_jit: entry exceeds module cache budget");
    }
    while (cache.used + incoming > cache.budget && !cache.entries.empty()) {
      emit_audit("vm2_jit_oom", "budget pressure module=" + std::to_string(module.id()), module.id());
      auto victim = std::min_element(cache.entries.begin(), cache.entries.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.second.lru_tick < rhs.second.lru_tick;
      });
      if (victim == cache.entries.end()) {
        break;
      }
      emit_audit("vm2_jit_evict",
                 "budget pressure module=" + std::to_string(module.id()) + " pc=" +
                     std::to_string(victim->second.key.entry_pc) + " epoch=" +
                     std::to_string(victim->second.key.epoch_id),
                 victim->second.key.entry_pc);
      erase_entry(&module, cache, victim->second.key.entry_pc, Vm2JitLifecycleState::evicted, nullptr);
    }
  }

  Entry compile_c_entry(const Vm2Module& module,
                        const Vm2Context& context,
                        std::uint32_t entry_pc,
                        const std::vector<std::uint32_t>& blocks) {
#if defined(VMP_JIT_C_BACKEND_DISABLED)
    (void)module;
    (void)context;
    (void)entry_pc;
    (void)blocks;
    throw std::runtime_error("vmp jit c-backend unavailable on iOS");
#elif defined(_WIN32)
    (void)module;
    (void)context;
    (void)entry_pc;
    (void)blocks;
    throw std::runtime_error("vm2_jit: c backend unavailable on windows in this build");
#else
    ensure_directory(cache_dir);
    const auto base = cache_dir / ("vm2jit_" + std::to_string(module.id()) + "_" + std::to_string(entry_pc));
    const auto c_path = base.string() + "_func.c";
    const auto so_path = base.string() + "_func.so";
    std::ofstream out(c_path, std::ios::binary | std::ios::trunc);
    if (!out) {
      throw std::runtime_error("vm2_jit: failed to open generated C source");
    }
    out << "#include <stdint.h>\n#include <dlfcn.h>\nstruct Vm2Context;\n";
    out << "typedef uint32_t (*fn_t)(struct Vm2Context*, uint32_t);\n";
    out << "__attribute__((visibility(\"default\"))) uint32_t vmp_vm2_jit_entry(struct Vm2Context* ctx) {\n";
    out << "  static fn_t fn = 0;\n";
    out << "  if (!fn) fn = (fn_t)dlsym(RTLD_DEFAULT, \"vmp_vm2_jit_execute_function\");\n";
    out << "  if (!fn) return 0;\n";
    out << "  return fn(ctx, " << entry_pc << "u);\n}\n";
    out.close();

    const std::string compile_cmd =
        std::string("cc -shared -O2 -fPIC -o ") + shell_escape(so_path) + " " + shell_escape(c_path) + " -ldl >/dev/null 2>&1";
    if (std::system(compile_cmd.c_str()) != 0) {
      throw std::runtime_error("vm2_jit: cc backend compile failed");
    }

    void* handle = ::dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr) {
      throw std::runtime_error(std::string("vm2_jit: dlopen failed: ") + ::dlerror());
    }
    auto* symbol = reinterpret_cast<Vm2JitEntry>(::dlsym(handle, "vmp_vm2_jit_entry"));
    if (symbol == nullptr) {
      ::dlclose(handle);
      throw std::runtime_error(std::string("vm2_jit: dlsym failed: ") + ::dlerror());
    }

    Entry entry;
    entry.entry_pc = entry_pc;
    entry.blocks = blocks;
    entry.backend = Vm2JitBackend::c;
    entry.fn = symbol;
    entry.code_size = 64;
    entry.stats.code_size = entry.code_size;
    entry.integrity_ptr = reinterpret_cast<void*>(symbol);
    entry.integrity_size = entry.code_size;
    entry.code_region = nullptr;
    entry.code_region_size = 0;
    entry.dl_handle = handle;
    entry.c_source_path = c_path;
    entry.c_so_path = so_path;
    entry.key_context_tag = current_key_context_tag(context, module.id());
    const auto key = derive_integrity_key(context, module.id());
    entry.integrity_tag = compute_integrity_tag(key, module.id(), entry_pc,
                                                snapshot_code_bytes(entry.integrity_ptr, entry.integrity_size));
    return entry;
#endif
  }

  Entry compile_x64_entry(const Vm2Module& module,
                          const Vm2Context& context,
                          std::uint32_t entry_pc,
                          const std::vector<std::uint32_t>& blocks) {
#if defined(__linux__) && defined(__x86_64__)
    if (!function_is_x64_supported(module, blocks)) {
      throw std::runtime_error("vm2_jit: x64 backend unsupported opcode in function");
    }
    const std::size_t alloc_size = 64;
    void* region = ::mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
      throw std::runtime_error("vm2_jit: mmap failed");
    }
    auto* out = static_cast<std::uint8_t*>(region);
    out[0] = 0x48; out[1] = 0x83; out[2] = 0xEC; out[3] = 0x08; out += 4;
    out[0] = 0x48; out[1] = 0xBE; out += 2;
    write_u64(out, static_cast<std::uint64_t>(entry_pc));
    out[0] = 0x48; out[1] = 0xB8; out += 2;
    write_u64(out, reinterpret_cast<std::uint64_t>(&vmp_vm2_jit_function_trampoline));
    out[0] = 0xFF; out[1] = 0xD0; out += 2;
    out[0] = 0x48; out[1] = 0x83; out[2] = 0xC4; out[3] = 0x08; out += 4;
    out[0] = 0xC3;
    const auto used = static_cast<std::size_t>(out - static_cast<std::uint8_t*>(region)) + 1u;
    if (::mprotect(region, alloc_size, PROT_READ | PROT_EXEC) != 0) {
      ::munmap(region, alloc_size);
      throw std::runtime_error("vm2_jit: mprotect failed");
    }

    Entry entry;
    entry.entry_pc = entry_pc;
    entry.blocks = blocks;
    entry.backend = Vm2JitBackend::x64;
    entry.fn = reinterpret_cast<Vm2JitEntry>(region);
    entry.code_size = used;
    entry.stats.code_size = entry.code_size;
    entry.integrity_ptr = region;
    entry.integrity_size = used;
    entry.code_region = region;
    entry.code_region_size = alloc_size;
    entry.key_context_tag = current_key_context_tag(context, module.id());
    const auto key = derive_integrity_key(context, module.id());
    entry.integrity_tag = compute_integrity_tag(key, module.id(), entry_pc,
                                                snapshot_code_bytes(entry.integrity_ptr, entry.integrity_size));
    return entry;
#else
    (void)module;
    (void)context;
    (void)entry_pc;
    (void)blocks;
    throw std::runtime_error("vm2_jit: x64 backend unavailable");
#endif
  }

  Entry compile_entry(const Vm2Module& module,
                      const Vm2Context& context,
                      std::uint32_t entry_pc,
                      const std::vector<std::uint32_t>& blocks) {
    auto requested = parse_backend_env();
    const auto& runtime_state = vmp::runtime::state::RuntimeState::instance();
    if (runtime_state.jit_execmem_unavailable()) {
      if (runtime_state.config().platform == "ios") {
        requested = Vm2JitBackend::off;
      } else if (c_backend_available()) {
        requested = Vm2JitBackend::c;
      } else {
        requested = Vm2JitBackend::off;
      }
    }
    if (requested == Vm2JitBackend::off) {
      throw std::runtime_error("vm2_jit: backend disabled");
    }
    if (requested == Vm2JitBackend::x64) {
      try {
        return compile_x64_entry(module, context, entry_pc, blocks);
      } catch (const std::exception& ex) {
        emit_audit("vm2_jit_fallback_backend", ex.what(), entry_pc);
        return compile_c_entry(module, context, entry_pc, blocks);
      }
    }
    return compile_c_entry(module, context, entry_pc, blocks);
  }
};

Vm2Jit& Vm2Jit::instance() {
  static Vm2Jit jit;
  return jit;
}

Vm2Jit::Vm2Jit() : impl_(new Impl{}) {
  impl_->refresh_config_from_env();
  vmp::runtime::cryptor::RollingOpcodeRegistry::instance().register_epoch_bump_callback(
      vmp::runtime::cryptor::VmDomain::vm2,
      [](std::uint64_t module_id, std::uint32_t epoch_id) { Vm2Jit::instance().invalidate_module_for_epoch_change(module_id, epoch_id); });
#if defined(_WIN32)
  impl_->cache_dir = std::filesystem::temp_directory_path() / ("vmp-vm2-jit-" + std::to_string(::GetCurrentProcessId()));
#else
  impl_->cache_dir = std::filesystem::temp_directory_path() / ("vmp-vm2-jit-" + std::to_string(::getpid()));
#endif
}

Vm2Jit::~Vm2Jit() { delete impl_; }

Vm2JitBackend Vm2Jit::backend_requested() const {
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
    return Vm2JitBackend::off;
  }

  if (impl_->c_backend_available()) {
    if (!impl_->capability_event_emitted) {
      impl_->emit_audit("jit_execmem_unavailable", "execmem unavailable; downgrading vm2 JIT to c backend");
      impl_->capability_event_emitted = true;
    }
    return Vm2JitBackend::c;
  }

  if (!impl_->capability_event_emitted) {
    impl_->emit_audit("jit_execmem_unavailable", "execmem unavailable and c backend missing; interpreter-only fallback");
    impl_->capability_event_emitted = true;
  }
  return Vm2JitBackend::off;
}

Vm2JitBackend Vm2Jit::selected_backend() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return backend_requested();
}

std::string Vm2Jit::selected_backend_name() const { return backend_name(selected_backend()); }

bool Vm2Jit::enabled() const { return selected_backend() != Vm2JitBackend::off; }

void Vm2Jit::set_audit_writer(vmp::runtime::audit::AuditWriter* writer) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->audit = writer;
}

void Vm2Jit::set_module_cache_budget_bytes(std::size_t value) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->config.module_cache_budget_bytes = value;
}

std::size_t Vm2Jit::module_cache_budget_bytes() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->config.module_cache_budget_bytes;
}

Vm2JitEntry Vm2Jit::compile_if_needed(const Vm2Module& module,
                                      const Vm2Context& context,
                                      std::uint32_t entry_pc,
                                      std::uint64_t hit_count) {
  vmp::runtime::cryptor::vm2::ensure_registered(module);
  const auto epoch_id = vmp::runtime::cryptor::vm2::current_epoch_id(module);
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->refresh_config_from_env();
  if (backend_requested() == Vm2JitBackend::off || hit_count < impl_->config.function_hot_threshold) {
    return nullptr;
  }
  auto& cache = impl_->module_cache(module.id());
  cache.module = &module;
  const auto tag = current_key_context_tag(context, module.id());
  if (!cache.entries.empty() && cache.key_context_tag != tag) {
    module.clear_function_jit_entries();
    impl_->modules.erase(module.id());
    impl_->emit_audit("vm2_jit_invalidate", "module=" + std::to_string(module.id()) + " reason=key_context_change");
    auto& fresh = impl_->module_cache(module.id());
    fresh.key_context_tag = tag;
    fresh.module = &module;
  } else {
    cache.key_context_tag = tag;
  }
  if (cache.cooldown_entries.find(entry_pc) != cache.cooldown_entries.end()) {
    return nullptr;
  }
  auto existing = impl_->find_entry(cache, module.id(), entry_pc, epoch_id);
  if (existing != cache.entries.end()) {
    if (existing->second.stats.state == Vm2JitLifecycleState::ready) {
      return existing->second.fn;
    }
    return nullptr;
  }

  Impl::Entry placeholder;
  placeholder.key = Impl::make_key(module.id(), entry_pc, epoch_id);
  placeholder.entry_pc = entry_pc;
  placeholder.stats.state = Vm2JitLifecycleState::compiling;
  cache.entries.emplace(placeholder.key, std::move(placeholder));
  try {
    auto blocks = discover_function_blocks(module, entry_pc);
    auto entry = impl_->compile_entry(module, context, entry_pc, blocks);
    entry.key = Impl::make_key(module.id(), entry_pc, epoch_id);
    entry.stats.compile_count = 1;
    entry.stats.state = Vm2JitLifecycleState::ready;
    impl_->evict_if_needed(module, cache, entry.code_size);
    entry.lru_tick = ++cache.lru_clock;
    cache.used += entry.code_size;
    cache.entries[entry.key] = std::move(entry);
    module.set_function_jit_entry(entry_pc, reinterpret_cast<std::uintptr_t>(cache.entries[Impl::make_key(module.id(), entry_pc, epoch_id)].fn));
    impl_->emit_audit("vm2_jit_compile",
                      "module=" + std::to_string(module.id()) + " pc=" + std::to_string(entry_pc) +
                          " epoch=" + std::to_string(epoch_id),
                      entry_pc);
    return cache.entries[Impl::make_key(module.id(), entry_pc, epoch_id)].fn;
  } catch (const std::exception& ex) {
    impl_->erase_entry(&module, cache, entry_pc, Vm2JitLifecycleState::invalidated, nullptr);
    impl_->emit_audit("vm2_jit_fallback_backend", ex.what(), entry_pc);
    return nullptr;
  }
}

std::uint32_t Vm2Jit::dispatch(Vm2Context& context, std::uint32_t entry_pc) {
  const auto epoch_id = vmp::runtime::cryptor::vm2::current_epoch_id(*context.module);
  Vm2JitEntry fn = nullptr;
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto mod_it = impl_->modules.find(context.module->id());
    if (mod_it == impl_->modules.end()) {
      return std::numeric_limits<std::uint32_t>::max();
    }
    auto& cache = mod_it->second;
    const auto tag = current_key_context_tag(context, context.module->id());
    if (cache.key_context_tag != tag) {
      context.module->clear_function_jit_entries();
      impl_->modules.erase(mod_it);
      impl_->emit_audit("vm2_jit_invalidate",
                        "module=" + std::to_string(context.module->id()) + " reason=key_context_change", entry_pc);
      return std::numeric_limits<std::uint32_t>::max();
    }
    auto entry_it = impl_->find_entry(cache, context.module->id(), entry_pc, epoch_id);
    if (entry_it == cache.entries.end() || entry_it->second.stats.state != Vm2JitLifecycleState::ready) {
      return std::numeric_limits<std::uint32_t>::max();
    }
    auto current_bytes = snapshot_code_bytes(entry_it->second.integrity_ptr, entry_it->second.integrity_size);
    const auto key = derive_integrity_key(context, context.module->id());
    const auto expected = compute_integrity_tag(key, context.module->id(), entry_pc, current_bytes);
    if (expected != entry_it->second.integrity_tag) {
      impl_->emit_audit("vm2_jit_integrity_failure",
                        "module=" + std::to_string(context.module->id()) + " pc=" + std::to_string(entry_pc), entry_pc);
      cache.cooldown_entries.insert(entry_pc);
      impl_->erase_entry(context.module, cache, entry_pc, Vm2JitLifecycleState::evicted, nullptr);
      return std::numeric_limits<std::uint32_t>::max();
    }
    entry_it->second.stats.hit_count++;
    entry_it->second.stats.entry_trampoline_hits++;
    entry_it->second.lru_tick = ++cache.lru_clock;
    fn = entry_it->second.fn;
  }
  return fn != nullptr ? fn(&context) : std::numeric_limits<std::uint32_t>::max();
}

void Vm2Jit::invalidate_all() {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  for (auto& [_, cache] : impl_->modules) {
    if (cache.module != nullptr) {
      cache.module->clear_function_jit_entries();
    }
    for (auto& [__, entry] : cache.entries) {
      entry.stats.state = Vm2JitLifecycleState::invalidated;
      impl_->destroy_entry(entry);
    }
  }
  impl_->modules.clear();
  impl_->emit_audit("vm2_jit_invalidate", "all");
}

void Vm2Jit::invalidate_module(std::uint64_t module_id) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  if (mod_it == impl_->modules.end()) {
    return;
  }
  if (mod_it->second.module != nullptr) {
    mod_it->second.module->clear_function_jit_entries();
  }
  for (auto& [_, entry] : mod_it->second.entries) {
    entry.stats.state = Vm2JitLifecycleState::invalidated;
    impl_->destroy_entry(entry);
  }
  impl_->modules.erase(mod_it);
  impl_->emit_audit("vm2_jit_invalidate", "module=" + std::to_string(module_id));
}

void Vm2Jit::invalidate_entry(std::uint64_t module_id, std::uint32_t entry_pc) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  if (mod_it == impl_->modules.end()) {
    return;
  }
  const auto epoch_id =
      vmp::runtime::cryptor::RollingOpcodeRegistry::instance().current_epoch_id(vmp::runtime::cryptor::VmDomain::vm2,
                                                                                module_id);
  auto entry_it = impl_->find_entry(mod_it->second, module_id, entry_pc, epoch_id);
  if (entry_it == mod_it->second.entries.end()) {
    return;
  }
  entry_it->second.stats.state = Vm2JitLifecycleState::invalidated;
  mod_it->second.used -= entry_it->second.code_size;
  if (mod_it->second.module != nullptr) {
    mod_it->second.module->clear_function_jit_entry(entry_pc);
  }
  impl_->destroy_entry(entry_it->second);
  mod_it->second.entries.erase(entry_it);
  impl_->emit_audit("vm2_jit_invalidate", "module=" + std::to_string(module_id) + " pc=" + std::to_string(entry_pc), entry_pc);
}

void Vm2Jit::invalidate_on_event(Vm2JitEventKind kind) {
  auto invalidate_modules_without_epoch = [&]() {
    std::vector<std::uint64_t> victims;
    {
      std::lock_guard<std::mutex> lock(impl_->mutex);
      for (const auto& [module_id, _] : impl_->modules) {
        if (vmp::runtime::cryptor::RollingOpcodeRegistry::instance().current_epoch_id(
                vmp::runtime::cryptor::VmDomain::vm2, module_id) == 0u) {
          victims.push_back(module_id);
        }
      }
    }
    for (const auto module_id : victims) {
      invalidate_module(module_id);
    }
  };

  switch (kind) {
    case Vm2JitEventKind::key_rotated:
      vmp::runtime::cryptor::RollingOpcodeRegistry::instance().rotate_all(
          vmp::runtime::cryptor::VmDomain::vm2,
          vmp::runtime::cryptor::RotationReason::key_rotation);
      invalidate_modules_without_epoch();
      break;
    case Vm2JitEventKind::integrity_failed:
      vmp::runtime::cryptor::RollingOpcodeRegistry::instance().rotate_all(
          vmp::runtime::cryptor::VmDomain::vm2,
          vmp::runtime::cryptor::RotationReason::integrity_event);
      invalidate_modules_without_epoch();
      break;
    case Vm2JitEventKind::detection_event:
      invalidate_all();
      break;
  }
}

void Vm2Jit::invalidate_module_for_key_context_change(const Vm2Module& module) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module.id());
  if (mod_it == impl_->modules.end()) {
    return;
  }
  for (auto& [_, entry] : mod_it->second.entries) {
    entry.stats.state = Vm2JitLifecycleState::invalidated;
    impl_->destroy_entry(entry);
  }
  module.clear_function_jit_entries();
  impl_->modules.erase(mod_it);
  impl_->emit_audit("vm2_jit_invalidate", "module=" + std::to_string(module.id()) + " reason=key_context_change");
}

void Vm2Jit::invalidate_module_for_epoch_change(std::uint64_t module_id, std::uint32_t current_epoch_id) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  if (mod_it == impl_->modules.end()) {
    return;
  }
  std::vector<std::uint32_t> victims;
  for (const auto& [key, entry] : mod_it->second.entries) {
    if (key.epoch_id != current_epoch_id) {
      victims.push_back(entry.entry_pc);
    }
  }
  for (const auto entry_pc : victims) {
    impl_->erase_entry(mod_it->second.module, mod_it->second, entry_pc, Vm2JitLifecycleState::invalidated, nullptr);
  }
  if (victims.empty()) {
    return;
  }
  impl_->emit_audit("vm2_jit_invalidate",
                    "module=" + std::to_string(module_id) + " reason=epoch_change epoch=" +
                        std::to_string(current_epoch_id));
}

Vm2JitEntryStats Vm2Jit::entry_stats(std::uint64_t module_id, std::uint32_t entry_pc) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  if (mod_it == impl_->modules.end()) {
    return {};
  }
  const auto epoch_id =
      vmp::runtime::cryptor::RollingOpcodeRegistry::instance().current_epoch_id(vmp::runtime::cryptor::VmDomain::vm2,
                                                                                module_id);
  auto entry_it = impl_->find_entry(mod_it->second, module_id, entry_pc, epoch_id);
  return entry_it == mod_it->second.entries.end() ? Vm2JitEntryStats{} : entry_it->second.stats;
}

std::size_t Vm2Jit::module_entry_count(std::uint64_t module_id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  return mod_it == impl_->modules.end() ? 0u : mod_it->second.entries.size();
}

std::size_t Vm2Jit::module_cache_bytes(std::uint64_t module_id) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  return mod_it == impl_->modules.end() ? 0u : mod_it->second.used;
}

bool Vm2Jit::has_entry(std::uint64_t module_id, std::uint32_t entry_pc) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  if (mod_it == impl_->modules.end()) {
    return false;
  }
  const auto epoch_id =
      vmp::runtime::cryptor::RollingOpcodeRegistry::instance().current_epoch_id(vmp::runtime::cryptor::VmDomain::vm2,
                                                                                module_id);
  return impl_->find_entry(mod_it->second, module_id, entry_pc, epoch_id) != mod_it->second.entries.end();
}

std::uint32_t Vm2Jit::entry_epoch_id(std::uint64_t module_id, std::uint32_t entry_pc) const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  if (mod_it == impl_->modules.end()) {
    return 0u;
  }
  const auto epoch_id =
      vmp::runtime::cryptor::RollingOpcodeRegistry::instance().current_epoch_id(vmp::runtime::cryptor::VmDomain::vm2,
                                                                                module_id);
  auto entry_it = impl_->find_entry(mod_it->second, module_id, entry_pc, epoch_id);
  return entry_it == mod_it->second.entries.end() ? 0u : entry_it->second.key.epoch_id;
}

bool Vm2Jit::debug_patch_code_byte(std::uint64_t module_id, std::uint32_t entry_pc, std::size_t offset, std::uint8_t value) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto mod_it = impl_->modules.find(module_id);
  if (mod_it == impl_->modules.end()) {
    return false;
  }
  const auto epoch_id =
      vmp::runtime::cryptor::RollingOpcodeRegistry::instance().current_epoch_id(vmp::runtime::cryptor::VmDomain::vm2,
                                                                                module_id);
  auto entry_it = impl_->find_entry(mod_it->second, module_id, entry_pc, epoch_id);
  if (entry_it == mod_it->second.entries.end()) {
    return false;
  }
  return patch_memory_byte(entry_it->second.integrity_ptr, entry_it->second.integrity_size, offset, value);
}

void Vm2Jit::reset_for_tests() {
  invalidate_all();
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->capability_event_emitted = false;
  impl_->refresh_config_from_env();
}

}  // namespace vmp::runtime::jit
