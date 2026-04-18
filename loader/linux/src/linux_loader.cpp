#include <vmp/loader/linux/linux_loader.h>

#if defined(__linux__)

#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <vmp/loader/common/platform_caps.h>
#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/audit/placeholder.h>
#include <vmp/runtime/integrity/integrity.h>
#include <vmp/runtime/state/state.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/keyctx.h>

namespace {

using vmp::runtime::audit::AnalysisEventRecord;
using vmp::runtime::audit::AuditWriter;
namespace common = vmp::loader::common;
namespace state = vmp::runtime::state;
namespace strings = vmp::runtime::strings;
namespace integrity = vmp::runtime::integrity;

std::once_flag g_loader_once;
std::unique_ptr<AuditWriter> g_audit;
std::unique_ptr<strings::KeyContext> g_key_context;

bool env_enabled(const char* name) noexcept {
  const char* value = std::getenv(name);
  return value != nullptr && *value != '\0';
}

std::vector<std::uint8_t> fixed_loader_salt() {
  return std::vector<std::uint8_t>{
      0x76, 0x6d, 0x70, 0x2d, 0x6c, 0x69, 0x6e, 0x75,
      0x78, 0x2d, 0x6c, 0x6f, 0x61, 0x64, 0x65, 0x72};
}

void append_event(AuditWriter& writer, std::string event_type, std::string note) noexcept {
  AnalysisEventRecord record = vmp::runtime::audit::make_event(std::move(event_type), std::move(note), 0, "", "", 0, "", "linux");
  writer.append(record);
  writer.flush();
}

void register_loader_regions(const char* loader_name, const void* code_base, std::size_t code_size,
                             const void* ro_base, std::size_t ro_size) {
  try {
    integrity::ProtectedRegion code{};
    code.name = std::string(loader_name) + ".code";
    code.base = code_base;
    code.size = code_size;
    code.flags = 0x1;
    integrity::RegionRegistry::instance().register_region(code);

    integrity::ProtectedRegion ro{};
    ro.name = std::string(loader_name) + ".rodata";
    ro.base = ro_base;
    ro.size = ro_size;
    ro.flags = 0x2;
    integrity::RegionRegistry::instance().register_region(ro);
  } catch (...) {
  }
}

void register_optional_rewriter_regions() {}

void load_key_context_if_present() {
  const char* hex = std::getenv("VMP_STRING_MASTER_KEY");
  if (hex == nullptr || *hex == '\0') {
    return;
  }
  std::vector<std::uint8_t> master = strings::hex_decode(hex);
  auto provider = strings::MasterKeyHandle([master]() mutable { return master; });
  g_key_context = std::make_unique<strings::KeyContext>(std::move(provider), fixed_loader_salt());
  (void)g_key_context->derive_subkey("loader-init");
  state::RuntimeState::instance().set_flag(state::RuntimeFlag::key_context_loaded);
}

void perform_linux_init() {
  if (env_enabled("VMP_DISABLE_LOADER")) {
    return;
  }

  g_audit = std::make_unique<AuditWriter>(common::detect_default_audit_path("linux"));

  state::RuntimeConfig config;
  config.platform = "linux";
  config.loader_entrypoint = ".init_array/constructor(101)";
  config.loader_disabled = false;
  state::RuntimeState::instance().init_once(g_audit.get(), config);

  const bool execmem_available = common::detect_execmem_available();
  state::RuntimeState::instance().set_jit_capability(!execmem_available);
  if (!execmem_available) {
    append_event(*g_audit, "jit_execmem_unavailable", "linux loader capability gate downgraded JIT backend");
  }

  { const auto salt = fixed_loader_salt(); register_loader_regions("linux", reinterpret_cast<const void*>(&perform_linux_init), 128, salt.data(), salt.size()); }
  register_optional_rewriter_regions();
  append_event(*g_audit, "loader_init", "linux_loader_ctor");
  load_key_context_if_present();
  vmp::runtime::audit::initialize_placeholder_hook_once();
  state::RuntimeState::instance().set_flag(state::RuntimeFlag::placeholder_called);
}

void record_init_failure(const std::string& note) noexcept {
  try {
    if (env_enabled("VMP_DISABLE_LOADER")) {
      return;
    }
    if (!g_audit) {
      g_audit = std::make_unique<AuditWriter>(common::detect_default_audit_path("linux"));
    }
    append_event(*g_audit, "loader_init_failure", note);
  } catch (...) {
  }
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void vmp_linux_init(void) __attribute__((constructor(101)));
extern "C" __attribute__((visibility("default"))) void vmp_linux_init(void) {
  std::call_once(g_loader_once, []() noexcept {
    try {
      perform_linux_init();
    } catch (const std::exception& ex) {
      record_init_failure(ex.what());
    } catch (...) {
      record_init_failure("unknown_exception");
    }
  });
}

using vmp_linux_init_fn = void (*)(void);
__attribute__((used, section(".init_array"))) static vmp_linux_init_fn vmp_linux_init_fallback = vmp_linux_init;

namespace vmp::loader::linux_platform {

const char* LoaderFacade::status() const noexcept { return "linux_loader_ready"; }

}  // namespace vmp::loader::linux_platform

#else

namespace vmp::loader::linux_platform {

const char* LoaderFacade::status() const noexcept { return "linux_loader_unavailable"; }

}  // namespace vmp::loader::linux_platform

extern "C" void vmp_linux_init(void) {}

#endif
