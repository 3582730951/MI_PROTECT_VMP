#include <vmp/loader/ios/ios_loader.h>

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
      0x76, 0x6d, 0x70, 0x2d, 0x69, 0x6f, 0x73, 0x2d,
      0x6c, 0x6f, 0x61, 0x64, 0x65, 0x72, 0x21, 0x21};
}

void append_event(AuditWriter& writer, std::string event_type, std::string note) noexcept {
  AnalysisEventRecord record = vmp::runtime::audit::make_event(std::move(event_type), std::move(note), 0, "", "", 0, "", "ios");
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

void perform_ios_init() {
  if (env_enabled("VMP_DISABLE_LOADER")) {
    return;
  }

  g_audit = std::make_unique<AuditWriter>(common::detect_default_audit_path("ios"));

  state::RuntimeConfig config;
  config.platform = "ios";
  config.loader_entrypoint = "constructor";
  config.loader_disabled = false;
  state::RuntimeState::instance().init_once(g_audit.get(), config);

  const bool execmem_available = common::detect_execmem_available();
  state::RuntimeState::instance().set_jit_capability(!execmem_available);
  if (!execmem_available) {
    append_event(*g_audit, "jit_execmem_unavailable", "ios capability gate forcing interpreter-only fallback");
  }

  { const auto salt = fixed_loader_salt(); register_loader_regions("ios", reinterpret_cast<const void*>(&perform_ios_init), 128, salt.data(), salt.size()); }
  register_optional_rewriter_regions();
  append_event(*g_audit, "loader_init", "ios_loader_init");
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
      g_audit = std::make_unique<AuditWriter>(common::detect_default_audit_path("ios"));
    }
    append_event(*g_audit, "loader_init_failure", note);
  } catch (...) {
  }
}

}  // namespace

extern "C" __attribute__((visibility("default"), constructor)) void vmp_ios_init(void) {
  std::call_once(g_loader_once, []() noexcept {
    try {
      perform_ios_init();
    } catch (const std::exception& ex) {
      record_init_failure(ex.what());
    } catch (...) {
      record_init_failure("unknown_exception");
    }
  });
}

namespace vmp::loader::ios {

const char* LoaderFacade::status() const noexcept { return "ios_loader_ready"; }

}  // namespace vmp::loader::ios
