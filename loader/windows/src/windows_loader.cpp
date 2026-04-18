#include <vmp/loader/windows/windows_loader.h>

#ifdef _WIN32

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
thread_local bool g_tls_seen = false;

bool env_enabled(const char* name) noexcept {
  const char* value = std::getenv(name);
  return value != nullptr && *value != '\0';
}

std::vector<std::uint8_t> fixed_loader_salt() {
  return std::vector<std::uint8_t>{
      0x76, 0x6d, 0x70, 0x2d, 0x77, 0x69, 0x6e, 0x64,
      0x6f, 0x77, 0x73, 0x2d, 0x6c, 0x64, 0x72, 0x21};
}

void append_event(AuditWriter& writer, std::string event_type, std::string note) noexcept {
  AnalysisEventRecord record = vmp::runtime::audit::make_event(std::move(event_type), std::move(note), 0, "", "", 0, "", "windows");
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

void perform_process_attach() {
  if (env_enabled("VMP_DISABLE_LOADER")) {
    return;
  }

  g_audit = std::make_unique<AuditWriter>(common::detect_default_audit_path("windows"));

  state::RuntimeConfig config;
  config.platform = "windows";
  config.loader_entrypoint = "TLS/.CRT$XLB";
  config.loader_disabled = false;
  state::RuntimeState::instance().init_once(g_audit.get(), config);

  const bool execmem_available = common::detect_execmem_available();
  state::RuntimeState::instance().set_jit_capability(!execmem_available);
  if (!execmem_available) {
    append_event(*g_audit, "jit_execmem_unavailable", "windows loader capability gate downgraded JIT backend");
  }

  { const auto salt = fixed_loader_salt(); register_loader_regions("windows", reinterpret_cast<const void*>(&perform_process_attach), 128, salt.data(), salt.size()); }
  register_optional_rewriter_regions();
  append_event(*g_audit, "loader_init", "windows_loader_attach");
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
      g_audit = std::make_unique<AuditWriter>(common::detect_default_audit_path("windows"));
    }
    append_event(*g_audit, "loader_init_failure", note);
  } catch (...) {
  }
}

void init_once_process() noexcept {
  std::call_once(g_loader_once, []() noexcept {
    try {
      perform_process_attach();
    } catch (const std::exception& ex) {
      record_init_failure(ex.what());
    } catch (...) {
      record_init_failure("unknown_exception");
    }
  });
}

void on_thread_event(DWORD reason) noexcept {
  if (reason == DLL_THREAD_ATTACH) {
    g_tls_seen = true;
  } else if (reason == DLL_THREAD_DETACH) {
    g_tls_seen = false;
  }
}

void NTAPI vmp_windows_tls_callback(PVOID, DWORD reason, PVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    init_once_process();
  }
  on_thread_event(reason);
}

#if defined(_MSC_VER)
#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK vmp_windows_tls_callback_ptr = vmp_windows_tls_callback;
#if defined(_M_X64) || defined(_M_ARM64)
#pragma comment(linker, "/INCLUDE:__tls_used")
#else
#pragma comment(linker, "/INCLUDE:_tls_used")
#endif
#else
extern "C" PIMAGE_TLS_CALLBACK vmp_windows_tls_callback_ptr __attribute__((section(".CRT$XLB"), used)) = vmp_windows_tls_callback;
#endif

}  // namespace

extern "C" BOOL WINAPI vmp_windows_loader_dll_main(HINSTANCE, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    init_once_process();
  }
  on_thread_event(reason);
  return TRUE;
}

extern "C" void vmp_windows_loader_force_link(void) {
  init_once_process();
}

namespace vmp::loader::windows {

const char* LoaderFacade::status() const noexcept { return "windows_loader_ready"; }

}  // namespace vmp::loader::windows

#else

namespace vmp::loader::windows {

const char* LoaderFacade::status() const noexcept { return "windows_loader_unavailable"; }

}  // namespace vmp::loader::windows

#endif
