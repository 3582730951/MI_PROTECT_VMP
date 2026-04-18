#include <cstdlib>
#include <filesystem>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/state/state.h>

#if defined(VMP_SELFTEST_WINDOWS)
#include <vmp/loader/windows/windows_loader.h>
#elif defined(VMP_SELFTEST_LINUX)
#include <vmp/loader/linux/linux_loader.h>
#elif defined(VMP_SELFTEST_ANDROID)
#include <vmp/loader/android/android_loader.h>
#elif defined(VMP_SELFTEST_IOS)
#include <vmp/loader/ios/ios_loader.h>
#endif

int main() {
  const auto audit_path = std::filesystem::temp_directory_path() / "vmp_loader_selftest.log";
  vmp::runtime::audit::AuditWriter writer(audit_path);
  auto& state = vmp::runtime::state::RuntimeState::instance();
  state.shutdown();
  (void)state.init_once(&writer, {"selftest", "vmp-loader-selftest", false});
#if defined(VMP_SELFTEST_WINDOWS)
  vmp_windows_loader_force_link();
  (void)vmp::loader::windows::LoaderFacade{}.status();
#elif defined(VMP_SELFTEST_LINUX)
  (void)vmp::loader::linux_platform::LoaderFacade{}.status();
#elif defined(VMP_SELFTEST_ANDROID)
  (void)vmp::loader::android::LoaderFacade{}.status();
#elif defined(VMP_SELFTEST_IOS)
  (void)vmp::loader::ios::LoaderFacade{}.status();
#endif
  return EXIT_SUCCESS;
}
