#include "test_common.h"

#include <iostream>

#include <vmp/runtime/env_integrity/monitor.h>

using namespace vmp::tests::runtime_env_integrity;

namespace {

void sample_target() {}
void alternate_target() {}

}  // namespace

int main() {
  try {
    const auto audit_path = temp_path("env_got_baseline", ".log");
    vmp::runtime::env_integrity::EnvIntegrityMonitor monitor(bytes16(0x31), audit_path);

    auto* slot_value = reinterpret_cast<void*>(&sample_target);
    monitor.import_table().register_got_slot("dispatcher.synthetic_slot", &slot_value);

    const auto clean = monitor.verify_sensitive_domain("vm1");
    require(clean.import_table_ok, "baseline GOT slot should verify cleanly");

    slot_value = reinterpret_cast<void*>(&alternate_target);
    const auto dirty = monitor.verify_sensitive_domain("vm1");
    require(!dirty.import_table_ok, "tampered GOT slot must fail verification");
    require(read_all(audit_path).find("got_entry_tampered") != std::string::npos,
            "got_entry_tampered audit missing");

    std::cout << "env_got_baseline_detects_tamper OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "env_got_baseline_detects_tamper failed: " << ex.what() << '\n';
    return 1;
  }
}
