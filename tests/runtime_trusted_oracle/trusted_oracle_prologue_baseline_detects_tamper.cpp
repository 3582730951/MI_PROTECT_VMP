#include "test_common.h"

#include <array>
#include <iostream>

#include <vmp/runtime/trusted_oracle/oracle.h>

using namespace vmp::tests::runtime_trusted_oracle;

int main() {
  std::array<std::uint8_t, 64> region{};
  for (std::size_t i = 0; i < region.size(); ++i) {
    region[i] = static_cast<std::uint8_t>(0x20 + i);
  }

  const auto audit_path = temp_path("trusted_oracle_prologue", ".log");
  vmp::runtime::trusted_oracle::TrustedOracle oracle(bytes16(0x31), audit_path);
  auto& baseline = oracle.prologue_baselines();
  baseline.register_region("fake_api", region.data(), 32);

  const auto ok = baseline.verify_region("fake_api");
  require(ok.ok, "fresh baseline verification should succeed");
  require(ok.resident_matches, "resident baseline copy mismatch");
  require(ok.ephemeral_matches, "ephemeral baseline copy mismatch");

  region[7] ^= 0x5A;
  const auto bad = baseline.verify_region("fake_api");
  require(!bad.ok, "tampered region should fail verification");
  require(bad.event_type == "api_prologue_tampered", "unexpected tamper event type");
  require(read_all(audit_path).find("api_prologue_tampered") != std::string::npos,
          "tamper audit event missing");

  std::cout << "trusted_oracle_prologue_baseline_detects_tamper OK\n";
}
