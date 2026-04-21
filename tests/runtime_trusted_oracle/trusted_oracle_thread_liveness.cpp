#include "test_common.h"

#include <iostream>

#include <vmp/runtime/trusted_oracle/oracle.h>

using namespace vmp::tests::runtime_trusted_oracle;

int main() {
  const auto audit_path = temp_path("trusted_oracle_thread", ".log");
  vmp::runtime::trusted_oracle::TrustedOracle oracle(bytes16(0x51), audit_path);

  const auto ok = oracle.verify_detector_thread();
  require(ok.matched, "detector thread should report matching tid");
  require(ok.expected_tid != 0, "expected tid should be populated");
  require(ok.observed_tid != 0, "observed tid should be populated");

  vmp::runtime::trusted_oracle::ThreadVerificationOptions opts;
  opts.observed_tid_provider = []() -> std::uint64_t { return 0xDEADBEEF; };
  const auto mismatch = oracle.verify_detector_thread(opts);
  require(!mismatch.matched, "injected tid mismatch should be detected");
  require(read_all(audit_path).find("thread_creation_hijacked") != std::string::npos,
          "thread hijack audit event missing");

  std::cout << "trusted_oracle_thread_liveness OK\n";
}
