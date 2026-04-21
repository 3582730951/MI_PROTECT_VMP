#include "test_common.h"

#include <iostream>
#include <vector>

#include <vmp/runtime/trusted_oracle/oracle.h>

using namespace vmp::tests::runtime_trusted_oracle;

int main() {
  const auto audit_path = temp_path("trusted_oracle_vote", ".log");
  vmp::runtime::trusted_oracle::TrustedOracle oracle(bytes16(0x41), audit_path);

  vmp::runtime::trusted_oracle::PtraceReadings ptrace{};
  ptrace.status_sampled = true;
  ptrace.tracer_pid = 0;
  ptrace.traceme_attempted = true;
  ptrace.traceme_allowed = false;
  const auto ptrace_vote = oracle.evaluate_ptrace_status(ptrace);
  require(ptrace_vote.divergent, "ptrace vote should detect divergence");
  require(ptrace_vote.event_type == "oracle_divergence", "ptrace divergence event mismatch");

  vmp::runtime::trusted_oracle::TimeReadings time{};
  time.counter_delta = 500;
  time.monotonic_delta_ns = 50'000'000;
  time.max_clock_delta_ns = 1;
  const auto time_vote = oracle.evaluate_time_sources(time);
  require(time_vote.divergent, "time-source vote should detect divergence");

  vmp::runtime::trusted_oracle::RandomReadings random{};
  random.syscall_sampled = true;
  random.syscall_ok = true;
  random.syscall_bytes = {0x01, 0x02, 0x03, 0x04};
  random.hardware_sampled = true;
  random.hardware_ok = false;
  const auto random_vote = oracle.evaluate_random_sources(random);
  require(random_vote.divergent, "random-source vote should detect divergence");

  const auto log = read_all(audit_path);
  require(log.find("oracle_divergence") != std::string::npos, "oracle divergence audit missing");
  require(log.find("fact=ptrace_attached") != std::string::npos, "ptrace divergence note missing");
  require(log.find("fact=time_source") != std::string::npos, "time divergence note missing");
  require(log.find("fact=random_source") != std::string::npos, "random divergence note missing");

  std::cout << "trusted_oracle_cross_source_voting OK\n";
}
