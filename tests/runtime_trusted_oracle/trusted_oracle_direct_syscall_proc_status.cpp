#include "test_common.h"

#include <iostream>
#include <string>
#include <vector>

#include <vmp/runtime/trusted_oracle/oracle.h>

using namespace vmp::tests::runtime_trusted_oracle;

int main() {
  std::vector<char> buffer(4096, '\0');
  const int fd = vmp::runtime::trusted_oracle::DirectSyscall::open_readonly("/proc/self/status");
  require(fd >= 0, "direct open(/proc/self/status) failed");
  const auto count = vmp::runtime::trusted_oracle::DirectSyscall::read(fd, buffer.data(), buffer.size() - 1);
  require(count > 0, "direct read(/proc/self/status) returned no bytes");
  require(vmp::runtime::trusted_oracle::DirectSyscall::close(fd) == 0, "direct close(/proc/self/status) failed");

  const std::string text(buffer.data(), static_cast<std::size_t>(count));
  require(text.find("TracerPid:") != std::string::npos, "TracerPid line missing from /proc/self/status");
  require(vmp::runtime::trusted_oracle::DirectSyscall::gettid() != 0, "direct gettid returned zero");

  vmp::runtime::trusted_oracle::TrustedOracle oracle(bytes16(0x11));
  const auto ptrace_vote = oracle.probe_ptrace_status();
  require(!ptrace_vote.divergent, "clean harness should not diverge on ptrace vote");
  require(!ptrace_vote.fact_value, "clean harness should not look ptraced");

  std::cout << "trusted_oracle_direct_syscall_proc_status OK\n";
}
