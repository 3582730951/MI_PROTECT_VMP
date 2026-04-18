#include "test_common.h"

#include <chrono>
#include <cstdlib>
#include <iostream>

using namespace vmp::tests::runtime_state_machine;

int main() {
  const auto audit_path = temp_path("hw_breakpoint_probe", ".log");
  auto exe = std::filesystem::current_path() / "tools" / "vmp-state-probe";
  if (!std::filesystem::exists(exe)) {
    exe = std::filesystem::current_path().parent_path() / "tools" / "vmp-state-probe";
  }
  const auto start = std::chrono::steady_clock::now();
  const std::string cmd = shell_quote(exe.string()) + " --audit " + shell_quote(audit_path.string()) + " --event hw_breakpoint >/dev/null 2>&1";
  const int rc = std::system(cmd.c_str());
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
  require(rc == 0, "vmp-state-probe hw_breakpoint failed");
  require(elapsed >= 40 && elapsed <= 1000, "grace window out of range");
  const auto log = read_all(audit_path);
  require(log.find("state_transition") != std::string::npos, "missing state_transition");
  require(log.find("Terminating") != std::string::npos, "missing terminating transition note");
  require(log.find("terminating_grace_start") != std::string::npos, "missing grace start");
  require(log.find("terminating_done") != std::string::npos, "missing terminating_done");
  std::cout << "hw_breakpoint_goes_to_terminating OK\n";
}
