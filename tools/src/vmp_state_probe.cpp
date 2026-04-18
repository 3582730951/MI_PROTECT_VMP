#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/integrity/integrity.h>
#include <vmp/runtime/state/state.h>
#include <vmp/runtime/strings/keyctx.h>

namespace {

struct Options {
  std::string event;
  std::filesystem::path audit_path = std::filesystem::temp_directory_path() / "vmp_state_probe.log";
  bool no_exit = false;
};

Options parse_args(int argc, char** argv) {
  Options out;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--event" && i + 1 < argc) {
      out.event = argv[++i];
    } else if (arg == "--audit" && i + 1 < argc) {
      out.audit_path = argv[++i];
    } else if (arg == "--no-exit") {
      out.no_exit = true;
    } else {
      throw std::runtime_error("unknown arg: " + arg);
    }
  }
  if (out.event.empty()) {
    throw std::runtime_error("--event required");
  }
  return out;
}

vmp::runtime::state::RuntimeEventKind parse_event(const std::string& raw, vmp::runtime::state::RuntimeEventPayload& payload) {
  if (raw.rfind("integrity_failed:", 0) == 0) {
    payload.name = raw.substr(std::string("integrity_failed:").size());
    payload.note = "region=" + payload.name;
    return vmp::runtime::state::RuntimeEventKind::integrity_failed;
  }
  if (raw == "hw_breakpoint") {
    payload.name = raw;
    payload.note = raw;
    return vmp::runtime::state::RuntimeEventKind::hw_breakpoint;
  }
  if (raw == "env_anomaly") {
    payload.name = raw;
    payload.note = raw;
    return vmp::runtime::state::RuntimeEventKind::env_anomaly;
  }
  if (raw == "shutdown") {
    payload.name = raw;
    payload.note = raw;
    return vmp::runtime::state::RuntimeEventKind::shutdown_requested;
  }
  throw std::runtime_error("unsupported event: " + raw);
}

std::string read_all(const std::filesystem::path& path) {
  std::ifstream in(path);
  return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const auto options = parse_args(argc, argv);
    vmp::runtime::audit::AuditWriter writer(options.audit_path);
    auto& state = vmp::runtime::state::RuntimeState::instance();
    state.shutdown();

    vmp::runtime::state::RuntimeConfig config;
    config.platform = "linux";
    config.loader_entrypoint = "vmp-state-probe";
    config.terminate_grace_ms = 50;
    if (options.no_exit) {
      config.exit_fn = [](int) {};
    }
    state.init_once(&writer, config);
    std::cout << "state=" << vmp::runtime::state::to_string(state.current_state()) << "\n";

    vmp::runtime::state::RuntimeEventPayload payload;
    const auto kind = parse_event(options.event, payload);
    state.observe(kind, payload);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    writer.flush();
    std::cout << "after=" << vmp::runtime::state::to_string(state.current_state()) << "\n";
    const auto log = read_all(options.audit_path);
    std::cout << log;
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "vmp-state-probe failed: " << ex.what() << '\n';
    return 1;
  }
}
