#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

#include <nlohmann/json.hpp>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/audit/reaction.h>
#include <vmp/runtime/bridge/bridge.h>
#include <vmp/runtime/jit/vm1_jit.h>
#include <vmp/runtime/state/profile.h>
#include <vmp/runtime/state/scheduler.h>
#include <vmp/runtime/state/state.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/keyctx.h>
#include <vmp/runtime/vm1/vm1.h>

#include "string_protect_common.h"

namespace {

struct Options {
  std::string audit_path;
  std::string string_pool_path;
  std::string string_idx_path;
  std::string key_env = "VMP_STRING_MASTER_KEY";
  std::uint32_t native_print_string = 0;
  std::string jit = "auto";
  std::string profile_path;
  std::string profile_out_path;
  std::string module_path;
  std::vector<std::string> args;
};

void set_env_var(const char* name, const std::string& value) {
#if defined(_WIN32)
  _putenv_s(name, value.c_str());
#else
  ::setenv(name, value.c_str(), 1);
#endif
}

Options parse_args(int argc, char** argv) {
  Options options;
  for (int argi = 1; argi < argc; ++argi) {
    const std::string arg = argv[argi];
    if (arg == "--audit-path") {
      options.audit_path = argv[++argi];
    } else if (arg == "--string-pool") {
      options.string_pool_path = argv[++argi];
    } else if (arg == "--string-idx") {
      options.string_idx_path = argv[++argi];
    } else if (arg == "--key-env") {
      options.key_env = argv[++argi];
    } else if (arg == "--native-print-string") {
      options.native_print_string = static_cast<std::uint32_t>(std::stoul(argv[++argi]));
    } else if (arg == "--jit") {
      options.jit = argv[++argi];
    } else if (arg == "--profile") {
      options.profile_path = argv[++argi];
    } else if (arg == "--profile-out") {
      options.profile_out_path = argv[++argi];
    } else if (arg.rfind("--jit=", 0) == 0) {
      options.jit = arg.substr(6);
    } else if (arg.rfind("--", 0) == 0) {
      throw std::runtime_error("unknown argument: " + arg);
    } else if (options.module_path.empty()) {
      options.module_path = arg;
    } else {
      options.args.push_back(arg);
    }
  }
  if (options.module_path.empty()) {
    throw std::runtime_error("module path is required");
  }
  if (options.jit != "auto" && options.jit != "off" && options.jit != "c" && options.jit != "x64") {
    throw std::runtime_error("--jit must be auto|off|c|x64");
  }
  return options;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const auto options = parse_args(argc, argv);
    if (options.jit != "auto") {
      set_env_var("VMP_JIT_BACKEND", options.jit);
    }
    if (!options.audit_path.empty()) {
      set_env_var("VMP_AUDIT_PATH", options.audit_path);
    }
    vmp::runtime::jit::Vm1Jit::instance().reset_for_tests();
    if (const char* verbose = std::getenv("VMP_JIT_VERBOSE"); verbose != nullptr && std::string(verbose) == "1") {
      std::cout << "jit backend=" << vmp::runtime::jit::Vm1Jit::instance().selected_backend_name() << '\n';
    }

    const auto module = vmp::runtime::vm1::Vm1Module::load_from_file(options.module_path);
    vmp::runtime::vm1::Vm1Context context(module);
    for (int i = 0; i < static_cast<int>(options.args.size()) && i < 8; ++i) {
      context.vr[static_cast<std::size_t>(i)] = std::strtoull(options.args[static_cast<std::size_t>(i)].c_str(), nullptr, 0);
    }

    std::unique_ptr<vmp::runtime::audit::AuditWriter> writer;
    std::unique_ptr<vmp::runtime::audit::ReactionDispatcher> dispatcher;
    if (!options.audit_path.empty()) {
      writer = std::make_unique<vmp::runtime::audit::AuditWriter>(options.audit_path);
      dispatcher = std::make_unique<vmp::runtime::audit::ReactionDispatcher>(*writer,
                                                                             vmp::runtime::audit::ReactionPolicy::audit_only);
      context.audit_dispatcher = dispatcher.get();
      vmp::runtime::jit::Vm1Jit::instance().set_audit_writer(writer.get());
    }

    auto& runtime_state = vmp::runtime::state::RuntimeState::instance();
    runtime_state.shutdown();
    runtime_state.init_once(writer.get(), {VMP_PLATFORM_STR, "vmp-vm1-run", false});
    if (!options.profile_path.empty()) {
      if (!runtime_state.load_offline_profile(options.profile_path)) {
        throw std::runtime_error("failed to load offline profile");
      }
    }

    if (!options.string_pool_path.empty() || !options.string_idx_path.empty()) {
      if (options.string_pool_path.empty() || options.string_idx_path.empty()) {
        throw std::runtime_error("--string-pool and --string-idx must be used together");
      }
      const auto [index, salt] = vmp::tools::strings_tool::load_index_file(options.string_idx_path);
      auto key = vmp::runtime::strings::KeyContext(vmp::tools::strings_tool::key_from_env(options.key_env), salt);
      context.string_pool = std::make_shared<vmp::runtime::strings::StringPool>(
          vmp::tools::strings_tool::read_binary(options.string_pool_path), index, std::move(key));
      context.string_pool->set_audit_dispatcher(context.audit_dispatcher);
    }

    vmp::runtime::bridge::BridgeRegistry registry;
    if (options.native_print_string != 0) {
      registry.register_native(options.native_print_string, [&](const vmp::runtime::bridge::DomainCallArgs& args) {
        const auto text = context.transient_string(args.ints.at(0));
        std::cout << "native_string=" << text << '\n';
        return vmp::runtime::bridge::DomainCallResult{static_cast<std::uint64_t>(text.size()), 0.0, 0};
      });
      context.bridge_registry = &registry;
    }

    vmp::runtime::vm1::Vm1Interpreter interpreter;

    if (!options.profile_path.empty()) {
      vmp::runtime::state::HotScheduler scheduler;
      vmp::runtime::state::SchedulerInput input;
      input.modules[module.id()].current_budget_bytes = vmp::runtime::jit::Vm1Jit::instance().module_cache_budget_bytes();
      vmp::runtime::state::SchedulerBindings bindings;
      bindings.vm1_modules[module.id()] = &module;
      auto actions = scheduler.make_actions(runtime_state.fused_profile_snapshot(), runtime_state.hot_recorder().snapshot(),
                                            input, &runtime_state);
      scheduler.apply_actions(actions, bindings, &runtime_state);
    }

    const auto result = interpreter.execute(context);
    for (const auto& [pc, hits] : module.block_hit_counters) {
      for (std::uint64_t i = 0; i < hits; ++i) {
        runtime_state.hot_recorder().record_block_entry(module.id(), pc);
      }
      const auto stats = vmp::runtime::jit::Vm1Jit::instance().entry_stats(module.id(), pc);
      for (std::uint64_t i = 0; i < stats.hit_count; ++i) runtime_state.hot_recorder().record_jit_hit(module.id(), pc);
      const auto misses = hits > stats.hit_count ? hits - stats.hit_count : 0;
      for (std::uint64_t i = 0; i < misses; ++i) runtime_state.hot_recorder().record_jit_miss(module.id(), pc);
    }
    runtime_state.hot_recorder().set_uptime_seconds_for_tests(120.0);
    if (!options.profile_out_path.empty()) {
      const auto online_profile = vmp::runtime::state::offline_profile_from_snapshot(runtime_state.hot_recorder().snapshot(),
                                                                                      module.id());
      vmp::runtime::state::save_to_file(online_profile, options.profile_out_path);
    }
    if (writer) {
      writer->flush();
    }
    runtime_state.shutdown();
    std::cout << "ret_int=" << result.ret_int << " ret_float=" << result.ret_float << '\n';
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "vmp-vm1-run failed: " << ex.what() << '\n';
    return 1;
  }
}
