#include <vmp/runtime/bridge/bridge.h>

#include <memory>
#include <mutex>

#include <vmp/runtime/cryptor/rolling_opcode_vm1.h>
#include <vmp/runtime/vm1/vm1.h>

namespace vmp::runtime::bridge {
namespace {
thread_local int g_bridge_depth = 0;
thread_local std::shared_ptr<DomainCallException> g_last_domain_exception;

struct DepthGuard {
  explicit DepthGuard(int max_depth) {
    if (max_depth <= 0) {
      max_depth = 64;
    }
    if (g_bridge_depth >= max_depth) {
      throw BridgeException("bridge: max_depth exceeded");
    }
    ++g_bridge_depth;
  }
  ~DepthGuard() { --g_bridge_depth; }
};
}  // namespace

DomainCallException::DomainCallException(int status_code, std::string message)
    : std::runtime_error(std::move(message)), status_code_(status_code) {}

void BridgeRegistry::register_native(std::uint32_t id,
                                     std::function<DomainCallResult(const DomainCallArgs&)> fn) {
  native_handlers_[id] = std::move(fn);
}

void BridgeRegistry::register_vm1(std::uint32_t id, vmp::runtime::vm1::Vm1Module* module) {
  vm1_handlers_[id] = module;
}

DomainCallResult BridgeRegistry::call(Domain target, std::uint32_t id, const DomainCallArgs& args, int max_depth) {
  DepthGuard depth_guard(max_depth);
  clear_last_domain_exception();
  try {
    switch (target) {
      case Domain::native: {
        const auto it = native_handlers_.find(id);
        if (it == native_handlers_.end()) {
          throw BridgeException("bridge: native handler not found");
        }
        return it->second(args);
      }
      case Domain::vm1: {
        const auto it = vm1_handlers_.find(id);
        if (it == vm1_handlers_.end() || it->second == nullptr) {
          throw BridgeException("bridge: vm1 module not found");
        }
        vmp::runtime::cryptor::vm1::notify_domain_switch(*it->second);
        vmp::runtime::vm1::Vm1Context context(*it->second);
        context.bridge_registry = this;
        context.max_bridge_depth = max_depth;
        for (std::size_t i = 0; i < args.ints.size() && i < 8; ++i) {
          context.vr[i] = args.ints[i];
        }
        const std::size_t spill_count = args.ints.size() > 8 ? args.ints.size() - 8 : 0u;
        context.set_stack_top(static_cast<std::uint64_t>(spill_count * sizeof(std::uint64_t)));
        for (std::size_t i = 0; i < spill_count; ++i) {
          context.write_memory<std::uint64_t>(static_cast<std::uint64_t>(i * sizeof(std::uint64_t)), args.ints[8 + i]);
        }
        for (std::size_t i = 0; i < args.floats.size() && i < vmp::runtime::vm1::kVm1FloatRegisterCount; ++i) {
          context.vfr[i] = args.floats[i];
        }
        for (std::size_t i = 0; i < args.opaque.size() && i < 8; ++i) {
          context.vr[i] = reinterpret_cast<std::uintptr_t>(args.opaque[i]);
        }
        vmp::runtime::vm1::Vm1Interpreter interpreter;
        const auto result = interpreter.execute(context);
        return DomainCallResult{result.ret_int, result.ret_float, 0};
      }
      case Domain::vm2: {
        const auto it = vm2_handlers_.find(id);
        if (it == vm2_handlers_.end()) {
          throw BridgeException("bridge: vm2 module not found");
        }
        return it->second(args, this, max_depth);
      }
    }
  } catch (const BridgeException&) {
    throw;
  } catch (const std::exception& ex) {
    g_last_domain_exception = std::make_shared<DomainCallException>(-1, ex.what());
    return DomainCallResult{0, 0.0, -1};
  } catch (...) {
    g_last_domain_exception = std::make_shared<DomainCallException>(-2, "bridge: unknown exception");
    return DomainCallResult{0, 0.0, -2};
  }
  throw BridgeException("bridge: unreachable target");
}

std::shared_ptr<DomainCallException> BridgeRegistry::last_domain_exception() const {
  return g_last_domain_exception;
}

void BridgeRegistry::clear_last_domain_exception() { g_last_domain_exception.reset(); }

}  // namespace vmp::runtime::bridge
