#include <vmp/runtime/vm1/vm1.h>

#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <vector>

#if VMP_WITH_JIT
#include <vmp/runtime/jit/vm1_jit.h>
#endif
#include <vmp/runtime/cryptor/rolling_opcode_vm1.h>
#include <vmp/runtime/env_integrity/monitor.h>
#include <vmp/runtime/stack_probe/probe.h>

namespace vmp::runtime::vm1 {
namespace {

struct BlockExecutionResult {
  std::uint32_t next_pc = 0;
  bool halted = false;
};

std::uint8_t fetch_byte(const Vm1Module& module, std::size_t forward_pc) {
  if (forward_pc >= module.code.size()) {
    throw VmException(VmTrapCode::invalid_module, static_cast<std::uint32_t>(forward_pc), "vm1: pc out of range");
  }
  if ((module.module_flags & VMP_FLAG_OPCODE_ENCRYPTED) != 0u) {
    return vmp::runtime::cryptor::vm1::fetch_byte(module, forward_pc);
  }
  if ((module.module_flags & VMP_FLAG_REVERSE_ORDER) == 0u) {
    return module.code[forward_pc];
  }
  if (module.reverse_code.empty() || module.forward_instruction_start_by_pc.size() != module.code.size() ||
      module.forward_instruction_length_by_pc.size() != module.code.size()) {
    throw VmException(VmTrapCode::invalid_module, static_cast<std::uint32_t>(forward_pc), "vm1: reverse layout cache missing");
  }
  const auto inst_start = module.forward_instruction_start_by_pc[forward_pc];
  const auto inst_length = module.forward_instruction_length_by_pc[forward_pc];
  if (inst_length == 0u) {
    throw VmException(VmTrapCode::invalid_module, static_cast<std::uint32_t>(forward_pc), "vm1: invalid reverse instruction metadata");
  }
  const auto reverse_pc = module.code.size() - static_cast<std::size_t>(inst_start) - inst_length +
                          (forward_pc - static_cast<std::size_t>(inst_start));
  return module.reverse_code.at(reverse_pc);
}

std::uint16_t read_u16(const Vm1Module& module, std::size_t& pc) {
  if (pc + 2 > module.code.size()) {
    throw VmException(VmTrapCode::invalid_module, static_cast<std::uint32_t>(pc), "vm1: truncated u16 operand");
  }
  const auto lo = fetch_byte(module, pc);
  const auto hi = fetch_byte(module, pc + 1u);
  pc += 2;
  return static_cast<std::uint16_t>(lo) | static_cast<std::uint16_t>(hi << 8u);
}

std::uint32_t read_u32(const Vm1Module& module, std::size_t& pc) {
  if (pc + 4 > module.code.size()) {
    throw VmException(VmTrapCode::invalid_module, static_cast<std::uint32_t>(pc), "vm1: truncated u32 operand");
  }
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(fetch_byte(module, pc + static_cast<std::size_t>(i))) << (8 * i);
  }
  pc += 4;
  return value;
}

std::uint64_t read_u64(const Vm1Module& module, std::size_t& pc) {
  if (pc + 8 > module.code.size()) {
    throw VmException(VmTrapCode::invalid_module, static_cast<std::uint32_t>(pc), "vm1: truncated u64 operand");
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(fetch_byte(module, pc + static_cast<std::size_t>(i))) << (8 * i);
  }
  pc += 8;
  return value;
}

std::int32_t read_i32(const Vm1Module& module, std::size_t& pc) {
  return static_cast<std::int32_t>(read_u32(module, pc));
}

double bit_cast_double(std::uint64_t value) {
  double out = 0.0;
  std::memcpy(&out, &value, sizeof(out));
  return out;
}

std::uint64_t flags_carry_add(std::uint64_t lhs, std::uint64_t rhs) { return lhs > std::numeric_limits<std::uint64_t>::max() - rhs; }

bool flags_overflow_add(std::int64_t lhs, std::int64_t rhs, std::int64_t result) {
  return ((lhs ^ result) & (rhs ^ result)) < 0;
}

bool flags_overflow_sub(std::int64_t lhs, std::int64_t rhs, std::int64_t result) {
  return ((lhs ^ rhs) & (lhs ^ result)) < 0;
}

void set_common_flags(Vm1Context& context, std::uint64_t value) {
  context.flags.zero = (value == 0);
  context.flags.neg = (static_cast<std::int64_t>(value) < 0);
}

void set_logic_flags(Vm1Context& context, std::uint64_t value) {
  set_common_flags(context, value);
  context.flags.carry = false;
  context.flags.overflow = false;
}

void dispatch_audit(Vm1Context& context, const std::string& event_type, const std::string& note) {
  if (context.audit_dispatcher == nullptr) {
    return;
  }
  context.audit_dispatcher->dispatch(
      vmp::runtime::audit::make_event(event_type, note, context.pc, "vm1", "", 0),
      vmp::runtime::audit::ReactionPolicy::audit_only);
}

[[noreturn]] void raise_trap(Vm1Context& context, VmTrapCode code, const std::string& message,
                             const char* event_type = nullptr) {
  if (event_type != nullptr) {
    dispatch_audit(context, event_type, message);
  }
  throw VmException(code, context.pc, message);
}

std::uint64_t resolve_address(const Vm1Context& context, std::uint8_t base, std::int32_t offset) {
  std::uint64_t base_value = 0;
  if (base == static_cast<std::uint8_t>(MemoryBase::stack_pointer)) {
    base_value = context.sp;
  } else if (base < kVm1GeneralRegisterCount) {
    base_value = context.vr[base];
  } else {
    throw VmException(VmTrapCode::invalid_register, context.pc, "vm1: invalid memory base register");
  }
  if (offset >= 0) {
    return base_value + static_cast<std::uint64_t>(offset);
  }
  return base_value - static_cast<std::uint64_t>(-static_cast<std::int64_t>(offset));
}

void compare_and_set_flags(Vm1Context& context, std::uint64_t lhs, std::uint64_t rhs) {
  const auto s_lhs = static_cast<std::int64_t>(lhs);
  const auto s_rhs = static_cast<std::int64_t>(rhs);
  const auto diff = static_cast<std::uint64_t>(lhs - rhs);
  set_common_flags(context, diff);
  context.flags.carry = lhs < rhs;
  context.flags.overflow = flags_overflow_sub(s_lhs, s_rhs, static_cast<std::int64_t>(diff));
}

void set_float_flags(Vm1Context& context, double value) {
  context.flags.zero = (value == 0.0);
  context.flags.neg = std::signbit(value);
  context.flags.carry = false;
  context.flags.overflow = false;
}

struct VecPair {
  std::uint64_t lo = 0;
  std::uint64_t hi = 0;
};

VecPair read_vec_pair(const Vm1Context& context, std::uint8_t index) {
  const auto base = static_cast<std::size_t>(index) * 2u;
  if (base + 1 >= context.vr.size()) {
    throw VmException(VmTrapCode::invalid_register, context.pc, "vm1: vector register out of range");
  }
  return {context.vr[base], context.vr[base + 1]};
}

void write_vec_pair(Vm1Context& context, std::uint8_t index, const VecPair& value) {
  const auto base = static_cast<std::size_t>(index) * 2u;
  if (base + 1 >= context.vr.size()) {
    throw VmException(VmTrapCode::invalid_register, context.pc, "vm1: vector register out of range");
  }
  context.vr[base] = value.lo;
  context.vr[base + 1] = value.hi;
  set_logic_flags(context, value.lo | value.hi);
}

bool evaluate_condition_code(const Vm1Context& context, std::uint8_t cc) {
  switch (cc) {
    case 0: return context.flags.zero;
    case 1: return !context.flags.zero;
    case 2: return context.flags.neg && !context.flags.zero;
    case 3: return context.flags.neg || context.flags.zero;
    case 4: return !context.flags.neg && !context.flags.zero;
    case 5: return !context.flags.neg || context.flags.zero;
    default: return false;
  }
}

void execute_call(Vm1Context& context, std::uint32_t target_pc, std::uint8_t arg_count, std::uint32_t return_pc) {
  const std::size_t spill_count = arg_count > 8 ? static_cast<std::size_t>(arg_count - 8) : 0u;
  const std::uint64_t new_sp = context.stack_top_;
  const std::uint64_t new_top = new_sp + static_cast<std::uint64_t>(spill_count * sizeof(std::uint64_t));
  if (new_top > context.stack_size()) {
    raise_trap(context, VmTrapCode::stack_overflow, "vm1: stack overflow during call", "vm1_stack_overflow");
  }
  for (std::size_t i = 0; i < spill_count; ++i) {
    context.write_memory<std::uint64_t>(new_sp + static_cast<std::uint64_t>(i * sizeof(std::uint64_t)),
                                        context.vr[8 + i]);
  }
  Vm1Context::CallFrame frame;
  frame.vr = context.vr;
  frame.vfr = context.vfr;
  frame.flags = context.flags;
  frame.return_pc = return_pc;
  frame.caller_sp = context.sp;
  frame.caller_stack_top = context.stack_top_;
  frame.arg_count = arg_count;
  context.frames_.push_back(frame);
  context.sp = new_sp;
  context.stack_top_ = new_top;
  context.pc = target_pc;
}

void execute_return(Vm1Context& context, bool explicit_domain_ret, bool& halted) {
  (void)explicit_domain_ret;
  const auto ret_int = context.vr[0];
  const auto ret_float = context.vfr[0];
  if (context.frames_.empty()) {
    context.clear_frame_transient_strings();
    halted = true;
    context.vr[0] = ret_int;
    context.vfr[0] = ret_float;
    return;
  }
  context.clear_frame_transient_strings();
  const auto frame = context.frames_.back();
  context.frames_.pop_back();
  context.vr = frame.vr;
  context.vfr = frame.vfr;
  context.flags = frame.flags;
  context.pc = frame.return_pc;
  context.sp = frame.caller_sp;
  context.stack_top_ = frame.caller_stack_top;
  context.vr[0] = ret_int;
  context.vfr[0] = ret_float;
  set_logic_flags(context, ret_int);
}

vmp::runtime::bridge::Domain bridge_domain_from_byte(std::uint8_t raw) {
  switch (raw) {
    case 0: return vmp::runtime::bridge::Domain::native;
    case 1: return vmp::runtime::bridge::Domain::vm1;
    case 2: return vmp::runtime::bridge::Domain::vm2;
    default: throw std::runtime_error("vm1: invalid domain byte");
  }
}

BlockExecutionResult execute_basic_block(Vm1Context& context, std::uint32_t start_pc) {
  if (context.module == nullptr) {
    throw VmException(VmTrapCode::invalid_module, 0, "vm1: null module");
  }
  (void)vmp::runtime::stack_probe::default_stack_probe().maybe_probe(
      vmp::runtime::stack_probe::ProbeRequest{
          vmp::runtime::stack_probe::selector_low12(reinterpret_cast<std::uintptr_t>(context.module) ^ context.module->id()),
          vmp::runtime::stack_probe::ProbeTriggerSite::vm1_handler_dispatch,
          vmp::runtime::stack_probe::kDefaultMaxFrames},
      context.audit_dispatcher);
  auto dispatch_scope = vmp::runtime::cryptor::vm1::begin_dispatch(*context.module);
  if (start_pc >= context.module->code.size()) {
    throw VmException(VmTrapCode::invalid_module, start_pc, "vm1: pc out of range");
  }
  context.execution_halted = false;
  context.pc = start_pc;
  bool halted = false;
  bool control_flow_changed = false;
  do {
    control_flow_changed = false;
    const std::uint32_t instruction_pc = context.pc;
    std::size_t cursor = context.pc;
    const auto opcode = static_cast<Opcode>(read_u16(*context.module, cursor));
    context.pc = static_cast<std::uint32_t>(cursor);
    switch (opcode) {
      case Opcode::nop:
        break;
      case Opcode::breakpoint:
        dispatch_audit(context, "vm1_breakpoint", "breakpoint opcode executed");
        break;
      case Opcode::trap: {
        const auto code = read_u32(*context.module, cursor);
        context.pc = static_cast<std::uint32_t>(cursor);
        std::ostringstream oss;
        oss << "vm1: trap opcode status=" << code;
        raise_trap(context, VmTrapCode::trap_instruction, oss.str(), "vm1_trap");
      }
      case Opcode::ldi64: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto imm = read_u64(*context.module, cursor);
        context.vr.at(dst) = imm;
        set_logic_flags(context, imm);
        break;
      }
      case Opcode::ldi_u64: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto imm = read_u64(*context.module, cursor);
        context.vr.at(dst) = imm;
        set_logic_flags(context, imm);
        break;
      }
      case Opcode::ldi_f64: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto imm = bit_cast_double(read_u64(*context.module, cursor));
        if (dst >= kVm1FloatRegisterCount) {
          raise_trap(context, VmTrapCode::invalid_register, "vm1: float register out of range");
        }
        context.vfr[dst] = imm;
        set_float_flags(context, imm);
        break;
      }
      case Opcode::mov: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto src = fetch_byte(*context.module, cursor++);
        context.vr.at(dst) = context.vr.at(src);
        set_logic_flags(context, context.vr.at(dst));
        break;
      }
      case Opcode::add:
      case Opcode::sub:
      case Opcode::mul:
      case Opcode::div:
      case Opcode::mod:
      case Opcode::bit_and:
      case Opcode::bit_or:
      case Opcode::bit_xor:
      case Opcode::shl:
      case Opcode::shr:
      case Opcode::sar: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto lhs_reg = fetch_byte(*context.module, cursor++);
        const auto rhs_reg = fetch_byte(*context.module, cursor++);
        const auto lhs = context.vr.at(lhs_reg);
        const auto rhs = context.vr.at(rhs_reg);
        std::uint64_t result = 0;
        switch (opcode) {
          case Opcode::add: {
            result = lhs + rhs;
            set_common_flags(context, result);
            context.flags.carry = flags_carry_add(lhs, rhs);
            context.flags.overflow = flags_overflow_add(static_cast<std::int64_t>(lhs), static_cast<std::int64_t>(rhs),
                                                        static_cast<std::int64_t>(result));
            break;
          }
          case Opcode::sub: {
            result = lhs - rhs;
            set_common_flags(context, result);
            context.flags.carry = lhs < rhs;
            context.flags.overflow = flags_overflow_sub(static_cast<std::int64_t>(lhs), static_cast<std::int64_t>(rhs),
                                                        static_cast<std::int64_t>(result));
            break;
          }
          case Opcode::mul:
            result = lhs * rhs;
            set_common_flags(context, result);
            context.flags.carry = false;
            context.flags.overflow = false;
            break;
          case Opcode::div:
            if (rhs == 0) {
              raise_trap(context, VmTrapCode::divide_by_zero, "vm1: divide by zero");
            }
            result = static_cast<std::uint64_t>(static_cast<std::int64_t>(lhs) / static_cast<std::int64_t>(rhs));
            set_logic_flags(context, result);
            break;
          case Opcode::mod:
            if (rhs == 0) {
              raise_trap(context, VmTrapCode::divide_by_zero, "vm1: modulo by zero");
            }
            result = static_cast<std::uint64_t>(static_cast<std::int64_t>(lhs) % static_cast<std::int64_t>(rhs));
            set_logic_flags(context, result);
            break;
          case Opcode::bit_and:
            result = lhs & rhs;
            set_logic_flags(context, result);
            break;
          case Opcode::bit_or:
            result = lhs | rhs;
            set_logic_flags(context, result);
            break;
          case Opcode::bit_xor:
            result = lhs ^ rhs;
            set_logic_flags(context, result);
            break;
          case Opcode::shl:
            result = lhs << (rhs & 63u);
            set_logic_flags(context, result);
            break;
          case Opcode::shr:
            result = lhs >> (rhs & 63u);
            set_logic_flags(context, result);
            break;
          case Opcode::sar:
            result = static_cast<std::uint64_t>(static_cast<std::int64_t>(lhs) >> (rhs & 63u));
            set_logic_flags(context, result);
            break;
          default:
            break;
        }
        context.vr.at(dst) = result;
        break;
      }
      case Opcode::neg:
      case Opcode::bit_not:
      case Opcode::popcnt:
      case Opcode::clz:
      case Opcode::ctz:
      case Opcode::bswap: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto src = fetch_byte(*context.module, cursor++);
        std::uint64_t result = 0;
        if (opcode == Opcode::neg) {
          result = static_cast<std::uint64_t>(-static_cast<std::int64_t>(context.vr.at(src)));
        } else if (opcode == Opcode::bit_not) {
          result = ~context.vr.at(src);
        } else if (opcode == Opcode::popcnt) {
          result = static_cast<std::uint64_t>(__builtin_popcountll(context.vr.at(src)));
        } else if (opcode == Opcode::clz) {
          result = context.vr.at(src) == 0 ? 64u : static_cast<std::uint64_t>(__builtin_clzll(context.vr.at(src)));
        } else if (opcode == Opcode::ctz) {
          result = context.vr.at(src) == 0 ? 64u : static_cast<std::uint64_t>(__builtin_ctzll(context.vr.at(src)));
        } else if (opcode == Opcode::bswap) {
          result = __builtin_bswap64(context.vr.at(src));
        }
        context.vr.at(dst) = result;
        set_logic_flags(context, result);
        break;
      }
      case Opcode::cmp:
      case Opcode::test: {
        const auto lhs_reg = fetch_byte(*context.module, cursor++);
        const auto rhs_reg = fetch_byte(*context.module, cursor++);
        const auto lhs = context.vr.at(lhs_reg);
        const auto rhs = context.vr.at(rhs_reg);
        if (opcode == Opcode::cmp) {
          compare_and_set_flags(context, lhs, rhs);
        } else {
          set_logic_flags(context, lhs & rhs);
        }
        break;
      }
      case Opcode::setcc: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto cc = fetch_byte(*context.module, cursor++);
        context.vr.at(dst) = evaluate_condition_code(context, cc) ? 1u : 0u;
        set_logic_flags(context, context.vr.at(dst));
        break;
      }
      case Opcode::load_mem8:
      case Opcode::load_mem16:
      case Opcode::load_mem32:
      case Opcode::load_mem64:
      case Opcode::load_sext8:
      case Opcode::load_sext16:
      case Opcode::load_sext32:
      case Opcode::lea: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto base = fetch_byte(*context.module, cursor++);
        const auto offset = read_i32(*context.module, cursor);
        const auto address = resolve_address(context, base, offset);
        switch (opcode) {
          case Opcode::load_mem8: context.vr.at(dst) = context.read_memory<std::uint8_t>(address); break;
          case Opcode::load_mem16: context.vr.at(dst) = context.read_memory<std::uint16_t>(address); break;
          case Opcode::load_mem32: context.vr.at(dst) = context.read_memory<std::uint32_t>(address); break;
          case Opcode::load_mem64: context.vr.at(dst) = context.read_memory<std::uint64_t>(address); break;
          case Opcode::load_sext8: context.vr.at(dst) = static_cast<std::uint64_t>(static_cast<std::int64_t>(context.read_memory<std::int8_t>(address))); break;
          case Opcode::load_sext16: context.vr.at(dst) = static_cast<std::uint64_t>(static_cast<std::int64_t>(context.read_memory<std::int16_t>(address))); break;
          case Opcode::load_sext32: context.vr.at(dst) = static_cast<std::uint64_t>(static_cast<std::int64_t>(context.read_memory<std::int32_t>(address))); break;
          case Opcode::lea: context.vr.at(dst) = address; break;
          default: break;
        }
        set_logic_flags(context, context.vr.at(dst));
        break;
      }
      case Opcode::store_mem8:
      case Opcode::store_mem16:
      case Opcode::store_mem32:
      case Opcode::store_mem64: {
        const auto base = fetch_byte(*context.module, cursor++);
        const auto src = fetch_byte(*context.module, cursor++);
        const auto offset = read_i32(*context.module, cursor);
        const auto address = resolve_address(context, base, offset);
        switch (opcode) {
          case Opcode::store_mem8: context.write_memory<std::uint8_t>(address, static_cast<std::uint8_t>(context.vr.at(src))); break;
          case Opcode::store_mem16: context.write_memory<std::uint16_t>(address, static_cast<std::uint16_t>(context.vr.at(src))); break;
          case Opcode::store_mem32: context.write_memory<std::uint32_t>(address, static_cast<std::uint32_t>(context.vr.at(src))); break;
          case Opcode::store_mem64: context.write_memory<std::uint64_t>(address, context.vr.at(src)); break;
          default: break;
        }
        break;
      }
      case Opcode::fadd:
      case Opcode::fsub:
      case Opcode::fmul:
      case Opcode::fdiv: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto lhs = fetch_byte(*context.module, cursor++);
        const auto rhs = fetch_byte(*context.module, cursor++);
        double result = 0.0;
        if (opcode == Opcode::fadd) result = context.vfr.at(lhs) + context.vfr.at(rhs);
        else if (opcode == Opcode::fsub) result = context.vfr.at(lhs) - context.vfr.at(rhs);
        else if (opcode == Opcode::fmul) result = context.vfr.at(lhs) * context.vfr.at(rhs);
        else {
          if (context.vfr.at(rhs) == 0.0) raise_trap(context, VmTrapCode::divide_by_zero, "vm1: float divide by zero");
          result = context.vfr.at(lhs) / context.vfr.at(rhs);
        }
        context.vfr.at(dst) = result;
        set_float_flags(context, result);
        break;
      }
      case Opcode::fsqrt: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto src = fetch_byte(*context.module, cursor++);
        context.vfr.at(dst) = std::sqrt(context.vfr.at(src));
        set_float_flags(context, context.vfr.at(dst));
        break;
      }
      case Opcode::i64_to_f64: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto src = fetch_byte(*context.module, cursor++);
        context.vfr.at(dst) = static_cast<double>(static_cast<std::int64_t>(context.vr.at(src)));
        set_float_flags(context, context.vfr.at(dst));
        break;
      }
      case Opcode::f64_to_i64: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto src = fetch_byte(*context.module, cursor++);
        context.vr.at(dst) = static_cast<std::uint64_t>(static_cast<std::int64_t>(context.vfr.at(src)));
        set_logic_flags(context, context.vr.at(dst));
        break;
      }
      case Opcode::fcmp: {
        const auto lhs = fetch_byte(*context.module, cursor++);
        const auto rhs = fetch_byte(*context.module, cursor++);
        const auto diff = context.vfr.at(lhs) - context.vfr.at(rhs);
        set_float_flags(context, diff);
        break;
      }
      case Opcode::vadd128:
      case Opcode::vxor128:
      case Opcode::vshuffle128: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto lhs = fetch_byte(*context.module, cursor++);
        const auto rhs = fetch_byte(*context.module, cursor++);
        auto left = read_vec_pair(context, lhs);
        auto right = read_vec_pair(context, rhs);
        VecPair out{};
        if (opcode == Opcode::vadd128) {
          out.lo = left.lo + right.lo;
          out.hi = left.hi + right.hi;
        } else if (opcode == Opcode::vxor128) {
          out.lo = left.lo ^ right.lo;
          out.hi = left.hi ^ right.hi;
        } else {
          out.lo = left.hi;
          out.hi = right.lo;
        }
        write_vec_pair(context, dst, out);
        break;
      }
      case Opcode::memcpy:
      case Opcode::memset:
      case Opcode::strcmp: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto lhs = fetch_byte(*context.module, cursor++);
        const auto rhs = fetch_byte(*context.module, cursor++);
        if (opcode == Opcode::memcpy) {
          const auto dest = context.vr.at(dst);
          const auto src = context.vr.at(lhs);
          const auto len = static_cast<std::size_t>(context.vr.at(rhs));
          for (std::size_t i = 0; i < len; ++i) context.write_memory<std::uint8_t>(dest + i, context.read_memory<std::uint8_t>(src + i));
          set_logic_flags(context, len);
        } else if (opcode == Opcode::memset) {
          const auto dest = context.vr.at(dst);
          const auto value = static_cast<std::uint8_t>(context.vr.at(lhs));
          const auto len = static_cast<std::size_t>(context.vr.at(rhs));
          for (std::size_t i = 0; i < len; ++i) context.write_memory<std::uint8_t>(dest + i, value);
          set_logic_flags(context, len);
        } else {
          const auto a = context.vr.at(dst);
          const auto b = context.vr.at(lhs);
          std::int64_t cmp_result = 0;
          std::size_t i = 0;
          for (;; ++i) {
            const auto av = context.read_memory<std::uint8_t>(a + i);
            const auto bv = context.read_memory<std::uint8_t>(b + i);
            if (av != bv || av == 0 || bv == 0) {
              cmp_result = static_cast<std::int64_t>(av) - static_cast<std::int64_t>(bv);
              break;
            }
          }
          context.vr.at(rhs) = static_cast<std::uint64_t>(cmp_result);
          set_logic_flags(context, context.vr.at(rhs));
        }
        break;
      }
      case Opcode::strlen: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto src = fetch_byte(*context.module, cursor++);
        std::size_t len = 0;
        while (context.read_memory<std::uint8_t>(context.vr.at(src) + len) != 0) ++len;
        context.vr.at(dst) = len;
        set_logic_flags(context, len);
        break;
      }
      case Opcode::cas_u64: {
        const auto base = fetch_byte(*context.module, cursor++);
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto offset = read_i32(*context.module, cursor);
        const auto expected = fetch_byte(*context.module, cursor++);
        const auto desired = fetch_byte(*context.module, cursor++);
        const auto address = resolve_address(context, base, offset);
        const auto old = context.read_memory<std::uint64_t>(address);
        if (old == context.vr.at(expected)) context.write_memory<std::uint64_t>(address, context.vr.at(desired));
        context.vr.at(dst) = old;
        compare_and_set_flags(context, old, context.vr.at(expected));
        break;
      }
      case Opcode::xchg_u64: {
        const auto base = fetch_byte(*context.module, cursor++);
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto offset = read_i32(*context.module, cursor);
        const auto src = fetch_byte(*context.module, cursor++);
        const auto address = resolve_address(context, base, offset);
        const auto old = context.read_memory<std::uint64_t>(address);
        context.write_memory<std::uint64_t>(address, context.vr.at(src));
        context.vr.at(dst) = old;
        set_logic_flags(context, old);
        break;
      }
      case Opcode::syscall_proxy: {
        const auto code = read_u32(*context.module, cursor);
        dispatch_audit(context, "vm1_syscall_proxy", "syscall_proxy=" + std::to_string(code));
        context.vr[0] = 0;
        set_logic_flags(context, 0);
        break;
      }
      case Opcode::bridge_args: {
        const auto ic = fetch_byte(*context.module, cursor++);
        const auto fc = fetch_byte(*context.module, cursor++);
        const auto oc = fetch_byte(*context.module, cursor++);
        context.vr[31] = (static_cast<std::uint64_t>(ic) << 16u) | (static_cast<std::uint64_t>(fc) << 8u) | oc;
        set_logic_flags(context, context.vr[31]);
        break;
      }
      case Opcode::jmp: {
        const auto target = read_u32(*context.module, cursor);
        context.pc = target;
        control_flow_changed = true;
        break;
      }
      case Opcode::jeq:
      case Opcode::jne:
      case Opcode::jlt:
      case Opcode::jle:
      case Opcode::jgt:
      case Opcode::jge: {
        const auto lhs_reg = fetch_byte(*context.module, cursor++);
        const auto rhs_reg = fetch_byte(*context.module, cursor++);
        const auto target = read_u32(*context.module, cursor);
        const auto lhs = context.vr.at(lhs_reg);
        const auto rhs = context.vr.at(rhs_reg);
        compare_and_set_flags(context, lhs, rhs);
        bool take = false;
        switch (opcode) {
          case Opcode::jeq: take = lhs == rhs; break;
          case Opcode::jne: take = lhs != rhs; break;
          case Opcode::jlt: take = static_cast<std::int64_t>(lhs) < static_cast<std::int64_t>(rhs); break;
          case Opcode::jle: take = static_cast<std::int64_t>(lhs) <= static_cast<std::int64_t>(rhs); break;
          case Opcode::jgt: take = static_cast<std::int64_t>(lhs) > static_cast<std::int64_t>(rhs); break;
          case Opcode::jge: take = static_cast<std::int64_t>(lhs) >= static_cast<std::int64_t>(rhs); break;
          default: break;
        }
        context.pc = take ? target : static_cast<std::uint32_t>(cursor);
        control_flow_changed = true;
        break;
      }
      case Opcode::call: {
        const auto target = read_u32(*context.module, cursor);
        const auto arg_count = fetch_byte(*context.module, cursor++);
        execute_call(context, target, arg_count, static_cast<std::uint32_t>(cursor));
        control_flow_changed = true;
        break;
      }
      case Opcode::call_indirect: {
        const auto target_reg = fetch_byte(*context.module, cursor++);
        const auto arg_count = fetch_byte(*context.module, cursor++);
        execute_call(context, static_cast<std::uint32_t>(context.vr.at(target_reg)), arg_count, static_cast<std::uint32_t>(cursor));
        control_flow_changed = true;
        break;
      }
      case Opcode::jmp_indirect: {
        const auto target_reg = fetch_byte(*context.module, cursor++);
        context.pc = static_cast<std::uint32_t>(context.vr.at(target_reg));
        control_flow_changed = true;
        break;
      }
      case Opcode::ret:
        execute_return(context, false, halted);
        control_flow_changed = true;
        break;
      case Opcode::domain_call: {
        const auto domain = fetch_byte(*context.module, cursor++);
        const auto id = read_u32(*context.module, cursor);
        const auto int_count = fetch_byte(*context.module, cursor++);
        const auto float_count = fetch_byte(*context.module, cursor++);
        const auto opaque_count = fetch_byte(*context.module, cursor++);
        context.pc = static_cast<std::uint32_t>(cursor);
        if (context.bridge_registry == nullptr) {
          raise_trap(context, VmTrapCode::bridge_error, "vm1: bridge registry not configured");
        }
        if (bridge_domain_from_byte(domain) == vmp::runtime::bridge::Domain::vm2) {
          vmp::runtime::cryptor::vm1::notify_domain_switch(*context.module);
        }
        vmp::runtime::bridge::DomainCallArgs args;
        args.ints.reserve(int_count);
        for (std::uint8_t i = 0; i < int_count; ++i) {
          if (i < 8) {
            args.ints.push_back(context.vr[i]);
          } else {
            args.ints.push_back(context.read_memory<std::uint64_t>(context.sp + static_cast<std::uint64_t>((i - 8) * 8)));
          }
        }
        args.floats.reserve(float_count);
        for (std::uint8_t i = 0; i < float_count; ++i) {
          args.floats.push_back(i < kVm1FloatRegisterCount ? context.vfr[i] : 0.0);
        }
        args.opaque.reserve(opaque_count);
        for (std::uint8_t i = 0; i < opaque_count; ++i) {
          args.opaque.push_back(reinterpret_cast<void*>(static_cast<std::uintptr_t>(context.vr[i])));
        }
        try {
          const auto result = context.bridge_registry->call(bridge_domain_from_byte(domain), id, args, context.max_bridge_depth);
          context.vr[0] = result.ret_int;
          context.vfr[0] = result.ret_float;
          context.vr[31] = static_cast<std::uint64_t>(static_cast<std::int64_t>(result.status));
          set_logic_flags(context, result.ret_int);
        } catch (const vmp::runtime::bridge::BridgeException& ex) {
          raise_trap(context, VmTrapCode::bridge_error, ex.what());
        }
        control_flow_changed = true;
        break;
      }
      case Opcode::domain_ret:
        execute_return(context, true, halted);
        control_flow_changed = true;
        break;
      case Opcode::load_transient_string: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto id = read_u32(*context.module, cursor);
        context.vr.at(dst) = context.materialize_transient_string(id);
        set_logic_flags(context, context.vr.at(dst));
        break;
      }
      case Opcode::release_transient_string: {
        const auto src = fetch_byte(*context.module, cursor++);
        context.release_transient_string(context.vr.at(src));
        context.vr.at(src) = 0;
        set_logic_flags(context, 0);
        break;
      }
      case Opcode::transient_read8: {
        const auto dst = fetch_byte(*context.module, cursor++);
        const auto handle = fetch_byte(*context.module, cursor++);
        const auto index = fetch_byte(*context.module, cursor++);
        const auto value = context.transient_string(context.vr.at(handle));
        const auto idx = static_cast<std::size_t>(context.vr.at(index));
        context.vr.at(dst) = idx < value.size() ? static_cast<std::uint8_t>(value[idx]) : 0u;
        set_logic_flags(context, context.vr.at(dst));
        break;
      }
      case Opcode::transient_wipe: {
        const auto src = fetch_byte(*context.module, cursor++);
        if (context.vr.at(src) != 0) {
          context.release_transient_string(context.vr.at(src));
        }
        context.vr.at(src) = 0;
        set_logic_flags(context, 0);
        break;
      }
      default:
        context.pc = instruction_pc;
        raise_trap(context, VmTrapCode::unknown_opcode, "vm1: unknown opcode", "vm1_unknown_opcode");
    }
    if (!halted && !control_flow_changed) {
      context.pc = static_cast<std::uint32_t>(cursor);
    }
  } while (!halted && !control_flow_changed);

  context.execution_halted = halted;
  return BlockExecutionResult{context.pc, halted};
}

}  // namespace

ExecutionResult Vm1Interpreter::execute(Vm1Context& context) {
  if (context.module == nullptr) {
    throw VmException(VmTrapCode::invalid_module, 0, "vm1: null module");
  }
  if (context.pc > context.module->code.size()) {
    throw VmException(VmTrapCode::invalid_module, context.pc, "vm1: entry pc out of range");
  }
  (void)vmp::runtime::env_integrity::verify_sensitive_domain_entry("vm1", context.audit_dispatcher);
  try {
    while (!context.execution_halted) {
      const auto block_pc = context.pc;
      std::vector<std::uint32_t> observed_trace;
      observed_trace.push_back(block_pc);
#if VMP_WITH_JIT
      const auto hit_count = context.module->note_block_hit(block_pc);
      if (auto* entry = vmp::runtime::jit::Vm1Jit::instance().compile_if_needed(*context.module, block_pc, hit_count); entry != nullptr) {
        vmp::runtime::jit::Vm1Jit::instance().record_entry_trampoline_hit(*context.module, block_pc);
        const auto next_pc = entry(&context);
        context.pc = next_pc;
        if (!context.execution_halted) {
          observed_trace.push_back(next_pc);
        }
        vmp::runtime::jit::Vm1Jit::instance().record_trace_observation(*context.module, observed_trace);
        continue;
      }
#endif
      auto result = execute_basic_block(context, block_pc);
      context.pc = result.next_pc;
      if (!result.halted) {
        observed_trace.push_back(result.next_pc);
      }
#if VMP_WITH_JIT
      vmp::runtime::jit::Vm1Jit::instance().record_trace_observation(*context.module, observed_trace);
#endif
    }
    return ExecutionResult{context.vr[0], context.vfr[0]};
  } catch (...) {
    context.clear_all_transient_strings();
    throw;
  }
}

extern "C" std::uint32_t vmp_vm1_jit_execute_block(Vm1Context* context, std::uint32_t start_pc) {
  const auto result = execute_basic_block(*context, start_pc);
  context->pc = result.next_pc;
  context->execution_halted = result.halted;
  return result.next_pc;
}

extern "C" std::uint32_t vmp_vm1_jit_execute_trace(Vm1Context* context, const std::uint32_t* block_pcs,
                                                     std::size_t block_count) {
  if (context == nullptr || block_pcs == nullptr || block_count == 0) {
    return 0;
  }
  std::uint32_t next_pc = context->pc;
  for (std::size_t i = 0; i < block_count; ++i) {
    const auto result = execute_basic_block(*context, block_pcs[i]);
    next_pc = result.next_pc;
    context->pc = next_pc;
    context->execution_halted = result.halted;
    if (result.halted) {
      return next_pc;
    }
    if (i + 1 < block_count && next_pc != block_pcs[i + 1]) {
      return next_pc;
    }
  }
  return next_pc;
}

}  // namespace vmp::runtime::vm1
