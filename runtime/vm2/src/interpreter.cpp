#include <vmp/runtime/vm2/vm2.h>

#include <array>
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>

#include <vmp/runtime/cryptor/rolling_opcode_vm2.h>
#include <vmp/runtime/env_integrity/monitor.h>
#include <vmp/runtime/obfuscation/bogus_flow.h>
#include <vmp/runtime/obfuscation/mba.h>
#include <vmp/runtime/obfuscation/opaque.h>
#include <vmp/runtime/stack_probe/probe.h>
#include <vmp/runtime/vm1/vm1.h>
#if VMP_WITH_JIT
#include <limits>
#include <vmp/runtime/jit/vm2_jit.h>
#endif

namespace vmp::runtime::vm2 {
namespace {

std::uint8_t fetch_byte(const Vm2Module& module, std::size_t forward_pc) {
  if (forward_pc >= module.code.size()) throw Vm2Exception(static_cast<std::uint32_t>(forward_pc), "vm2: pc out of range");
  if ((module.module_flags & VMP_FLAG_OPCODE_ENCRYPTED) != 0u) {
    return vmp::runtime::cryptor::vm2::fetch_byte(module, forward_pc);
  }
  if ((module.module_flags & VMP_FLAG_REVERSE_ORDER) == 0u) return module.code[forward_pc];
  if (module.reverse_code.empty() || module.forward_instruction_start_by_pc.size() != module.code.size() ||
      module.forward_instruction_length_by_pc.size() != module.code.size()) {
    throw Vm2Exception(static_cast<std::uint32_t>(forward_pc), "vm2: reverse layout cache missing");
  }
  const auto inst_start = module.forward_instruction_start_by_pc[forward_pc];
  const auto inst_length = module.forward_instruction_length_by_pc[forward_pc];
  if (inst_length == 0u) {
    throw Vm2Exception(static_cast<std::uint32_t>(forward_pc), "vm2: invalid reverse instruction metadata");
  }
  const auto reverse_pc = module.code.size() - static_cast<std::size_t>(inst_start) - inst_length +
                          (forward_pc - static_cast<std::size_t>(inst_start));
  return module.reverse_code.at(reverse_pc);
}

std::uint16_t read_u16(const Vm2Module& module, std::size_t& pc) {
  if (pc + 2 > module.code.size()) throw Vm2Exception(static_cast<std::uint32_t>(pc), "vm2: truncated u16 operand");
  const auto lo = fetch_byte(module, pc);
  const auto hi = fetch_byte(module, pc + 1u);
  pc += 2;
  return static_cast<std::uint16_t>(lo) | static_cast<std::uint16_t>(hi << 8u);
}

std::uint32_t read_u32(const Vm2Module& module, std::size_t& pc) {
  if (pc + 4 > module.code.size()) throw Vm2Exception(static_cast<std::uint32_t>(pc), "vm2: truncated u32 operand");
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) value |= static_cast<std::uint32_t>(fetch_byte(module, pc + static_cast<std::size_t>(i))) << (8 * i);
  pc += 4;
  return value;
}

std::uint64_t read_u64(const Vm2Module& module, std::size_t& pc) {
  if (pc + 8 > module.code.size()) throw Vm2Exception(static_cast<std::uint32_t>(pc), "vm2: truncated u64 operand");
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) value |= static_cast<std::uint64_t>(fetch_byte(module, pc + static_cast<std::size_t>(i))) << (8 * i);
  pc += 8;
  return value;
}

std::int32_t read_i32(const Vm2Module& module, std::size_t& pc) {
  return static_cast<std::int32_t>(read_u32(module, pc));
}

double bit_cast_double(std::uint64_t value) {
  double out = 0.0;
  std::memcpy(&out, &value, sizeof(out));
  return out;
}

std::uint64_t bit_cast_u64(double value) {
  std::uint64_t out = 0;
  std::memcpy(&out, &value, sizeof(out));
  return out;
}

void dispatch_audit(Vm2Context& context, const std::string& event_type, const std::string& note) {
  if (context.audit_dispatcher == nullptr) return;
  context.audit_dispatcher->dispatch(vmp::runtime::audit::make_event(event_type, note, context.pc, "vm2", "", 0),
                                     vmp::runtime::audit::ReactionPolicy::audit_only);
}

std::uint64_t resolve_address(const Vm2Context& context, std::uint8_t base, std::int32_t offset) {
  std::uint64_t base_value = 0;
  if (base == static_cast<std::uint8_t>(MemoryBase::sp)) {
    base_value = context.sp;
  } else if (base < kVm2GeneralRegisterCount) {
    base_value = context.r[base];
  } else {
    throw Vm2Exception(context.pc, "vm2: invalid memory base register");
  }
  if (offset >= 0) return base_value + static_cast<std::uint64_t>(offset);
  return base_value - static_cast<std::uint64_t>(-static_cast<std::int64_t>(offset));
}

void set_predicates_from_value(Vm2Context& context, std::uint64_t value, bool carry = false, bool overflow = false) {
  context.p[0] = (value == 0);
  context.p[1] = (static_cast<std::int64_t>(value) < 0);
  context.p[2] = carry;
  context.p[3] = overflow;
}

void set_predicates_from_vec(Vm2Context& context, const Vec128& value) {
  context.p[0] = value.u64.lo == 0 && value.u64.hi == 0;
  context.p[1] = (static_cast<std::int64_t>(value.u64.hi) < 0);
  context.p[2] = false;
  context.p[3] = false;
}

std::uint64_t count_leading_zeros(std::uint64_t value) {
  if (value == 0) return 64;
#if defined(__GNUC__) || defined(__clang__)
  return static_cast<std::uint64_t>(__builtin_clzll(value));
#else
  std::uint64_t count = 0;
  for (std::uint64_t mask = 1ull << 63; (value & mask) == 0; mask >>= 1) ++count;
  return count;
#endif
}

std::uint64_t count_trailing_zeros(std::uint64_t value) {
  if (value == 0) return 64;
#if defined(__GNUC__) || defined(__clang__)
  return static_cast<std::uint64_t>(__builtin_ctzll(value));
#else
  std::uint64_t count = 0;
  while ((value & 1u) == 0u) {
    value >>= 1u;
    ++count;
  }
  return count;
#endif
}

std::uint64_t count_population(std::uint64_t value) {
#if defined(__GNUC__) || defined(__clang__)
  return static_cast<std::uint64_t>(__builtin_popcountll(value));
#else
  std::uint64_t out = 0;
  while (value != 0) {
    out += value & 1u;
    value >>= 1u;
  }
  return out;
#endif
}

bool overflow_add(std::int64_t lhs, std::int64_t rhs, std::int64_t result) {
  return ((lhs ^ result) & (rhs ^ result)) < 0;
}

bool overflow_sub(std::int64_t lhs, std::int64_t rhs, std::int64_t result) {
  return ((lhs ^ rhs) & (lhs ^ result)) < 0;
}

void enter_call(Vm2Context& context, std::uint32_t target_pc, std::uint8_t arg_count, std::uint32_t return_pc) {
  const std::size_t spill_count = arg_count > 8 ? static_cast<std::size_t>(arg_count - 8) : 0u;
  Vm2Context::CallFrame frame;
  frame.r = context.r;
  frame.q = context.q;
  frame.d = context.d;
  frame.p = context.p;
  frame.caller_lr = context.lr;
  frame.caller_sp = context.sp;
  context.frames_.push_back(frame);
  if (spill_count > 0) {
    const auto spill_base = context.allocate_spill(spill_count * sizeof(std::uint64_t), "call spill");
    for (std::size_t i = 0; i < spill_count; ++i) {
      std::uint64_t value = 0;
      const auto caller_addr = frame.caller_sp + static_cast<std::uint64_t>(i * sizeof(std::uint64_t));
      if (frame.caller_sp < context.stack_size() && caller_addr + sizeof(std::uint64_t) <= context.stack_size()) {
        value = context.read_memory<std::uint64_t>(caller_addr);
      } else if (8 + i < context.r.size()) {
        value = context.r[8 + i];
      }
      context.write_memory<std::uint64_t>(spill_base + static_cast<std::uint64_t>(i * sizeof(std::uint64_t)), value);
    }
  }
  context.lr = return_pc;
  context.pc = target_pc;
}

void leave_call(Vm2Context& context, bool& halted) {
  const auto ret_int = context.r[0];
  const auto ret_float = context.d[0];
  const auto ret_vec = context.q[0];
  if (context.frames_.empty()) {
    context.clear_frame_transient_strings();
    halted = true;
    context.r[0] = ret_int;
    context.d[0] = ret_float;
    context.q[0] = ret_vec;
    return;
  }
  context.clear_frame_transient_strings();
  const auto frame = context.frames_.back();
  context.frames_.pop_back();
  context.r = frame.r;
  context.q = frame.q;
  context.d = frame.d;
  context.p = frame.p;
  context.sp = frame.caller_sp;
  context.pc = context.lr;
  context.lr = frame.caller_lr;
  context.r[0] = ret_int;
  context.d[0] = ret_float;
  context.q[0] = ret_vec;
  set_predicates_from_value(context, ret_int);
}

vmp::runtime::bridge::Domain bridge_domain_from_byte(std::uint8_t raw) {
  switch (raw) {
    case 0: return vmp::runtime::bridge::Domain::native;
    case 1: return vmp::runtime::bridge::Domain::vm1;
    case 2: return vmp::runtime::bridge::Domain::vm2;
    default: throw Vm2Exception(0, "vm2: invalid bridge domain");
  }
}

}  // namespace

Vm2Interpreter::Vm2Interpreter() { assert(vmp::runtime::vm1::handler_table_identity() != handler_table_identity()); }


#if defined(_MSC_VER)
#define VMP_NOINLINE __declspec(noinline)
#else
#define VMP_NOINLINE __attribute__((noinline))
#endif

#ifndef VMP_POLYMORPHIC_HANDLER_SEED
#define VMP_POLYMORPHIC_HANDLER_SEED 0
#endif

#ifndef VMP_ENABLE_OPAQUE_HANDLER_PREDICATES
#define VMP_ENABLE_OPAQUE_HANDLER_PREDICATES 1
#endif

constexpr std::uint64_t kVm2PolymorphicBuildSeed =
    static_cast<std::uint64_t>(VMP_POLYMORPHIC_HANDLER_SEED) ^ 0x56324d3200000001ull;

constexpr std::uint64_t mix_u64(std::uint64_t value) {
  value += 0x9e3779b97f4a7c15ull;
  value = (value ^ (value >> 30u)) * 0xbf58476d1ce4e5b9ull;
  value = (value ^ (value >> 27u)) * 0x94d049bb133111ebull;
  return value ^ (value >> 31u);
}

constexpr std::uint8_t vm2_variant_for_opcode_word(std::uint16_t word) {
  return static_cast<std::uint8_t>(mix_u64(kVm2PolymorphicBuildSeed ^ static_cast<std::uint64_t>(word)) % 3ull);
}

constexpr std::uint8_t vm2_junk_length_for_opcode_word(std::uint16_t word) {
  return static_cast<std::uint8_t>(4u + (mix_u64(kVm2PolymorphicBuildSeed ^ (static_cast<std::uint64_t>(word) << 11u)) % 29ull));
}

constexpr std::uint64_t vm2_handler_fingerprint_value(std::uint16_t word,
                                                      std::size_t canonical_index,
                                                      std::size_t shuffled_index) {
  return mix_u64(kVm2PolymorphicBuildSeed ^ (static_cast<std::uint64_t>(word) << 32u) ^
                 (static_cast<std::uint64_t>(canonical_index) << 16u) ^ static_cast<std::uint64_t>(shuffled_index));
}

struct Vm2DispatchFrame {
  Vm2Context& context;
  std::uint32_t instruction_pc;
  std::size_t& cursor;
  bool& control_flow_changed;
  const std::optional<std::size_t>& stop_after_frame_depth;
  std::optional<ExecutionResult>& early_return;
};

using Vm2HandlerFn = void (*)(Vm2DispatchFrame&);

struct Vm2HandlerRuntimeEntry {
  PolymorphicHandlerInfo info{};
  Vm2HandlerFn fn = nullptr;
};

const void* vm2_handler_entry_identity(Vm2HandlerFn fn) noexcept {
  union {
    Vm2HandlerFn fn;
    const void* ptr;
  } caster{fn};
  return caster.ptr;
}

struct Vm2HandlerCatalog {
  PolymorphicHandlerLayout layout{};
  std::vector<Vm2HandlerRuntimeEntry> runtime_entries;
  std::vector<std::pair<std::uint16_t, std::size_t>> lookup_by_opcode;

  const Vm2HandlerRuntimeEntry* resolve(Opcode opcode) const {
    const auto word = static_cast<std::uint16_t>(opcode);
    const auto it = std::lower_bound(
        lookup_by_opcode.begin(), lookup_by_opcode.end(), word,
        [](const auto& lhs, std::uint16_t rhs) { return lhs.first < rhs; });
    if (it == lookup_by_opcode.end() || it->first != word) {
      return nullptr;
    }
    return &runtime_entries[it->second];
  }
};

void execute_vm2_opcode(Vm2DispatchFrame& frame, Opcode opcode);

template <Opcode Op, unsigned Variant>
VMP_NOINLINE void emit_vm2_polymorphic_junk() {
  constexpr auto opcode_word = static_cast<std::uint16_t>(Op);
  constexpr auto junk_length = vm2_junk_length_for_opcode_word(opcode_word);
  constexpr auto salt_a = mix_u64(kVm2PolymorphicBuildSeed ^ (static_cast<std::uint64_t>(opcode_word) << 9u) ^ Variant);
  constexpr auto salt_b = mix_u64(kVm2PolymorphicBuildSeed ^ (static_cast<std::uint64_t>(junk_length) << 17u) ^
                                  (static_cast<std::uint64_t>(Variant) << 33u));
  volatile std::uint64_t sink = salt_a ^ salt_b ^ junk_length;
  if constexpr (Variant == 0u) {
    sink += salt_a;
    sink ^= salt_b;
    sink -= salt_a;
  } else if constexpr (Variant == 1u) {
    sink ^= salt_a;
    sink += static_cast<std::uint64_t>(junk_length) * 0x101ull;
    sink ^= (salt_b >> 1u);
  } else {
    sink += (salt_a ^ salt_b);
    sink = (sink << 7u) | (sink >> 57u);
    sink ^= salt_b;
  }
#if VMP_ENABLE_OPAQUE_HANDLER_PREDICATES
  volatile std::uint64_t opaque_seed =
      vmp::runtime::obfuscation::opaque_handler_mix(sink ^ static_cast<std::uint64_t>(opcode_word),
                                                    salt_a ^ (static_cast<std::uint64_t>(Variant) << 32u));
  const auto opaque_true = vmp::runtime::obfuscation::opaque_even_product_predicate(opaque_seed);
  volatile std::uint64_t opaque_probe =
      vmp::runtime::obfuscation::mba_add_u64(
          vmp::runtime::obfuscation::mba_mul2_u64(opaque_seed),
          vmp::runtime::obfuscation::mba_sub_u64(salt_b, static_cast<std::uint64_t>(junk_length)));
  sink ^= (opaque_probe & 0ull);
  sink += ((opaque_probe >> 63u) & 0ull);
  VMP_APPLY_HANDLER_BOGUS_FLOW(
      Variant,
      sink,
      opaque_true,
      static_cast<std::uint64_t>(opaque_seed),
      salt_a,
      salt_b,
      (static_cast<std::uint64_t>(opcode_word) << 16u) ^ static_cast<std::uint64_t>(junk_length));
#endif
#if defined(__GNUC__) || defined(__clang__)
  asm volatile("" : : "r"(sink) : "memory");
#endif
  if ((sink & 0xffff000000000000ull) == 0xffff000000000000ull) {
    __builtin_trap();
  }
}

template <Opcode Op, unsigned Variant>
VMP_NOINLINE void vm2_handler_entry(Vm2DispatchFrame& frame) {
  emit_vm2_polymorphic_junk<Op, Variant>();
  execute_vm2_opcode(frame, Op);
}

template <Opcode Op>
constexpr std::uint8_t selected_vm2_variant() {
  return vm2_variant_for_opcode_word(static_cast<std::uint16_t>(Op));
}

template <Opcode Op>
Vm2HandlerFn select_vm2_handler() {
  if constexpr (selected_vm2_variant<Op>() == 0u) {
    return &vm2_handler_entry<Op, 0u>;
  } else if constexpr (selected_vm2_variant<Op>() == 1u) {
    return &vm2_handler_entry<Op, 1u>;
  }
  return &vm2_handler_entry<Op, 2u>;
}

Vm2HandlerFn vm2_handler_for_opcode(Opcode opcode) {
  switch (opcode) {
#define VMP_VM2_OPCODE(name) case Opcode::name: return select_vm2_handler<Opcode::name>();
#include "polymorphic_opcode_list.inc"
#undef VMP_VM2_OPCODE
    default: return nullptr;
  }
}

Vm2HandlerCatalog build_vm2_handler_catalog() {
  struct PendingEntry {
    std::uint64_t shuffle_key = 0;
    Vm2HandlerRuntimeEntry entry{};
  };

  Vm2HandlerCatalog catalog;
  catalog.layout.build_seed = kVm2PolymorphicBuildSeed;
  const auto& canonical = canonical_opcode_sequence();
  std::vector<PendingEntry> pending;
  pending.reserve(canonical.size());
  for (std::size_t i = 0; i < canonical.size(); ++i) {
    const auto opcode = canonical[i];
    const auto fn = vm2_handler_for_opcode(opcode);
    PolymorphicHandlerInfo info;
    info.opcode = opcode;
    info.canonical_index = static_cast<std::uint16_t>(i);
    info.variant = vm2_variant_for_opcode_word(static_cast<std::uint16_t>(opcode));
    info.junk_length = vm2_junk_length_for_opcode_word(static_cast<std::uint16_t>(opcode));
    info.entry = vm2_handler_entry_identity(fn);
    pending.push_back(PendingEntry{
        mix_u64(kVm2PolymorphicBuildSeed ^ (static_cast<std::uint64_t>(static_cast<std::uint16_t>(opcode)) << 24u) ^ i),
        Vm2HandlerRuntimeEntry{info, fn}});
  }
  std::sort(pending.begin(), pending.end(), [](const PendingEntry& lhs, const PendingEntry& rhs) {
    if (lhs.shuffle_key != rhs.shuffle_key) {
      return lhs.shuffle_key < rhs.shuffle_key;
    }
    return static_cast<std::uint16_t>(lhs.entry.info.opcode) < static_cast<std::uint16_t>(rhs.entry.info.opcode);
  });

  catalog.runtime_entries.reserve(pending.size());
  catalog.layout.entries.reserve(pending.size());
  for (std::size_t shuffled_index = 0; shuffled_index < pending.size(); ++shuffled_index) {
    auto entry = pending[shuffled_index].entry;
    entry.info.shuffled_index = static_cast<std::uint16_t>(shuffled_index);
    entry.info.fingerprint = vm2_handler_fingerprint_value(static_cast<std::uint16_t>(entry.info.opcode),
                                                           entry.info.canonical_index,
                                                           entry.info.shuffled_index);
    catalog.lookup_by_opcode.emplace_back(static_cast<std::uint16_t>(entry.info.opcode), shuffled_index);
    catalog.layout.layout_fingerprint =
        mix_u64(catalog.layout.layout_fingerprint ^ entry.info.fingerprint ^
                (static_cast<std::uint64_t>(entry.info.variant) << 8u) ^ entry.info.junk_length);
    catalog.runtime_entries.push_back(entry);
    catalog.layout.entries.push_back(entry.info);
  }
  std::sort(catalog.lookup_by_opcode.begin(), catalog.lookup_by_opcode.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; });
  return catalog;
}

const Vm2HandlerCatalog& vm2_handler_catalog() {
  static const Vm2HandlerCatalog catalog = build_vm2_handler_catalog();
  return catalog;
}

void execute_vm2_opcode(Vm2DispatchFrame& frame, Opcode opcode) {
  auto& context = frame.context;
  auto& cursor = frame.cursor;
  auto& control_flow_changed = frame.control_flow_changed;
  auto& stop_after_frame_depth = frame.stop_after_frame_depth;
  auto& early_return = frame.early_return;
  switch (opcode) {
        case Opcode::nop:
          break;
        case Opcode::brk:
          dispatch_audit(context, "vm2_breakpoint", "brk opcode executed");
          break;
        case Opcode::ftrap: {
          const auto code = read_u32(*context.module, cursor);
          context.pc = frame.instruction_pc;
          dispatch_audit(context, "vm2_trap", "ftrap opcode executed");
          throw Vm2Exception(frame.instruction_pc, "vm2 trap code=" + std::to_string(code));
        }
        case Opcode::ildimm: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto imm = read_u64(*context.module, cursor);
          context.r.at(dst) = imm;
          set_predicates_from_value(context, imm);
          break;
        }
        case Opcode::dldimm: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto imm = bit_cast_double(read_u64(*context.module, cursor));
          context.d.at(dst) = imm;
          context.p[0] = (imm == 0.0);
          context.p[1] = std::signbit(imm);
          context.p[2] = false;
          context.p[3] = false;
          break;
        }
        case Opcode::vldimm: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto index = read_u32(*context.module, cursor);
          if (index >= context.module->const_pool.size()) throw Vm2Exception(frame.instruction_pc, "vm2: const pool index out of range");
          Vec128 value{};
          for (int i = 0; i < 8; ++i) value.u64.lo |= static_cast<std::uint64_t>(context.module->const_pool[index].bytes[static_cast<std::size_t>(i)]) << (8 * i);
          for (int i = 0; i < 8; ++i) value.u64.hi |= static_cast<std::uint64_t>(context.module->const_pool[index].bytes[8 + static_cast<std::size_t>(i)]) << (8 * i);
          context.q.at(dst) = value;
          set_predicates_from_vec(context, value);
          break;
        }
        case Opcode::imov: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto src = fetch_byte(*context.module, cursor++);
          context.r.at(dst) = context.r.at(src);
          set_predicates_from_value(context, context.r.at(dst));
          break;
        }
        case Opcode::dmov: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto src = fetch_byte(*context.module, cursor++);
          context.d.at(dst) = context.d.at(src);
          context.p[0] = (context.d.at(dst) == 0.0);
          context.p[1] = std::signbit(context.d.at(dst));
          context.p[2] = false;
          context.p[3] = false;
          break;
        }
        case Opcode::iadd:
        case Opcode::isub:
        case Opcode::imul:
        case Opcode::idiv:
        case Opcode::imod:
        case Opcode::iand:
        case Opcode::ior:
        case Opcode::ixor:
        case Opcode::ishl:
        case Opcode::ishr:
        case Opcode::isar: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto lhs_reg = fetch_byte(*context.module, cursor++);
          const auto rhs_reg = fetch_byte(*context.module, cursor++);
          const auto lhs = context.r.at(lhs_reg);
          const auto rhs = context.r.at(rhs_reg);
          std::uint64_t result = 0;
          bool carry = false;
          bool overflow = false;
          switch (opcode) {
            case Opcode::iadd:
              result = lhs + rhs;
              carry = lhs > std::numeric_limits<std::uint64_t>::max() - rhs;
              overflow = overflow_add(static_cast<std::int64_t>(lhs), static_cast<std::int64_t>(rhs), static_cast<std::int64_t>(result));
              break;
            case Opcode::isub:
              result = lhs - rhs;
              carry = lhs < rhs;
              overflow = overflow_sub(static_cast<std::int64_t>(lhs), static_cast<std::int64_t>(rhs), static_cast<std::int64_t>(result));
              break;
            case Opcode::imul:
              result = lhs * rhs;
              break;
            case Opcode::idiv:
              if (rhs == 0) throw Vm2DivByZero(frame.instruction_pc, "vm2: divide by zero");
              result = static_cast<std::uint64_t>(static_cast<std::int64_t>(lhs) / static_cast<std::int64_t>(rhs));
              break;
            case Opcode::imod:
              if (rhs == 0) throw Vm2DivByZero(frame.instruction_pc, "vm2: modulo by zero");
              result = static_cast<std::uint64_t>(static_cast<std::int64_t>(lhs) % static_cast<std::int64_t>(rhs));
              break;
            case Opcode::iand: result = lhs & rhs; break;
            case Opcode::ior: result = lhs | rhs; break;
            case Opcode::ixor: result = lhs ^ rhs; break;
            case Opcode::ishl: result = lhs << (rhs & 63u); break;
            case Opcode::ishr: result = lhs >> (rhs & 63u); break;
            case Opcode::isar: result = static_cast<std::uint64_t>(static_cast<std::int64_t>(lhs) >> (rhs & 63u)); break;
            default: break;
          }
          context.r.at(dst) = result;
          set_predicates_from_value(context, result, carry, overflow);
          break;
        }
        case Opcode::ineg:
        case Opcode::inot:
        case Opcode::ipopcnt:
        case Opcode::iclz:
        case Opcode::ictz:
        case Opcode::ibswap: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto src = fetch_byte(*context.module, cursor++);
          const auto value = context.r.at(src);
          std::uint64_t result = 0;
          switch (opcode) {
            case Opcode::ineg: result = static_cast<std::uint64_t>(-static_cast<std::int64_t>(value)); break;
            case Opcode::inot: result = ~value; break;
            case Opcode::ipopcnt: result = count_population(value); break;
            case Opcode::iclz: result = count_leading_zeros(value); break;
            case Opcode::ictz: result = count_trailing_zeros(value); break;
            case Opcode::ibswap: result = __builtin_bswap64(value); break;
            default: break;
          }
          context.r.at(dst) = result;
          set_predicates_from_value(context, result);
          break;
        }
        case Opcode::icmp:
        case Opcode::itest: {
          const auto lhs = context.r.at(fetch_byte(*context.module, cursor++));
          const auto rhs = context.r.at(fetch_byte(*context.module, cursor++));
          if (opcode == Opcode::icmp) {
            const auto diff = lhs - rhs;
            set_predicates_from_value(context, diff, lhs < rhs,
                                      overflow_sub(static_cast<std::int64_t>(lhs), static_cast<std::int64_t>(rhs), static_cast<std::int64_t>(diff)));
          } else {
            set_predicates_from_value(context, lhs & rhs);
          }
          break;
        }
        case Opcode::isetcc: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto pred = fetch_byte(*context.module, cursor++);
          context.r.at(dst) = context.p.at(pred) ? 1u : 0u;
          set_predicates_from_value(context, context.r.at(dst));
          break;
        }
        case Opcode::dadd:
        case Opcode::dsub:
        case Opcode::dmul:
        case Opcode::ddiv: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto lhs = context.d.at(fetch_byte(*context.module, cursor++));
          const auto rhs = context.d.at(fetch_byte(*context.module, cursor++));
          double value = 0.0;
          switch (opcode) {
            case Opcode::dadd: value = lhs + rhs; break;
            case Opcode::dsub: value = lhs - rhs; break;
            case Opcode::dmul: value = lhs * rhs; break;
            case Opcode::ddiv: value = lhs / rhs; break;
            default: break;
          }
          context.d.at(dst) = value;
          context.p[0] = (value == 0.0);
          context.p[1] = std::signbit(value);
          context.p[2] = false;
          context.p[3] = false;
          break;
        }
        case Opcode::dsqrt: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto src = fetch_byte(*context.module, cursor++);
          context.d.at(dst) = std::sqrt(context.d.at(src));
          context.p[0] = (context.d.at(dst) == 0.0);
          context.p[1] = std::signbit(context.d.at(dst));
          context.p[2] = false;
          context.p[3] = false;
          break;
        }
        case Opcode::i64tof: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto src = fetch_byte(*context.module, cursor++);
          context.d.at(dst) = static_cast<double>(static_cast<std::int64_t>(context.r.at(src)));
          context.p[0] = (context.d.at(dst) == 0.0);
          context.p[1] = std::signbit(context.d.at(dst));
          context.p[2] = false;
          context.p[3] = false;
          break;
        }
        case Opcode::f64toi: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto src = fetch_byte(*context.module, cursor++);
          context.r.at(dst) = static_cast<std::uint64_t>(static_cast<std::int64_t>(context.d.at(src)));
          set_predicates_from_value(context, context.r.at(dst));
          break;
        }
        case Opcode::dcmp: {
          const auto lhs = context.d.at(fetch_byte(*context.module, cursor++));
          const auto rhs = context.d.at(fetch_byte(*context.module, cursor++));
          const auto diff = lhs - rhs;
          context.p[0] = (lhs == rhs);
          context.p[1] = diff < 0.0;
          context.p[2] = false;
          context.p[3] = false;
          break;
        }
        case Opcode::vadd128:
        case Opcode::vsub128:
        case Opcode::vmul128:
        case Opcode::vxor128: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto lhs = context.q.at(fetch_byte(*context.module, cursor++));
          const auto rhs = context.q.at(fetch_byte(*context.module, cursor++));
          Vec128 out{};
          for (int i = 0; i < 2; ++i) {
            switch (opcode) {
              case Opcode::vadd128: out.lanes[static_cast<std::size_t>(i)] = lhs.lanes[static_cast<std::size_t>(i)] + rhs.lanes[static_cast<std::size_t>(i)]; break;
              case Opcode::vsub128: out.lanes[static_cast<std::size_t>(i)] = lhs.lanes[static_cast<std::size_t>(i)] - rhs.lanes[static_cast<std::size_t>(i)]; break;
              case Opcode::vmul128: out.lanes[static_cast<std::size_t>(i)] = lhs.lanes[static_cast<std::size_t>(i)] * rhs.lanes[static_cast<std::size_t>(i)]; break;
              case Opcode::vxor128: out.lanes[static_cast<std::size_t>(i)] = lhs.lanes[static_cast<std::size_t>(i)] ^ rhs.lanes[static_cast<std::size_t>(i)]; break;
              default: break;
            }
          }
          context.q.at(dst) = out;
          set_predicates_from_vec(context, out);
          break;
        }
        case Opcode::imemld8:
        case Opcode::imemld16:
        case Opcode::imemld32:
        case Opcode::imemld64: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto base = fetch_byte(*context.module, cursor++);
          const auto offset = read_i32(*context.module, cursor);
          const auto address = resolve_address(context, base, offset);
          switch (opcode) {
            case Opcode::imemld8: context.r.at(dst) = context.read_memory<std::uint8_t>(address); break;
            case Opcode::imemld16: context.r.at(dst) = context.read_memory<std::uint16_t>(address); break;
            case Opcode::imemld32: context.r.at(dst) = context.read_memory<std::uint32_t>(address); break;
            case Opcode::imemld64: context.r.at(dst) = context.read_memory<std::uint64_t>(address); break;
            default: break;
          }
          set_predicates_from_value(context, context.r.at(dst));
          break;
        }
        case Opcode::imemst8:
        case Opcode::imemst16:
        case Opcode::imemst32:
        case Opcode::imemst64: {
          const auto base = fetch_byte(*context.module, cursor++);
          const auto src = fetch_byte(*context.module, cursor++);
          const auto offset = read_i32(*context.module, cursor);
          const auto address = resolve_address(context, base, offset);
          switch (opcode) {
            case Opcode::imemst8: context.write_memory<std::uint8_t>(address, static_cast<std::uint8_t>(context.r.at(src))); break;
            case Opcode::imemst16: context.write_memory<std::uint16_t>(address, static_cast<std::uint16_t>(context.r.at(src))); break;
            case Opcode::imemst32: context.write_memory<std::uint32_t>(address, static_cast<std::uint32_t>(context.r.at(src))); break;
            case Opcode::imemst64: context.write_memory<std::uint64_t>(address, context.r.at(src)); break;
            default: break;
          }
          break;
        }
        case Opcode::vmemld128: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto base = fetch_byte(*context.module, cursor++);
          const auto offset = read_i32(*context.module, cursor);
          context.q.at(dst) = context.read_vec128(resolve_address(context, base, offset));
          set_predicates_from_vec(context, context.q.at(dst));
          break;
        }
        case Opcode::vmemst128: {
          const auto base = fetch_byte(*context.module, cursor++);
          const auto src = fetch_byte(*context.module, cursor++);
          const auto offset = read_i32(*context.module, cursor);
          context.write_vec128(resolve_address(context, base, offset), context.q.at(src));
          break;
        }
        case Opcode::imemcpy: {
          const auto dst_addr = context.r.at(fetch_byte(*context.module, cursor++));
          const auto src_addr = context.r.at(fetch_byte(*context.module, cursor++));
          const auto len = static_cast<std::size_t>(context.r.at(fetch_byte(*context.module, cursor++)));
          for (std::size_t i = 0; i < len; ++i) {
            context.write_memory<std::uint8_t>(dst_addr + i, context.read_memory<std::uint8_t>(src_addr + i));
          }
          set_predicates_from_value(context, len == 0 ? 0 : context.read_memory<std::uint8_t>(dst_addr));
          break;
        }
        case Opcode::imemset: {
          const auto dst_addr = context.r.at(fetch_byte(*context.module, cursor++));
          const auto byte_value = static_cast<std::uint8_t>(context.r.at(fetch_byte(*context.module, cursor++)) & 0xFFu);
          const auto len = static_cast<std::size_t>(context.r.at(fetch_byte(*context.module, cursor++)));
          for (std::size_t i = 0; i < len; ++i) {
            context.write_memory<std::uint8_t>(dst_addr + i, byte_value);
          }
          set_predicates_from_value(context, byte_value);
          break;
        }
        case Opcode::istrcmp: {
          const auto dst = fetch_byte(*context.module, cursor++);
          auto lhs = context.r.at(fetch_byte(*context.module, cursor++));
          auto rhs = context.r.at(fetch_byte(*context.module, cursor++));
          std::int64_t result = 0;
          for (;;) {
            const auto a = context.read_memory<std::uint8_t>(lhs++);
            const auto b = context.read_memory<std::uint8_t>(rhs++);
            result = static_cast<std::int64_t>(a) - static_cast<std::int64_t>(b);
            if (result != 0 || a == 0 || b == 0) break;
          }
          context.r.at(dst) = static_cast<std::uint64_t>(result);
          set_predicates_from_value(context, context.r.at(dst));
          break;
        }
        case Opcode::istrlen: {
          const auto dst = fetch_byte(*context.module, cursor++);
          auto ptr = context.r.at(fetch_byte(*context.module, cursor++));
          std::uint64_t len = 0;
          while (context.read_memory<std::uint8_t>(ptr + len) != 0) ++len;
          context.r.at(dst) = len;
          set_predicates_from_value(context, len);
          break;
        }
        case Opcode::icas64: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto base = fetch_byte(*context.module, cursor++);
          const auto expected = fetch_byte(*context.module, cursor++);
          const auto desired = fetch_byte(*context.module, cursor++);
          const auto offset = read_i32(*context.module, cursor);
          const auto addr = resolve_address(context, base, offset);
          const auto current = context.read_memory<std::uint64_t>(addr);
          if (current == context.r.at(expected)) {
            context.write_memory<std::uint64_t>(addr, context.r.at(desired));
            context.p[0] = true;
          } else {
            context.p[0] = false;
          }
          context.r.at(dst) = current;
          context.p[1] = static_cast<std::int64_t>(current) < 0;
          context.p[2] = false;
          context.p[3] = false;
          break;
        }
        case Opcode::ixchg64: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto base = fetch_byte(*context.module, cursor++);
          const auto src = fetch_byte(*context.module, cursor++);
          const auto offset = read_i32(*context.module, cursor);
          const auto addr = resolve_address(context, base, offset);
          const auto current = context.read_memory<std::uint64_t>(addr);
          context.write_memory<std::uint64_t>(addr, context.r.at(src));
          context.r.at(dst) = current;
          set_predicates_from_value(context, current);
          break;
        }
        case Opcode::ifence:
          break;
        case Opcode::jmp:
          context.pc = read_u32(*context.module, cursor);
          control_flow_changed = true;
          break;
        case Opcode::jp:
        case Opcode::jnp: {
          const auto pred = fetch_byte(*context.module, cursor++);
          const auto target = read_u32(*context.module, cursor);
          const auto take = opcode == Opcode::jp ? context.p.at(pred) : !context.p.at(pred);
          context.pc = take ? target : static_cast<std::uint32_t>(cursor);
          control_flow_changed = true;
          break;
        }
        case Opcode::blnk: {
          const auto target = read_u32(*context.module, cursor);
          const auto arg_count = fetch_byte(*context.module, cursor++);
          enter_call(context, target, arg_count, static_cast<std::uint32_t>(cursor));
          control_flow_changed = true;
          break;
        }
        case Opcode::bret:
          leave_call(context, context.execution_halted);
          control_flow_changed = true;
          if (stop_after_frame_depth.has_value() && context.frames_.size() == *stop_after_frame_depth) {
            early_return = ExecutionResult{context.r[0], context.d[0], context.q[0]};
            return;
          }
          break;
        case Opcode::pcall: {
          const auto pred = fetch_byte(*context.module, cursor++);
          const auto target = read_u32(*context.module, cursor);
          const auto arg_count = fetch_byte(*context.module, cursor++);
          if (context.p.at(pred)) {
            enter_call(context, target, arg_count, static_cast<std::uint32_t>(cursor));
            control_flow_changed = true;
          }
          break;
        }
        case Opcode::pret:
          if (context.p[0]) {
            leave_call(context, context.execution_halted);
            control_flow_changed = true;
            if (stop_after_frame_depth.has_value() && context.frames_.size() == *stop_after_frame_depth) {
              early_return = ExecutionResult{context.r[0], context.d[0], context.q[0]};
              return;
            }
          }
          break;
        case Opcode::bridgeargs: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto src = fetch_byte(*context.module, cursor++);
          const auto aux = fetch_byte(*context.module, cursor++);
          context.r.at(dst) = context.r.at(src) + context.r.at(aux);
          set_predicates_from_value(context, context.r.at(dst));
          break;
        }
        case Opcode::xcall: {
          const auto domain = fetch_byte(*context.module, cursor++);
          const auto id = read_u32(*context.module, cursor);
          const auto int_count = fetch_byte(*context.module, cursor++);
          const auto float_count = fetch_byte(*context.module, cursor++);
          const auto opaque_count = fetch_byte(*context.module, cursor++);
          if (context.bridge_registry == nullptr) throw Vm2Exception(frame.instruction_pc, "vm2: bridge registry not configured");
          if (bridge_domain_from_byte(domain) == vmp::runtime::bridge::Domain::vm1) {
            vmp::runtime::cryptor::vm2::notify_domain_switch(*context.module);
          }
          vmp::runtime::bridge::DomainCallArgs args;
          for (std::uint8_t i = 0; i < int_count; ++i) {
            if (i < 8) {
              args.ints.push_back(context.r[i]);
            } else {
              args.ints.push_back(context.read_memory<std::uint64_t>(context.sp + static_cast<std::uint64_t>((i - 8) * 8)));
            }
          }
          for (std::uint8_t i = 0; i < float_count; ++i) {
            args.floats.push_back(i < kVm2FloatRegisterCount ? context.d[i] : 0.0);
          }
          for (std::uint8_t i = 0; i < opaque_count; ++i) {
            args.opaque.push_back(reinterpret_cast<void*>(static_cast<std::uintptr_t>(context.r[i])));
          }
          const auto result = context.bridge_registry->call(bridge_domain_from_byte(domain), id, args, context.max_bridge_depth);
          context.r[0] = result.ret_int;
          context.d[0] = result.ret_float;
          set_predicates_from_value(context, result.ret_int);
          break;
        }
        case Opcode::xret:
          leave_call(context, context.execution_halted);
          control_flow_changed = true;
          if (stop_after_frame_depth.has_value() && context.frames_.size() == *stop_after_frame_depth) {
            early_return = ExecutionResult{context.r[0], context.d[0], context.q[0]};
            return;
          }
          break;
        case Opcode::tsload: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto id = read_u32(*context.module, cursor);
          context.r.at(dst) = context.materialize_transient_string(id);
          set_predicates_from_value(context, context.r.at(dst));
          break;
        }
        case Opcode::tsrelease: {
          const auto src = fetch_byte(*context.module, cursor++);
          context.release_transient_string(context.r.at(src));
          context.r.at(src) = 0;
          set_predicates_from_value(context, 0);
          break;
        }
        case Opcode::tsread8: {
          const auto dst = fetch_byte(*context.module, cursor++);
          const auto handle_reg = fetch_byte(*context.module, cursor++);
          const auto index_reg = fetch_byte(*context.module, cursor++);
          const auto text = context.transient_string(context.r.at(handle_reg));
          const auto index = static_cast<std::size_t>(context.r.at(index_reg));
          context.r.at(dst) = index < text.size() ? static_cast<std::uint8_t>(text[index]) : 0u;
          set_predicates_from_value(context, context.r.at(dst));
          break;
        }
        case Opcode::tswipe: {
          const auto src = fetch_byte(*context.module, cursor++);
          const auto handle = context.r.at(src);
          context.release_transient_string(handle);
          context.r.at(src) = 0;
          set_predicates_from_value(context, 0);
          break;
        }
        default:
          context.pc = frame.instruction_pc;
          dispatch_audit(context, "vm2_unknown_opcode", "unknown opcode");
          throw Vm2UnknownOpcode(frame.instruction_pc, "vm2: unknown opcode");
      
  }
}

ExecutionResult execute_impl(Vm2Context& context, std::optional<std::size_t> stop_after_frame_depth) {
  if (context.module == nullptr) throw Vm2Exception(0, "vm2: null module");
  if (context.pc > context.module->code.size()) throw Vm2Exception(context.pc, "vm2: entry pc out of range");
  context.execution_halted = false;
  try {
    while (!context.execution_halted) {
      (void)vmp::runtime::stack_probe::default_stack_probe().maybe_probe(
          vmp::runtime::stack_probe::ProbeRequest{
              vmp::runtime::stack_probe::selector_low12(reinterpret_cast<std::uintptr_t>(context.module) ^ context.module->id()),
              vmp::runtime::stack_probe::ProbeTriggerSite::vm2_handler_dispatch,
              vmp::runtime::stack_probe::kDefaultMaxFrames},
          context.audit_dispatcher);
      auto dispatch_scope = vmp::runtime::cryptor::vm2::begin_dispatch(*context.module);
      if (context.pc >= context.module->code.size()) throw Vm2Exception(context.pc, "vm2: pc out of range");
#if VMP_WITH_JIT
      if (context.pc == context.jit_skip_entry_once_pc) {
        context.jit_skip_entry_once_pc = 0xFFFFFFFFu;
      } else if (context.module->is_function_entry_pc(context.pc)) {
        const auto entry_pc = context.pc;
        const auto hit_count = context.module->note_function_hit(entry_pc);
        (void)vmp::runtime::jit::Vm2Jit::instance().compile_if_needed(*context.module, context, entry_pc, hit_count);
        if (context.module->function_jit_entry(entry_pc) != 0u) {
          const auto next_pc = vmp::runtime::jit::Vm2Jit::instance().dispatch(context, entry_pc);
          if (next_pc != std::numeric_limits<std::uint32_t>::max()) {
            context.pc = next_pc;
            if (context.execution_halted || (stop_after_frame_depth.has_value() && context.frames_.size() == *stop_after_frame_depth)) {
              return ExecutionResult{context.r[0], context.d[0], context.q[0]};
            }
            continue;
          }
        }
      }
#endif
      bool control_flow_changed = false;
      const auto instruction_pc = context.pc;
      std::size_t cursor = context.pc;
      const auto opcode = static_cast<Opcode>(read_u16(*context.module, cursor));
      context.pc = static_cast<std::uint32_t>(cursor);
      const auto* handler_entry = vm2_handler_catalog().resolve(opcode);
      if (handler_entry == nullptr) {
        context.pc = instruction_pc;
        dispatch_audit(context, "vm2_unknown_opcode", "unknown opcode");
        throw Vm2UnknownOpcode(instruction_pc, "vm2: unknown opcode");
      }
      std::optional<ExecutionResult> early_return;
      Vm2DispatchFrame frame{context, instruction_pc, cursor, control_flow_changed, stop_after_frame_depth, early_return};
      handler_entry->fn(frame);
      if (early_return.has_value()) {
        return *early_return;
      }
      if (!context.execution_halted && !control_flow_changed) context.pc = static_cast<std::uint32_t>(cursor);
    }
    return ExecutionResult{context.r[0], context.d[0], context.q[0]};
  } catch (const Vm2StackOverflow&) {
    dispatch_audit(context, "vm2_stack_overflow", "stack overflow");
    context.clear_all_transient_strings();
    throw;
  } catch (const Vm2UnknownOpcode&) {
    context.clear_all_transient_strings();
    throw;
  } catch (...) {
    context.clear_all_transient_strings();
    throw;
  }
}

const PolymorphicHandlerLayout& polymorphic_handler_layout() { return vm2_handler_catalog().layout; }

std::uint64_t polymorphic_handler_layout_fingerprint() noexcept {
  return vm2_handler_catalog().layout.layout_fingerprint;
}

std::uint64_t polymorphic_handler_build_seed() noexcept { return vm2_handler_catalog().layout.build_seed; }

ExecutionResult Vm2Interpreter::execute(Vm2Context& context) {
  (void)vmp::runtime::env_integrity::verify_sensitive_domain_entry("vm2", context.audit_dispatcher);
  return execute_impl(context, std::nullopt);
}

#if VMP_WITH_JIT
extern "C" std::uint32_t vmp_vm2_jit_execute_function(Vm2Context* context, std::uint32_t entry_pc) {
  if (context == nullptr || context->module == nullptr) {
    return std::numeric_limits<std::uint32_t>::max();
  }
  context->pc = entry_pc;
  context->jit_skip_entry_once_pc = entry_pc;
  const auto stop_depth = context->frames_.empty() ? std::optional<std::size_t>{} :
                                                    std::optional<std::size_t>{context->frames_.size() - 1u};
  (void)execute_impl(*context, stop_depth);
  return context->execution_halted ? context->pc : context->pc;
}
#endif

}  // namespace vmp::runtime::vm2

namespace vmp::runtime::bridge {

void BridgeRegistry::register_vm2(std::uint32_t id, vmp::runtime::vm2::Vm2Module* module) {
  vm2_handlers_[id] = [module](const DomainCallArgs& args, BridgeRegistry* registry, int max_depth) -> DomainCallResult {
    if (module == nullptr) throw BridgeException("bridge: vm2 module not found");
    vmp::runtime::cryptor::vm2::notify_domain_switch(*module);
    vmp::runtime::vm2::Vm2Context context(*module);
    context.bridge_registry = registry;
    context.max_bridge_depth = max_depth;
    for (std::size_t i = 0; i < args.ints.size() && i < 8; ++i) context.r[i] = args.ints[i];
    for (std::size_t i = 0; i < args.floats.size() && i < vmp::runtime::vm2::kVm2FloatRegisterCount; ++i) context.d[i] = args.floats[i];
    for (std::size_t i = 0; i < args.opaque.size() && i < 8; ++i) context.r[i] = reinterpret_cast<std::uintptr_t>(args.opaque[i]);
    const std::size_t spill_count = args.ints.size() > 8 ? args.ints.size() - 8 : 0u;
    if (spill_count > 0) {
      const auto spill_base = context.allocate_spill(spill_count * sizeof(std::uint64_t), "bridge spill");
      for (std::size_t i = 0; i < spill_count; ++i) {
        context.write_memory<std::uint64_t>(spill_base + static_cast<std::uint64_t>(i * sizeof(std::uint64_t)), args.ints[8 + i]);
      }
    }
    vmp::runtime::vm2::Vm2Interpreter interpreter;
    const auto result = interpreter.execute(context);
    return DomainCallResult{result.ret_int, result.ret_float, 0};
  };
}

}  // namespace vmp::runtime::bridge
