#include <vmp/runtime/cryptor/rolling_opcode.h>

#include <algorithm>
#include <array>
#include <limits>
#include <mutex>
#include <numeric>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <vmp/runtime/strings/cipher.h>

namespace vmp::runtime::cryptor {
namespace {

using ByteVector = std::vector<std::uint8_t>;
using ModuleIdentity = ModuleDescriptor::Identity;
constexpr std::string_view kRollingEpochInfoV2 = "vmp.cryptor.epoch.v2";

struct EpochStorage {
  OpcodeEpoch epoch;
  ByteVector forward_storage;
  ByteVector reverse_storage;
};

struct ModuleState {
  ModuleDescriptor descriptor;
  RollingPolicy policy = default_rolling_policy();
  std::uint64_t dispatch_counter = 0;
  EpochStorage current;
  std::optional<EpochStorage> previous;
};

struct RotationJob {
  VmDomain domain = VmDomain::vm1;
  std::uint64_t module_id = 0;
  std::uint32_t new_epoch_id = 0;
  std::string module_name;
  std::string note;
  bool rotated = false;
};

using EpochStackMap = std::unordered_map<ModuleIdentity, std::vector<std::uint32_t>, ModuleIdentityHash>;
thread_local EpochStackMap g_epoch_stack;

std::uint16_t read_u16(const ByteVector& bytes, std::size_t offset) {
  if (offset + 2 > bytes.size()) {
    throw std::runtime_error("rolling_opcode: truncated u16");
  }
  return static_cast<std::uint16_t>(bytes[offset]) |
         static_cast<std::uint16_t>(bytes[offset + 1] << 8u);
}

void write_u16(ByteVector& bytes, std::size_t offset, std::uint16_t value) {
  if (offset + 2 > bytes.size()) {
    throw std::runtime_error("rolling_opcode: truncated write_u16");
  }
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
}

void append_u32(ByteVector& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void append_u64(ByteVector& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

bool reason_enabled(const RollingPolicy& policy, RotationReason reason) {
  switch (reason) {
    case RotationReason::key_rotation: return policy.rotate_on_key_rotation;
    case RotationReason::integrity_event: return policy.rotate_on_integrity_event;
    case RotationReason::domain_switch: return policy.rotate_on_domain_switch;
    case RotationReason::dispatch_budget: return policy.dispatch_budget != 0;
  }
  return false;
}

OpcodeMap build_identity_map(const std::vector<std::uint16_t>& canonical_words) {
  OpcodeMap map;
  map.canonical_words = canonical_words;
  map.encoded_words = canonical_words;
  map.decoded_words = canonical_words;
  for (std::size_t i = 0; i < canonical_words.size(); ++i) {
    map.canonical_index_by_word[canonical_words[i]] = i;
    map.encoded_index_by_word[canonical_words[i]] = i;
  }
  return map;
}

OpcodeMap build_map_from_seed(const std::vector<std::uint16_t>& canonical_words,
                              const std::vector<std::uint8_t>& master_key_material,
                              const std::vector<std::uint8_t>& seed,
                              std::string_view purpose_tag) {
  auto map = build_identity_map(canonical_words);
  if (canonical_words.empty()) {
    return map;
  }
  std::vector<std::size_t> permutation(canonical_words.size());
  std::iota(permutation.begin(), permutation.end(), 0u);

  auto key_material = master_key_material;
  if (key_material.empty()) {
    key_material.assign(16, 0u);
  }
  auto seed_material = seed;
  if (seed_material.empty()) {
    seed_material.assign(16, 0u);
  }

  auto salt = key_material;
  const auto info = purpose_tag.empty() ? std::string(kRollingEpochInfoV2) : std::string(purpose_tag);
  salt.insert(salt.end(), info.begin(), info.end());
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(salt, seed_material);
  const auto okm = vmp::runtime::strings::hkdf_expand_sha256(prk, vmp::runtime::strings::to_bytes(info),
                                                             vmp::runtime::strings::kChaCha20KeySize);
  vmp::runtime::strings::Nonce nonce{};
  const auto keystream = vmp::runtime::strings::chacha20_xor(okm, nonce, 0, std::vector<std::uint8_t>(4096, 0));

  std::size_t offset = 0;
  auto next_u32 = [&]() {
    if (offset + 4 > keystream.size()) {
      throw std::runtime_error("rolling_opcode: keystream exhausted");
    }
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
      value |= static_cast<std::uint32_t>(keystream[offset + static_cast<std::size_t>(i)]) << (8 * i);
    }
    offset += 4;
    return value;
  };

  for (std::size_t i = permutation.size(); i > 1; --i) {
    const auto bound = static_cast<std::uint32_t>(i);
    const auto limit = std::numeric_limits<std::uint32_t>::max() -
                       (std::numeric_limits<std::uint32_t>::max() % bound);
    std::uint32_t sample = 0;
    do {
      sample = next_u32();
    } while (sample > limit);
    std::swap(permutation[i - 1], permutation[static_cast<std::size_t>(sample % bound)]);
  }

  map.encoded_words.assign(canonical_words.size(), 0u);
  map.decoded_words.assign(canonical_words.size(), 0u);
  map.encoded_index_by_word.clear();
  for (std::size_t i = 0; i < permutation.size(); ++i) {
    const auto encoded_word = canonical_words[permutation[i]];
    map.encoded_words[i] = encoded_word;
    map.decoded_words[permutation[i]] = canonical_words[i];
    map.encoded_index_by_word[encoded_word] = permutation[i];
  }
  return map;
}

std::array<std::uint8_t, 16> derive_epoch_seed(const ModuleState& state,
                                               std::uint32_t epoch_id,
                                               RotationReason reason,
                                               const std::vector<std::uint8_t>& key_override,
                                               std::array<std::uint8_t, 32>& derived_prk) {
  auto key_material = key_override.empty() ? state.descriptor.key_context_material : key_override;
  if (key_material.empty()) {
    key_material = state.descriptor.master_key_material;
  }
  if (key_material.empty()) {
    key_material.assign(16, 0u);
  }

  ByteVector material = state.descriptor.base_seed;
  append_u64(material, state.descriptor.module_id);
  append_u32(material, epoch_id);
  material.push_back(static_cast<std::uint8_t>(reason));
  material.push_back(static_cast<std::uint8_t>(state.descriptor.domain));
  material.insert(material.end(), key_material.begin(), key_material.end());

  auto salt = key_material;
  const auto info = state.descriptor.purpose_tag.empty() ? std::string(kRollingEpochInfoV2) : state.descriptor.purpose_tag;
  salt.insert(salt.end(), info.begin(), info.end());
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(salt, material);
  const auto okm = vmp::runtime::strings::hkdf_expand_sha256(
      prk,
      vmp::runtime::strings::to_bytes(info),
      48);
  std::copy_n(prk.begin(), derived_prk.size(), derived_prk.begin());
  std::array<std::uint8_t, 16> seed{};
  std::copy_n(okm.begin() + 32, seed.size(), seed.begin());
  return seed;
}

ByteVector build_reverse_storage(const ModuleDescriptor& descriptor, const ByteVector& forward_storage) {
  if (!descriptor.reverse_order) {
    return {};
  }
  ByteVector reverse;
  reverse.reserve(forward_storage.size());
  std::vector<std::size_t> starts;
  starts.reserve(descriptor.instruction_lengths.size());
  std::size_t forward_pc = 0;
  for (const auto length : descriptor.instruction_lengths) {
    starts.push_back(forward_pc);
    forward_pc += length;
  }
  for (std::size_t i = descriptor.instruction_lengths.size(); i > 0; --i) {
    const auto start = starts[i - 1];
    const auto length = descriptor.instruction_lengths[i - 1];
    reverse.insert(reverse.end(),
                   forward_storage.begin() + static_cast<std::ptrdiff_t>(start),
                   forward_storage.begin() + static_cast<std::ptrdiff_t>(start + length));
  }
  return reverse;
}

EpochStorage build_initial_epoch(const ModuleDescriptor& descriptor) {
  EpochStorage out;
  out.epoch.epoch_id = 0;
  if (descriptor.opcode_encrypted) {
    out.epoch.map = build_map_from_seed(descriptor.canonical_opcode_words,
                                        descriptor.master_key_material,
                                        descriptor.base_seed,
                                        descriptor.purpose_tag);
  } else {
    out.epoch.map = build_identity_map(descriptor.canonical_opcode_words);
  }
  out.forward_storage = descriptor.canonical_forward_code;
  std::size_t forward_pc = 0;
  for (const auto length : descriptor.instruction_lengths) {
    const auto canonical_word = read_u16(descriptor.canonical_forward_code, forward_pc);
    write_u16(out.forward_storage, forward_pc, out.epoch.map.encode(canonical_word));
    forward_pc += length;
  }
  out.reverse_storage = build_reverse_storage(descriptor, out.forward_storage);
  return out;
}

EpochStorage build_next_epoch(const ModuleState& state,
                              RotationReason reason,
                              const std::vector<std::uint8_t>& key_override) {
  EpochStorage next;
  next.epoch.epoch_id = state.current.epoch.epoch_id + 1u;
  const auto seed = derive_epoch_seed(state, next.epoch.epoch_id, reason, key_override, next.epoch.derived_from_key_ctx);
  next.epoch.epoch_seed = seed;
  next.epoch.map = build_map_from_seed(state.descriptor.canonical_opcode_words,
                                       key_override.empty() ? state.descriptor.master_key_material : key_override,
                                       std::vector<std::uint8_t>(seed.begin(), seed.end()),
                                       state.descriptor.purpose_tag);
  next.forward_storage = state.current.forward_storage;
  std::size_t forward_pc = 0;
  for (const auto length : state.descriptor.instruction_lengths) {
    const auto canonical_word = state.current.epoch.map.decode(read_u16(state.current.forward_storage, forward_pc));
    write_u16(next.forward_storage, forward_pc, next.epoch.map.encode(canonical_word));
    forward_pc += length;
  }
  next.reverse_storage = build_reverse_storage(state.descriptor, next.forward_storage);
  return next;
}

const EpochStorage& select_epoch_storage(const ModuleState& state, std::uint32_t epoch_id) {
  if (state.current.epoch.epoch_id == epoch_id) {
    return state.current;
  }
  if (state.previous.has_value() && state.previous->epoch.epoch_id == epoch_id) {
    return *state.previous;
  }
  return state.current;
}

std::optional<std::uint32_t> current_tls_epoch(const ModuleIdentity& identity) {
  const auto it = g_epoch_stack.find(identity);
  if (it == g_epoch_stack.end() || it->second.empty()) {
    return std::nullopt;
  }
  return it->second.back();
}

void push_tls_epoch(const ModuleIdentity& identity, std::uint32_t epoch_id) {
  g_epoch_stack[identity].push_back(epoch_id);
}

void pop_tls_epoch(const ModuleIdentity& identity) noexcept {
  const auto it = g_epoch_stack.find(identity);
  if (it == g_epoch_stack.end() || it->second.empty()) {
    return;
  }
  it->second.pop_back();
  if (it->second.empty()) {
    g_epoch_stack.erase(it);
  }
}

}  // namespace

const RollingPolicy& default_rolling_policy() noexcept {
  static const RollingPolicy policy{};
  return policy;
}

const char* to_string(VmDomain domain) noexcept {
  switch (domain) {
    case VmDomain::vm1: return "vm1";
    case VmDomain::vm2: return "vm2";
  }
  return "vm?";
}

const char* to_string(RotationReason reason) noexcept {
  switch (reason) {
    case RotationReason::key_rotation: return "key_rotation";
    case RotationReason::integrity_event: return "integrity_event";
    case RotationReason::domain_switch: return "domain_switch";
    case RotationReason::dispatch_budget: return "dispatch_budget";
  }
  return "unknown";
}

std::uint16_t OpcodeMap::encode(std::uint16_t canonical_word) const {
  const auto it = canonical_index_by_word.find(canonical_word);
  if (it == canonical_index_by_word.end()) {
    throw std::runtime_error("rolling_opcode: invalid canonical opcode");
  }
  return encoded_words.at(it->second);
}

std::uint16_t OpcodeMap::decode(std::uint16_t encoded_word) const {
  const auto it = encoded_index_by_word.find(encoded_word);
  if (it == encoded_index_by_word.end()) {
    throw std::runtime_error("rolling_opcode: invalid encoded opcode");
  }
  return decoded_words.at(it->second);
}

DispatchEpochScope::DispatchEpochScope(VmDomain domain, std::uint64_t module_id, std::uint32_t epoch_id) noexcept
    : domain_(domain), module_id_(module_id), epoch_id_(epoch_id), armed_(true) {
  push_tls_epoch(ModuleIdentity{module_id_, domain_}, epoch_id_);
}

DispatchEpochScope::~DispatchEpochScope() { release(); }

DispatchEpochScope::DispatchEpochScope(DispatchEpochScope&& other) noexcept { *this = std::move(other); }

DispatchEpochScope& DispatchEpochScope::operator=(DispatchEpochScope&& other) noexcept {
  if (this != &other) {
    release();
    domain_ = other.domain_;
    module_id_ = other.module_id_;
    epoch_id_ = other.epoch_id_;
    armed_ = other.armed_;
    other.domain_ = VmDomain::vm1;
    other.module_id_ = 0;
    other.epoch_id_ = 0;
    other.armed_ = false;
  }
  return *this;
}

void DispatchEpochScope::release() noexcept {
  if (!armed_) {
    return;
  }
  pop_tls_epoch(ModuleIdentity{module_id_, domain_});
  armed_ = false;
}

class RollingOpcodeRegistryImpl {
 public:
  mutable std::mutex mutex;
  vmp::runtime::audit::AuditWriter* audit = nullptr;
  std::unordered_map<ModuleIdentity, ModuleState, ModuleIdentityHash> modules;
  std::unordered_map<ModuleIdentity, RollingPolicy, ModuleIdentityHash> policies;
  std::unordered_map<VmDomain, EpochBumpCallback> callbacks;
};

RollingOpcodeRegistry& RollingOpcodeRegistry::instance() {
  static RollingOpcodeRegistry registry;
  return registry;
}

namespace {
RollingOpcodeRegistryImpl& impl() {
  static RollingOpcodeRegistryImpl instance;
  return instance;
}

void emit_audit(vmp::runtime::audit::AuditWriter* writer,
                const std::string& module_name,
                const std::string& note) {
  if (writer != nullptr) {
    writer->append(vmp::runtime::audit::make_event("opcode_epoch_rotated", note, 0, module_name));
    return;
  }
  try {
    vmp::runtime::audit::AuditWriter fallback(vmp::runtime::audit::AuditWriter::default_path());
    fallback.append(vmp::runtime::audit::make_event("opcode_epoch_rotated", note, 0, module_name));
    fallback.flush();
  } catch (...) {
  }
}

RotationJob rotate_locked(ModuleState& state,
                          RotationReason reason,
                          const std::vector<std::uint8_t>& key_override) {
  RotationJob job;
  job.domain = state.descriptor.domain;
  job.module_id = state.descriptor.module_id;
  job.module_name = state.descriptor.module_name;
  if (!state.descriptor.opcode_encrypted || !reason_enabled(state.policy, reason)) {
    return job;
  }
  state.previous = state.current;
  state.current = build_next_epoch(state, reason, key_override);
  job.new_epoch_id = state.current.epoch.epoch_id;
  job.note = "module_id=" + std::to_string(job.module_id) + " reason=" + std::string(to_string(reason)) +
             " new_epoch_id=" + std::to_string(job.new_epoch_id);
  job.rotated = true;
  return job;
}

void ensure_module_locked(const ModuleDescriptor& descriptor) {
  auto& state = impl().modules[descriptor.identity()];
  if (state.descriptor.module_id != 0) {
    return;
  }
  state.descriptor = descriptor;
  if (auto it = impl().policies.find(descriptor.identity()); it != impl().policies.end()) {
    state.policy = it->second;
  }
  state.current = build_initial_epoch(descriptor);
}

}  // namespace

void RollingOpcodeRegistry::set_audit_writer(vmp::runtime::audit::AuditWriter* writer) noexcept {
  std::lock_guard<std::mutex> lock(impl().mutex);
  impl().audit = writer;
}

void RollingOpcodeRegistry::set_policy(const ModuleDescriptor& descriptor, RollingPolicy policy) {
  std::lock_guard<std::mutex> lock(impl().mutex);
  impl().policies[descriptor.identity()] = policy;
  auto it = impl().modules.find(descriptor.identity());
  if (it != impl().modules.end()) {
    it->second.policy = policy;
  }
}

std::optional<RollingPolicy> RollingOpcodeRegistry::policy_for(const ModuleDescriptor& descriptor) const {
  std::lock_guard<std::mutex> lock(impl().mutex);
  auto it = impl().policies.find(descriptor.identity());
  if (it == impl().policies.end()) {
    return std::nullopt;
  }
  return it->second;
}

void RollingOpcodeRegistry::clear_policy(const ModuleDescriptor& descriptor) {
  std::lock_guard<std::mutex> lock(impl().mutex);
  impl().policies.erase(descriptor.identity());
  auto it = impl().modules.find(descriptor.identity());
  if (it != impl().modules.end()) {
    it->second.policy = default_rolling_policy();
  }
}

void RollingOpcodeRegistry::register_epoch_bump_callback(VmDomain domain, EpochBumpCallback callback) {
  std::lock_guard<std::mutex> lock(impl().mutex);
  impl().callbacks[domain] = std::move(callback);
}

void RollingOpcodeRegistry::clear_epoch_bump_callback(VmDomain domain) {
  std::lock_guard<std::mutex> lock(impl().mutex);
  impl().callbacks.erase(domain);
}

void RollingOpcodeRegistry::ensure_module(const ModuleDescriptor& descriptor) {
  std::lock_guard<std::mutex> lock(impl().mutex);
  ensure_module_locked(descriptor);
}

bool RollingOpcodeRegistry::has_module(const ModuleDescriptor& descriptor) const {
  std::lock_guard<std::mutex> lock(impl().mutex);
  return impl().modules.find(descriptor.identity()) != impl().modules.end();
}

void RollingOpcodeRegistry::reset_for_tests() {
  std::lock_guard<std::mutex> lock(impl().mutex);
  impl().audit = nullptr;
  impl().modules.clear();
  impl().policies.clear();
  g_epoch_stack.clear();
}

DispatchEpochScope RollingOpcodeRegistry::begin_dispatch(const ModuleDescriptor& descriptor) {
  EpochBumpCallback callback;
  RotationJob job;
  std::uint32_t epoch_id = 0;
  vmp::runtime::audit::AuditWriter* writer = nullptr;
  {
    std::lock_guard<std::mutex> lock(impl().mutex);
    ensure_module_locked(descriptor);
    auto& state = impl().modules.at(descriptor.identity());
    state.dispatch_counter += 1u;
    if (state.descriptor.opcode_encrypted && state.policy.dispatch_budget != 0u &&
        (state.dispatch_counter % state.policy.dispatch_budget) == 0u) {
      job = rotate_locked(state, RotationReason::dispatch_budget, {});
    }
    epoch_id = state.current.epoch.epoch_id;
    auto cb_it = impl().callbacks.find(state.descriptor.domain);
    if (cb_it != impl().callbacks.end()) {
      callback = cb_it->second;
    }
    writer = impl().audit;
  }
  if (job.rotated && callback) {
    callback(job.module_id, job.new_epoch_id);
  }
  if (job.rotated) {
    emit_audit(writer, job.module_name, job.note);
  }
  return DispatchEpochScope(descriptor.domain, descriptor.module_id, epoch_id);
}

void RollingOpcodeRegistry::rotate_module(const ModuleDescriptor& descriptor,
                                          RotationReason reason,
                                          std::vector<std::uint8_t> key_material_override) {
  EpochBumpCallback callback;
  RotationJob job;
  vmp::runtime::audit::AuditWriter* writer = nullptr;
  {
    std::lock_guard<std::mutex> lock(impl().mutex);
    ensure_module_locked(descriptor);
    auto& state = impl().modules.at(descriptor.identity());
    job = rotate_locked(state, reason, key_material_override);
    auto cb_it = impl().callbacks.find(state.descriptor.domain);
    if (cb_it != impl().callbacks.end()) {
      callback = cb_it->second;
    }
    writer = impl().audit;
  }
  if (job.rotated && callback) {
    callback(job.module_id, job.new_epoch_id);
  }
  if (job.rotated) {
    emit_audit(writer, job.module_name, job.note);
  }
}

void RollingOpcodeRegistry::rotate_all(VmDomain domain,
                                       RotationReason reason,
                                       std::vector<std::uint8_t> key_material_override) {
  std::vector<std::pair<RotationJob, EpochBumpCallback>> jobs;
  vmp::runtime::audit::AuditWriter* writer = nullptr;
  {
    std::lock_guard<std::mutex> lock(impl().mutex);
    writer = impl().audit;
    for (auto& [_, state] : impl().modules) {
      if (state.descriptor.domain != domain) {
        continue;
      }
      auto job = rotate_locked(state, reason, key_material_override);
      auto cb_it = impl().callbacks.find(domain);
      jobs.emplace_back(std::move(job), cb_it == impl().callbacks.end() ? EpochBumpCallback{} : cb_it->second);
    }
  }
  for (auto& [job, callback] : jobs) {
    if (!job.rotated) {
      continue;
    }
    if (callback) {
      callback(job.module_id, job.new_epoch_id);
    }
    emit_audit(writer, job.module_name, job.note);
  }
}

std::uint32_t RollingOpcodeRegistry::current_epoch_id(const ModuleDescriptor& descriptor) const {
  return current_epoch_id(descriptor.domain, descriptor.module_id);
}

std::uint32_t RollingOpcodeRegistry::current_epoch_id(VmDomain domain, std::uint64_t module_id) const {
  std::lock_guard<std::mutex> lock(impl().mutex);
  auto it = impl().modules.find(ModuleIdentity{module_id, domain});
  return it == impl().modules.end() ? 0u : it->second.current.epoch.epoch_id;
}

std::optional<std::uint32_t> RollingOpcodeRegistry::previous_epoch_id(const ModuleDescriptor& descriptor) const {
  std::lock_guard<std::mutex> lock(impl().mutex);
  auto it = impl().modules.find(descriptor.identity());
  if (it == impl().modules.end() || !it->second.previous.has_value()) {
    return std::nullopt;
  }
  return it->second.previous->epoch.epoch_id;
}

std::uint64_t RollingOpcodeRegistry::dispatch_count(const ModuleDescriptor& descriptor) const {
  std::lock_guard<std::mutex> lock(impl().mutex);
  auto it = impl().modules.find(descriptor.identity());
  return it == impl().modules.end() ? 0u : it->second.dispatch_counter;
}

std::uint8_t RollingOpcodeRegistry::fetch_decoded_byte(const ModuleDescriptor& descriptor, std::size_t forward_pc) const {
  const_cast<RollingOpcodeRegistry*>(this)->ensure_module(descriptor);
  const auto epoch = current_tls_epoch(descriptor.identity()).value_or(current_epoch_id(descriptor));
  return fetch_decoded_byte_for_epoch(descriptor, forward_pc, epoch);
}

std::uint8_t RollingOpcodeRegistry::fetch_decoded_byte_for_epoch(const ModuleDescriptor& descriptor,
                                                                 std::size_t forward_pc,
                                                                 std::uint32_t epoch_id) const {
  std::lock_guard<std::mutex> lock(impl().mutex);
  auto it = impl().modules.find(descriptor.identity());
  if (it == impl().modules.end()) {
    throw std::runtime_error("rolling_opcode: module not registered");
  }
  const auto& state = it->second;
  if (forward_pc >= state.descriptor.canonical_forward_code.size()) {
    throw std::runtime_error("rolling_opcode: pc out of range");
  }
  const auto& storage = select_epoch_storage(state, epoch_id);
  const auto inst_start = state.descriptor.forward_instruction_start_by_pc.at(forward_pc);
  const auto inst_length = state.descriptor.forward_instruction_length_by_pc.at(forward_pc);
  const auto offset = forward_pc - static_cast<std::size_t>(inst_start);
  const auto physical_inst_start = state.descriptor.reverse_order
                                       ? state.descriptor.canonical_forward_code.size() - static_cast<std::size_t>(inst_start) - inst_length
                                       : static_cast<std::size_t>(inst_start);
  const auto physical_pc = state.descriptor.reverse_order
                               ? state.descriptor.canonical_forward_code.size() - static_cast<std::size_t>(inst_start) - inst_length + offset
                               : forward_pc;
  const auto& bytes = state.descriptor.reverse_order ? storage.reverse_storage : storage.forward_storage;
  if (offset < 2u) {
    const auto canonical_word = storage.epoch.map.decode(read_u16(bytes, physical_inst_start));
    return offset == 0u ? static_cast<std::uint8_t>(canonical_word & 0xFFu)
                        : static_cast<std::uint8_t>((canonical_word >> 8u) & 0xFFu);
  }
  return bytes.at(physical_pc);
}

std::vector<std::uint8_t> RollingOpcodeRegistry::debug_forward_storage(const ModuleDescriptor& descriptor) const {
  std::lock_guard<std::mutex> lock(impl().mutex);
  auto it = impl().modules.find(descriptor.identity());
  return it == impl().modules.end() ? std::vector<std::uint8_t>{} : it->second.current.forward_storage;
}

std::vector<std::uint8_t> RollingOpcodeRegistry::debug_forward_storage_for_epoch(const ModuleDescriptor& descriptor,
                                                                                 std::uint32_t epoch_id) const {
  std::lock_guard<std::mutex> lock(impl().mutex);
  auto it = impl().modules.find(descriptor.identity());
  if (it == impl().modules.end()) {
    return {};
  }
  return select_epoch_storage(it->second, epoch_id).forward_storage;
}

OpcodeMapStore RollingOpcodeRegistry::map_store(const ModuleDescriptor& descriptor) const {
  std::lock_guard<std::mutex> lock(impl().mutex);
  auto it = impl().modules.find(descriptor.identity());
  if (it == impl().modules.end()) {
    return {};
  }
  OpcodeMapStore store;
  store.current = it->second.current.epoch;
  if (it->second.previous.has_value()) {
    store.previous = it->second.previous->epoch;
  }
  return store;
}

}  // namespace vmp::runtime::cryptor
