#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/cryptor/rolling_policy.h>

namespace vmp::runtime::cryptor {

struct OpcodeMap {
  std::vector<std::uint16_t> canonical_words;
  std::vector<std::uint16_t> encoded_words;
  std::vector<std::uint16_t> decoded_words;
  std::unordered_map<std::uint16_t, std::size_t> canonical_index_by_word;
  std::unordered_map<std::uint16_t, std::size_t> encoded_index_by_word;

  std::uint16_t encode(std::uint16_t canonical_word) const;
  std::uint16_t decode(std::uint16_t encoded_word) const;
};

struct OpcodeEpoch {
  std::uint32_t epoch_id = 0;
  OpcodeMap map;
  std::array<std::uint8_t, 32> derived_from_key_ctx{};
  std::array<std::uint8_t, 16> epoch_seed{};
};

struct OpcodeMapStore {
  OpcodeEpoch current;
  std::optional<OpcodeEpoch> previous;
};

struct ModuleDescriptor {
  std::uint64_t module_id = 0;
  VmDomain domain = VmDomain::vm1;
  std::string module_name;
  bool opcode_encrypted = false;
  bool reverse_order = false;
  std::vector<std::uint8_t> canonical_forward_code;
  std::vector<std::uint16_t> instruction_lengths;
  std::vector<std::uint32_t> forward_instruction_start_by_pc;
  std::vector<std::uint16_t> forward_instruction_length_by_pc;
  std::vector<std::uint16_t> canonical_opcode_words;
  std::vector<std::uint8_t> master_key_material;
  std::vector<std::uint8_t> base_seed;
  std::vector<std::uint8_t> key_context_material;
  std::string purpose_tag = "vmp.cryptor.epoch.v2";

  struct Identity {
    std::uint64_t module_id = 0;
    VmDomain domain = VmDomain::vm1;

    bool operator==(const Identity& other) const noexcept {
      return module_id == other.module_id && domain == other.domain;
    }
  };

  Identity identity() const noexcept { return Identity{module_id, domain}; }
};

struct ModuleIdentityHash {
  std::size_t operator()(const ModuleDescriptor::Identity& identity) const noexcept {
    return (std::hash<std::uint64_t>{}(identity.module_id) << 1u) ^
           std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(identity.domain));
  }
};

class DispatchEpochScope {
 public:
  DispatchEpochScope() = default;
  DispatchEpochScope(VmDomain domain, std::uint64_t module_id, std::uint32_t epoch_id) noexcept;
  ~DispatchEpochScope();

  DispatchEpochScope(const DispatchEpochScope&) = delete;
  DispatchEpochScope& operator=(const DispatchEpochScope&) = delete;
  DispatchEpochScope(DispatchEpochScope&& other) noexcept;
  DispatchEpochScope& operator=(DispatchEpochScope&& other) noexcept;

  std::uint32_t epoch_id() const noexcept { return epoch_id_; }
  explicit operator bool() const noexcept { return armed_; }

 private:
  void release() noexcept;

  VmDomain domain_ = VmDomain::vm1;
  std::uint64_t module_id_ = 0;
  std::uint32_t epoch_id_ = 0;
  bool armed_ = false;
};

using EpochBumpCallback = std::function<void(std::uint64_t module_id, std::uint32_t new_epoch_id)>;

class RollingOpcodeRegistry {
 public:
  static RollingOpcodeRegistry& instance();

  void set_audit_writer(vmp::runtime::audit::AuditWriter* writer) noexcept;
  void set_policy(const ModuleDescriptor& descriptor, RollingPolicy policy);
  std::optional<RollingPolicy> policy_for(const ModuleDescriptor& descriptor) const;
  void clear_policy(const ModuleDescriptor& descriptor);

  void register_epoch_bump_callback(VmDomain domain, EpochBumpCallback callback);
  void clear_epoch_bump_callback(VmDomain domain);

  void ensure_module(const ModuleDescriptor& descriptor);
  bool has_module(const ModuleDescriptor& descriptor) const;
  void reset_for_tests();

  DispatchEpochScope begin_dispatch(const ModuleDescriptor& descriptor);
  void rotate_module(const ModuleDescriptor& descriptor,
                     RotationReason reason,
                     std::vector<std::uint8_t> key_material_override = {});
  void rotate_all(VmDomain domain,
                  RotationReason reason,
                  std::vector<std::uint8_t> key_material_override = {});

  std::uint32_t current_epoch_id(const ModuleDescriptor& descriptor) const;
  std::uint32_t current_epoch_id(VmDomain domain, std::uint64_t module_id) const;
  std::optional<std::uint32_t> previous_epoch_id(const ModuleDescriptor& descriptor) const;
  std::uint64_t dispatch_count(const ModuleDescriptor& descriptor) const;

  std::uint8_t fetch_decoded_byte(const ModuleDescriptor& descriptor, std::size_t forward_pc) const;
  std::uint8_t fetch_decoded_byte_for_epoch(const ModuleDescriptor& descriptor,
                                            std::size_t forward_pc,
                                            std::uint32_t epoch_id) const;

  std::vector<std::uint8_t> debug_forward_storage(const ModuleDescriptor& descriptor) const;
  std::vector<std::uint8_t> debug_forward_storage_for_epoch(const ModuleDescriptor& descriptor,
                                                            std::uint32_t epoch_id) const;
  OpcodeMapStore map_store(const ModuleDescriptor& descriptor) const;
};

}  // namespace vmp::runtime::cryptor
