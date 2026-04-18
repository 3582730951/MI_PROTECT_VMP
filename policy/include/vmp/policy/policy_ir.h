#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

namespace vmp::policy {

inline constexpr std::uint32_t kCurrentSchemaVersion = 1;

enum class LanguageOrigin {
  c,
  cpp,
  rust,
  binary,
};

enum class AnnotationOrigin {
  attribute,
  pragma,
  proc_macro,
  external_manifest,
};

enum class ProtectionDomain {
  native,
  vm1,
  vm2,
};

enum class JitPolicy {
  off,
  hot_only,
  aggressive,
};

enum class PlaintextBudget {
  none,
  transient_only,
};

enum class ReactionPolicy {
  log,
  degrade,
  decoy_terminate,
  audit_only,
  audit_then_delayed_exit,
};

enum class IntegrityLevel {
  none,
  basic,
  strict,
};

enum class PlatformCaps : std::uint32_t {
  none = 0,
  Windows = 1u << 0,
  Linux = 1u << 1,
  Android = 1u << 2,
  Ios = 1u << 3,
  X86 = 1u << 4,
  X64 = 1u << 5,
  Arm = 1u << 6,
  Arm64 = 1u << 7,
  JitAllowed = 1u << 8,
  ExecmemAllowed = 1u << 9,
  WxEnforced = 1u << 10,
};

enum class SensitivityLevel {
  normal,
  sensitive,
  highly_sensitive,
};

enum class MobileBridgeMode {
  off,
  android_jni,
  ios_swift_objc,
  both,
};

enum class ValidationSeverity {
  error,
  warning,
};

struct SourceLocation {
  std::string file;
  std::uint32_t line = 0;
  std::uint32_t column = 0;

  bool operator==(const SourceLocation& other) const noexcept;
};

struct PolicyDefaults {
  LanguageOrigin language_origin = LanguageOrigin::binary;
  AnnotationOrigin annotation_origin = AnnotationOrigin::external_manifest;
  ProtectionDomain protection_domain = ProtectionDomain::native;
  JitPolicy jit_policy = JitPolicy::off;
  PlaintextBudget plaintext_budget = PlaintextBudget::transient_only;
  ReactionPolicy reaction_policy = ReactionPolicy::log;
  IntegrityLevel integrity_level = IntegrityLevel::none;
  std::uint32_t platform_caps = static_cast<std::uint32_t>(PlatformCaps::none);
  SensitivityLevel sensitivity_level = SensitivityLevel::normal;
  std::uint64_t profile_seed = 0;
  MobileBridgeMode mobile_bridge_mode = MobileBridgeMode::off;
  std::vector<std::string> event_types;

  bool operator==(const PolicyDefaults& other) const noexcept;
};

struct PolicyEntry {
  std::string symbol_or_region;
  LanguageOrigin language_origin = LanguageOrigin::binary;
  AnnotationOrigin annotation_origin = AnnotationOrigin::external_manifest;
  ProtectionDomain protection_domain = ProtectionDomain::native;
  JitPolicy jit_policy = JitPolicy::off;
  PlaintextBudget plaintext_budget = PlaintextBudget::transient_only;
  ReactionPolicy reaction_policy = ReactionPolicy::log;
  IntegrityLevel integrity_level = IntegrityLevel::none;
  std::uint32_t platform_caps = static_cast<std::uint32_t>(PlatformCaps::none);
  SensitivityLevel sensitivity_level = SensitivityLevel::normal;
  std::uint64_t profile_seed = 0;
  MobileBridgeMode mobile_bridge_mode = MobileBridgeMode::off;
  SourceLocation source_location;
  std::vector<std::string> annotation_tags;
  std::vector<std::string> event_types;

  bool operator==(const PolicyEntry& other) const noexcept;
};

struct PolicyIR {
  std::vector<PolicyEntry> entries;
  PolicyDefaults defaults;
  std::uint32_t schema_version = kCurrentSchemaVersion;

  bool operator==(const PolicyIR& other) const noexcept;
};

struct ValidationError {
  ValidationSeverity severity = ValidationSeverity::error;
  std::string code;
  std::string entry;
  std::string field;
  std::string message;

  bool is_error() const noexcept { return severity == ValidationSeverity::error; }
};

PolicyDefaults default_policy_defaults();

void apply_vm_func_annotation(PolicyEntry& entry);
void apply_vm_string_annotation(PolicyEntry& entry);

PolicyIR load_from_file(const std::string& path);
PolicyIR load_from_string(const std::string& json_text);
void save_to_file(const PolicyIR& policy_ir, const std::string& path);
std::string save_to_string(const PolicyIR& policy_ir);

std::vector<ValidationError> validate(const PolicyIR& policy_ir);

std::string to_string(LanguageOrigin value);
std::string to_string(AnnotationOrigin value);
std::string to_string(ProtectionDomain value);
std::string to_string(JitPolicy value);
std::string to_string(PlaintextBudget value);
std::string to_string(ReactionPolicy value);
std::string to_string(IntegrityLevel value);
std::string to_string(SensitivityLevel value);
std::string to_string(MobileBridgeMode value);
std::string to_string(ValidationSeverity value);
std::vector<std::string> platform_caps_to_strings(std::uint32_t caps);
std::string format_validation_error(const ValidationError& error);

std::string schema_as_json();
void dump_schema(std::ostream& out);

constexpr std::uint32_t operator|(PlatformCaps lhs, PlatformCaps rhs) noexcept {
  return static_cast<std::uint32_t>(lhs) | static_cast<std::uint32_t>(rhs);
}

constexpr std::uint32_t operator|(std::uint32_t lhs, PlatformCaps rhs) noexcept {
  return lhs | static_cast<std::uint32_t>(rhs);
}

constexpr bool has_platform_cap(std::uint32_t caps, PlatformCaps flag) noexcept {
  return (caps & static_cast<std::uint32_t>(flag)) != 0;
}

}  // namespace vmp::policy
