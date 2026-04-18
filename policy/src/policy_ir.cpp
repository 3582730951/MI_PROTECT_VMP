#include <vmp/policy/policy_ir.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

#include <nlohmann/json.hpp>

namespace vmp::policy {
namespace {

using json = nlohmann::json;

struct EnumTables {
  static const std::map<LanguageOrigin, std::string>& language_origin() {
    static const std::map<LanguageOrigin, std::string> table{{LanguageOrigin::c, "c"},
                                                             {LanguageOrigin::cpp, "cpp"},
                                                             {LanguageOrigin::rust, "rust"},
                                                             {LanguageOrigin::binary, "binary"}};
    return table;
  }

  static const std::map<AnnotationOrigin, std::string>& annotation_origin() {
    static const std::map<AnnotationOrigin, std::string> table{{AnnotationOrigin::attribute, "attribute"},
                                                               {AnnotationOrigin::pragma, "pragma"},
                                                               {AnnotationOrigin::proc_macro, "proc_macro"},
                                                               {AnnotationOrigin::external_manifest,
                                                                "external_manifest"}};
    return table;
  }

  static const std::map<ProtectionDomain, std::string>& protection_domain() {
    static const std::map<ProtectionDomain, std::string> table{{ProtectionDomain::native, "native"},
                                                               {ProtectionDomain::vm1, "vm1"},
                                                               {ProtectionDomain::vm2, "vm2"}};
    return table;
  }

  static const std::map<JitPolicy, std::string>& jit_policy() {
    static const std::map<JitPolicy, std::string> table{{JitPolicy::off, "off"},
                                                        {JitPolicy::hot_only, "hot_only"},
                                                        {JitPolicy::aggressive, "aggressive"}};
    return table;
  }

  static const std::map<PlaintextBudget, std::string>& plaintext_budget() {
    static const std::map<PlaintextBudget, std::string> table{{PlaintextBudget::none, "none"},
                                                              {PlaintextBudget::transient_only,
                                                               "transient_only"}};
    return table;
  }

  static const std::map<ReactionPolicy, std::string>& reaction_policy() {
    static const std::map<ReactionPolicy, std::string> table{{ReactionPolicy::log, "log"},
                                                             {ReactionPolicy::degrade, "degrade"},
                                                             {ReactionPolicy::decoy_terminate,
                                                              "decoy_terminate"},
                                                             {ReactionPolicy::audit_only, "audit_only"},
                                                             {ReactionPolicy::audit_then_delayed_exit,
                                                              "audit_then_delayed_exit"}};
    return table;
  }

  static const std::map<IntegrityLevel, std::string>& integrity_level() {
    static const std::map<IntegrityLevel, std::string> table{{IntegrityLevel::none, "none"},
                                                             {IntegrityLevel::basic, "basic"},
                                                             {IntegrityLevel::strict, "strict"}};
    return table;
  }

  static const std::map<SensitivityLevel, std::string>& sensitivity_level() {
    static const std::map<SensitivityLevel, std::string> table{{SensitivityLevel::normal, "normal"},
                                                               {SensitivityLevel::sensitive, "sensitive"},
                                                               {SensitivityLevel::highly_sensitive,
                                                                "highly_sensitive"}};
    return table;
  }

  static const std::map<MobileBridgeMode, std::string>& mobile_bridge_mode() {
    static const std::map<MobileBridgeMode, std::string> table{{MobileBridgeMode::off, "off"},
                                                               {MobileBridgeMode::android_jni,
                                                                "android_jni"},
                                                               {MobileBridgeMode::ios_swift_objc,
                                                                "ios_swift_objc"},
                                                               {MobileBridgeMode::both, "both"}};
    return table;
  }

  static const std::vector<std::pair<PlatformCaps, const char*>>& platform_caps() {
    static const std::vector<std::pair<PlatformCaps, const char*>> table{{PlatformCaps::Windows, "windows"},
                                                                         {PlatformCaps::Linux, "linux"},
                                                                         {PlatformCaps::Android, "android"},
                                                                         {PlatformCaps::Ios, "ios"},
                                                                         {PlatformCaps::X86, "x86"},
                                                                         {PlatformCaps::X64, "x64"},
                                                                         {PlatformCaps::Arm, "arm"},
                                                                         {PlatformCaps::Arm64, "arm64"},
                                                                         {PlatformCaps::JitAllowed,
                                                                          "jit_allowed"},
                                                                         {PlatformCaps::ExecmemAllowed,
                                                                          "execmem_allowed"},
                                                                         {PlatformCaps::WxEnforced,
                                                                          "wx_enforced"}};
    return table;
  }
};

template <typename Enum>
std::string enum_to_string(Enum value, const std::map<Enum, std::string>& table) {
  const auto it = table.find(value);
  if (it == table.end()) {
    throw std::runtime_error("unmapped enum value");
  }
  return it->second;
}

template <typename Enum>
Enum enum_from_string(const json& value, const char* field_name, const std::map<Enum, std::string>& table) {
  if (!value.is_string()) {
    throw std::runtime_error(std::string("field '") + field_name + "' must be a string");
  }
  const auto needle = value.get<std::string>();
  for (const auto& [enum_value, text] : table) {
    if (text == needle) {
      return enum_value;
    }
  }
  std::ostringstream oss;
  oss << "field '" << field_name << "' has invalid value '" << needle << "'";
  throw std::runtime_error(oss.str());
}

void ensure_allowed_keys(const json& object,
                         const std::unordered_set<std::string>& allowed,
                         const std::string& context) {
  if (!object.is_object()) {
    throw std::runtime_error(context + " must be an object");
  }
  for (const auto& [key, _] : object.items()) {
    if (allowed.find(key) == allowed.end()) {
      throw std::runtime_error(context + " contains unknown field '" + key + "'");
    }
  }
}

std::vector<std::string> parse_string_array(const json& value, const char* field_name) {
  if (!value.is_array()) {
    throw std::runtime_error(std::string("field '") + field_name + "' must be an array");
  }
  std::vector<std::string> out;
  for (const auto& item : value) {
    if (!item.is_string()) {
      throw std::runtime_error(std::string("field '") + field_name + "' must contain only strings");
    }
    out.push_back(item.get<std::string>());
  }
  return out;
}

json platform_caps_to_json(std::uint32_t caps) {
  json values = json::array();
  for (const auto& [flag, name] : EnumTables::platform_caps()) {
    if (has_platform_cap(caps, flag)) {
      values.push_back(name);
    }
  }
  return values;
}

std::uint32_t platform_caps_from_json(const json& value, const char* field_name) {
  if (!value.is_array()) {
    throw std::runtime_error(std::string("field '") + field_name + "' must be an array");
  }
  std::uint32_t caps = static_cast<std::uint32_t>(PlatformCaps::none);
  for (const auto& item : value) {
    if (!item.is_string()) {
      throw std::runtime_error(std::string("field '") + field_name + "' must contain only strings");
    }
    const auto name = item.get<std::string>();
    bool matched = false;
    for (const auto& [flag, flag_name] : EnumTables::platform_caps()) {
      if (name == flag_name) {
        caps |= static_cast<std::uint32_t>(flag);
        matched = true;
        break;
      }
    }
    if (!matched) {
      throw std::runtime_error(std::string("field '") + field_name + "' has invalid capability '" + name + "'");
    }
  }
  return caps;
}

SourceLocation parse_source_location(const json& value) {
  static const std::unordered_set<std::string> kAllowed{"file", "line", "column"};
  ensure_allowed_keys(value, kAllowed, "source_location");
  SourceLocation out;
  if (const auto it = value.find("file"); it != value.end()) {
    if (!it->is_string()) {
      throw std::runtime_error("field 'source_location.file' must be a string");
    }
    out.file = it->get<std::string>();
  }
  if (const auto it = value.find("line"); it != value.end()) {
    if (!it->is_number_unsigned()) {
      throw std::runtime_error("field 'source_location.line' must be an unsigned integer");
    }
    out.line = it->get<std::uint32_t>();
  }
  if (const auto it = value.find("column"); it != value.end()) {
    if (!it->is_number_unsigned()) {
      throw std::runtime_error("field 'source_location.column' must be an unsigned integer");
    }
    out.column = it->get<std::uint32_t>();
  }
  return out;
}

json source_location_to_json(const SourceLocation& location) {
  return json{{"file", location.file}, {"line", location.line}, {"column", location.column}};
}

PolicyDefaults parse_defaults_object(const json& object, std::uint32_t schema_version) {
  (void)schema_version;
  static const std::unordered_set<std::string> kAllowed{"language_origin",
                                                        "annotation_origin",
                                                        "protection_domain",
                                                        "jit_policy",
                                                        "plaintext_budget",
                                                        "reaction_policy",
                                                        "integrity_level",
                                                        "platform_caps",
                                                        "sensitivity_level",
                                                        "profile_seed",
                                                        "mobile_bridge_mode",
                                                        "event_types"};
  ensure_allowed_keys(object, kAllowed, "defaults");

  PolicyDefaults defaults = default_policy_defaults();
  if (const auto it = object.find("language_origin"); it != object.end()) {
    defaults.language_origin = enum_from_string(*it, "language_origin", EnumTables::language_origin());
  }
  if (const auto it = object.find("annotation_origin"); it != object.end()) {
    defaults.annotation_origin = enum_from_string(*it, "annotation_origin", EnumTables::annotation_origin());
  }
  if (const auto it = object.find("protection_domain"); it != object.end()) {
    defaults.protection_domain = enum_from_string(*it, "protection_domain", EnumTables::protection_domain());
  }
  if (const auto it = object.find("jit_policy"); it != object.end()) {
    defaults.jit_policy = enum_from_string(*it, "jit_policy", EnumTables::jit_policy());
  }
  if (const auto it = object.find("plaintext_budget"); it != object.end()) {
    defaults.plaintext_budget = enum_from_string(*it, "plaintext_budget", EnumTables::plaintext_budget());
  }
  if (const auto it = object.find("reaction_policy"); it != object.end()) {
    defaults.reaction_policy = enum_from_string(*it, "reaction_policy", EnumTables::reaction_policy());
  }
  if (const auto it = object.find("integrity_level"); it != object.end()) {
    defaults.integrity_level = enum_from_string(*it, "integrity_level", EnumTables::integrity_level());
  }
  if (const auto it = object.find("platform_caps"); it != object.end()) {
    defaults.platform_caps = platform_caps_from_json(*it, "platform_caps");
  }
  if (const auto it = object.find("sensitivity_level"); it != object.end()) {
    defaults.sensitivity_level = enum_from_string(*it, "sensitivity_level", EnumTables::sensitivity_level());
  }
  if (const auto it = object.find("profile_seed"); it != object.end()) {
    if (!it->is_number_unsigned()) {
      throw std::runtime_error("field 'profile_seed' must be an unsigned integer");
    }
    defaults.profile_seed = it->get<std::uint64_t>();
  }
  if (const auto it = object.find("mobile_bridge_mode"); it != object.end()) {
    defaults.mobile_bridge_mode = enum_from_string(*it, "mobile_bridge_mode", EnumTables::mobile_bridge_mode());
  }
  if (const auto it = object.find("event_types"); it != object.end()) {
    defaults.event_types = parse_string_array(*it, "event_types");
  }
  return defaults;
}

PolicyEntry parse_entry_object(const json& object, const PolicyDefaults& defaults, std::uint32_t schema_version) {
  (void)schema_version;
  static const std::unordered_set<std::string> kAllowed{"symbol_or_region",
                                                        "language_origin",
                                                        "annotation_origin",
                                                        "protection_domain",
                                                        "jit_policy",
                                                        "plaintext_budget",
                                                        "reaction_policy",
                                                        "integrity_level",
                                                        "platform_caps",
                                                        "sensitivity_level",
                                                        "profile_seed",
                                                        "mobile_bridge_mode",
                                                        "source_location",
                                                        "annotation_tags",
                                                        "event_types"};
  ensure_allowed_keys(object, kAllowed, "entry");

  if (!object.contains("symbol_or_region") || !object.at("symbol_or_region").is_string()) {
    throw std::runtime_error("entry field 'symbol_or_region' is required and must be a string");
  }

  PolicyEntry entry;
  entry.symbol_or_region = object.at("symbol_or_region").get<std::string>();
  entry.language_origin = defaults.language_origin;
  entry.annotation_origin = defaults.annotation_origin;
  entry.protection_domain = defaults.protection_domain;
  entry.jit_policy = defaults.jit_policy;
  entry.plaintext_budget = defaults.plaintext_budget;
  entry.reaction_policy = defaults.reaction_policy;
  entry.integrity_level = defaults.integrity_level;
  entry.platform_caps = defaults.platform_caps;
  entry.sensitivity_level = defaults.sensitivity_level;
  entry.profile_seed = defaults.profile_seed;
  entry.mobile_bridge_mode = defaults.mobile_bridge_mode;
  entry.event_types = defaults.event_types;

  if (const auto it = object.find("language_origin"); it != object.end()) {
    entry.language_origin = enum_from_string(*it, "language_origin", EnumTables::language_origin());
  }
  if (const auto it = object.find("annotation_origin"); it != object.end()) {
    entry.annotation_origin = enum_from_string(*it, "annotation_origin", EnumTables::annotation_origin());
  }
  if (const auto it = object.find("protection_domain"); it != object.end()) {
    entry.protection_domain = enum_from_string(*it, "protection_domain", EnumTables::protection_domain());
  }
  if (const auto it = object.find("jit_policy"); it != object.end()) {
    entry.jit_policy = enum_from_string(*it, "jit_policy", EnumTables::jit_policy());
  }
  if (const auto it = object.find("plaintext_budget"); it != object.end()) {
    entry.plaintext_budget = enum_from_string(*it, "plaintext_budget", EnumTables::plaintext_budget());
  }
  if (const auto it = object.find("reaction_policy"); it != object.end()) {
    entry.reaction_policy = enum_from_string(*it, "reaction_policy", EnumTables::reaction_policy());
  }
  if (const auto it = object.find("integrity_level"); it != object.end()) {
    entry.integrity_level = enum_from_string(*it, "integrity_level", EnumTables::integrity_level());
  }
  if (const auto it = object.find("platform_caps"); it != object.end()) {
    entry.platform_caps = platform_caps_from_json(*it, "platform_caps");
  }
  if (const auto it = object.find("sensitivity_level"); it != object.end()) {
    entry.sensitivity_level = enum_from_string(*it, "sensitivity_level", EnumTables::sensitivity_level());
  }
  if (const auto it = object.find("profile_seed"); it != object.end()) {
    if (!it->is_number_unsigned()) {
      throw std::runtime_error("field 'profile_seed' must be an unsigned integer");
    }
    entry.profile_seed = it->get<std::uint64_t>();
  }
  if (const auto it = object.find("mobile_bridge_mode"); it != object.end()) {
    entry.mobile_bridge_mode = enum_from_string(*it, "mobile_bridge_mode", EnumTables::mobile_bridge_mode());
  }
  if (const auto it = object.find("source_location"); it != object.end()) {
    entry.source_location = parse_source_location(*it);
  }
  if (const auto it = object.find("annotation_tags"); it != object.end()) {
    entry.annotation_tags = parse_string_array(*it, "annotation_tags");
  }
  if (const auto it = object.find("event_types"); it != object.end()) {
    entry.event_types = parse_string_array(*it, "event_types");
  }

  return entry;
}

json defaults_to_json(const PolicyDefaults& defaults) {
  return json{{"language_origin", to_string(defaults.language_origin)},
              {"annotation_origin", to_string(defaults.annotation_origin)},
              {"protection_domain", to_string(defaults.protection_domain)},
              {"jit_policy", to_string(defaults.jit_policy)},
              {"plaintext_budget", to_string(defaults.plaintext_budget)},
              {"reaction_policy", to_string(defaults.reaction_policy)},
              {"integrity_level", to_string(defaults.integrity_level)},
              {"platform_caps", platform_caps_to_json(defaults.platform_caps)},
              {"sensitivity_level", to_string(defaults.sensitivity_level)},
              {"profile_seed", defaults.profile_seed},
              {"mobile_bridge_mode", to_string(defaults.mobile_bridge_mode)},
              {"event_types", defaults.event_types}};
}

json entry_to_json(const PolicyEntry& entry) {
  return json{{"symbol_or_region", entry.symbol_or_region},
              {"language_origin", to_string(entry.language_origin)},
              {"annotation_origin", to_string(entry.annotation_origin)},
              {"protection_domain", to_string(entry.protection_domain)},
              {"jit_policy", to_string(entry.jit_policy)},
              {"plaintext_budget", to_string(entry.plaintext_budget)},
              {"reaction_policy", to_string(entry.reaction_policy)},
              {"integrity_level", to_string(entry.integrity_level)},
              {"platform_caps", platform_caps_to_json(entry.platform_caps)},
              {"sensitivity_level", to_string(entry.sensitivity_level)},
              {"profile_seed", entry.profile_seed},
              {"mobile_bridge_mode", to_string(entry.mobile_bridge_mode)},
              {"source_location", source_location_to_json(entry.source_location)},
              {"annotation_tags", entry.annotation_tags},
              {"event_types", entry.event_types}};
}

bool contains_tag(const std::vector<std::string>& values, const std::string& needle) {
  return std::find(values.begin(), values.end(), needle) != values.end();
}

void add_unique_tag(std::vector<std::string>& values, const std::string& needle) {
  if (!contains_tag(values, needle)) {
    values.push_back(needle);
  }
}

int sensitivity_rank(SensitivityLevel value) {
  switch (value) {
    case SensitivityLevel::normal:
      return 0;
    case SensitivityLevel::sensitive:
      return 1;
    case SensitivityLevel::highly_sensitive:
      return 2;
  }
  return -1;
}

void maybe_push(std::vector<ValidationError>& errors,
                ValidationSeverity severity,
                const PolicyEntry& entry,
                std::string code,
                std::string field,
                std::string message) {
  errors.push_back(ValidationError{severity, std::move(code), entry.symbol_or_region, std::move(field), std::move(message)});
}

std::string join_strings(const std::vector<std::string>& values) {
  std::ostringstream oss;
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i != 0) {
      oss << ", ";
    }
    oss << values[i];
  }
  return oss.str();
}

}  // namespace

bool SourceLocation::operator==(const SourceLocation& other) const noexcept {
  return file == other.file && line == other.line && column == other.column;
}

bool PolicyDefaults::operator==(const PolicyDefaults& other) const noexcept {
  return language_origin == other.language_origin && annotation_origin == other.annotation_origin &&
         protection_domain == other.protection_domain && jit_policy == other.jit_policy &&
         plaintext_budget == other.plaintext_budget && reaction_policy == other.reaction_policy &&
         integrity_level == other.integrity_level && platform_caps == other.platform_caps &&
         sensitivity_level == other.sensitivity_level && profile_seed == other.profile_seed &&
         mobile_bridge_mode == other.mobile_bridge_mode && event_types == other.event_types;
}

bool PolicyEntry::operator==(const PolicyEntry& other) const noexcept {
  return symbol_or_region == other.symbol_or_region && language_origin == other.language_origin &&
         annotation_origin == other.annotation_origin && protection_domain == other.protection_domain &&
         jit_policy == other.jit_policy && plaintext_budget == other.plaintext_budget &&
         reaction_policy == other.reaction_policy && integrity_level == other.integrity_level &&
         platform_caps == other.platform_caps && sensitivity_level == other.sensitivity_level &&
         profile_seed == other.profile_seed && mobile_bridge_mode == other.mobile_bridge_mode &&
         source_location == other.source_location && annotation_tags == other.annotation_tags &&
         event_types == other.event_types;
}

bool PolicyIR::operator==(const PolicyIR& other) const noexcept {
  return entries == other.entries && defaults == other.defaults && schema_version == other.schema_version;
}

PolicyDefaults default_policy_defaults() { return PolicyDefaults{}; }

void apply_vm_func_annotation(PolicyEntry& entry) {
  add_unique_tag(entry.annotation_tags, "vm_func");
  if (entry.protection_domain == ProtectionDomain::native) {
    entry.protection_domain = ProtectionDomain::vm1;
  }
  if (sensitivity_rank(entry.sensitivity_level) < sensitivity_rank(SensitivityLevel::sensitive)) {
    entry.sensitivity_level = SensitivityLevel::sensitive;
  }
}

void apply_vm_string_annotation(PolicyEntry& entry) {
  add_unique_tag(entry.annotation_tags, "vm_string");
  entry.sensitivity_level = SensitivityLevel::highly_sensitive;
  if (entry.plaintext_budget != PlaintextBudget::none) {
    entry.plaintext_budget = PlaintextBudget::transient_only;
  }
}

PolicyIR load_from_file(const std::string& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to open policy file: " + path);
  }
  std::ostringstream oss;
  oss << input.rdbuf();
  try {
    return load_from_string(oss.str());
  } catch (const std::exception& ex) {
    throw std::runtime_error(path + ": " + ex.what());
  }
}

PolicyIR load_from_string(const std::string& json_text) {
  json root;
  try {
    root = json::parse(json_text);
  } catch (const json::parse_error& ex) {
    throw std::runtime_error(std::string("invalid JSON: ") + ex.what());
  }

  static const std::unordered_set<std::string> kAllowed{"schema_version", "defaults", "entries"};
  ensure_allowed_keys(root, kAllowed, "policy root");

  PolicyIR out;
  if (const auto it = root.find("schema_version"); it != root.end()) {
    if (!it->is_number_unsigned()) {
      throw std::runtime_error("field 'schema_version' must be an unsigned integer");
    }
    out.schema_version = it->get<std::uint32_t>();
  }
  if (out.schema_version > kCurrentSchemaVersion) {
    std::ostringstream oss;
    oss << "unsupported schema_version " << out.schema_version << ", current schema_version is "
        << kCurrentSchemaVersion;
    throw std::runtime_error(oss.str());
  }
  if (const auto it = root.find("defaults"); it != root.end()) {
    out.defaults = parse_defaults_object(*it, out.schema_version);
  } else {
    out.defaults = default_policy_defaults();
  }
  if (!root.contains("entries") || !root.at("entries").is_array()) {
    throw std::runtime_error("field 'entries' is required and must be an array");
  }
  for (const auto& item : root.at("entries")) {
    out.entries.push_back(parse_entry_object(item, out.defaults, out.schema_version));
  }
  return out;
}

void save_to_file(const PolicyIR& policy_ir, const std::string& path) {
  std::ofstream output(path);
  if (!output) {
    throw std::runtime_error("failed to open output file: " + path);
  }
  output << save_to_string(policy_ir);
}

std::string save_to_string(const PolicyIR& policy_ir) {
  json root;
  root["schema_version"] = policy_ir.schema_version;
  root["defaults"] = defaults_to_json(policy_ir.defaults);
  root["entries"] = json::array();
  for (const auto& entry : policy_ir.entries) {
    root["entries"].push_back(entry_to_json(entry));
  }
  return root.dump(2) + "\n";
}

std::vector<ValidationError> validate(const PolicyIR& policy_ir) {
  std::vector<ValidationError> errors;
  for (const auto& entry : policy_ir.entries) {
    const bool is_vm_func = contains_tag(entry.annotation_tags, "vm_func");
    const bool is_vm_string = contains_tag(entry.annotation_tags, "vm_string");

    if (is_vm_func && entry.protection_domain == ProtectionDomain::native) {
      maybe_push(errors,
                 ValidationSeverity::error,
                 entry,
                 "vm_func_native",
                 "protection_domain",
                 "VM_func entries must remain in vm1 or vm2 and cannot fall back to native");
    }

    if (is_vm_string && entry.sensitivity_level != SensitivityLevel::highly_sensitive) {
      maybe_push(errors,
                 ValidationSeverity::error,
                 entry,
                 "vm_string_sensitivity",
                 "sensitivity_level",
                 "VM_string entries must use highly_sensitive sensitivity_level");
    }

    if (is_vm_string && entry.plaintext_budget != PlaintextBudget::none &&
        entry.plaintext_budget != PlaintextBudget::transient_only) {
      maybe_push(errors,
                 ValidationSeverity::error,
                 entry,
                 "vm_string_plaintext_budget",
                 "plaintext_budget",
                 "VM_string entries must use plaintext_budget none or transient_only");
    }

    if (entry.reaction_policy == ReactionPolicy::audit_then_delayed_exit &&
        !contains_tag(entry.event_types, "hw_breakpoint")) {
      maybe_push(errors,
                 ValidationSeverity::error,
                 entry,
                 "audit_then_delayed_exit_event_type",
                 "event_types",
                 "reaction_policy audit_then_delayed_exit requires event_types to contain 'hw_breakpoint'");
    }

    if (has_platform_cap(entry.platform_caps, PlatformCaps::Ios) &&
        !has_platform_cap(entry.platform_caps, PlatformCaps::JitAllowed) &&
        entry.jit_policy == JitPolicy::aggressive) {
      maybe_push(errors,
                 ValidationSeverity::error,
                 entry,
                 "ios_jit_capability",
                 "jit_policy",
                 "iOS entries without jit_allowed must use jit_policy off or hot_only with interpreter fallback");
    }

    if (entry.protection_domain == ProtectionDomain::vm2 && entry.integrity_level != IntegrityLevel::strict) {
      maybe_push(errors,
                 ValidationSeverity::error,
                 entry,
                 "vm2_integrity_level",
                 "integrity_level",
                 "vm2 entries must use integrity_level strict");
    }

    if (entry.profile_seed == 0) {
      maybe_push(errors,
                 ValidationSeverity::warning,
                 entry,
                 "profile_seed_zero",
                 "profile_seed",
                 "profile_seed is 0; offline/online profile correlation will be unstable");
    }

    if (entry.sensitivity_level == SensitivityLevel::normal && entry.plaintext_budget == PlaintextBudget::none) {
      maybe_push(errors,
                 ValidationSeverity::warning,
                 entry,
                 "normal_with_no_plaintext",
                 "plaintext_budget",
                 "sensitivity_level normal with plaintext_budget none is unusually strict");
    }
  }
  return errors;
}

std::string to_string(LanguageOrigin value) { return enum_to_string(value, EnumTables::language_origin()); }
std::string to_string(AnnotationOrigin value) { return enum_to_string(value, EnumTables::annotation_origin()); }
std::string to_string(ProtectionDomain value) { return enum_to_string(value, EnumTables::protection_domain()); }
std::string to_string(JitPolicy value) { return enum_to_string(value, EnumTables::jit_policy()); }
std::string to_string(PlaintextBudget value) { return enum_to_string(value, EnumTables::plaintext_budget()); }
std::string to_string(ReactionPolicy value) { return enum_to_string(value, EnumTables::reaction_policy()); }
std::string to_string(IntegrityLevel value) { return enum_to_string(value, EnumTables::integrity_level()); }
std::string to_string(SensitivityLevel value) { return enum_to_string(value, EnumTables::sensitivity_level()); }
std::string to_string(MobileBridgeMode value) { return enum_to_string(value, EnumTables::mobile_bridge_mode()); }

std::string to_string(ValidationSeverity value) {
  switch (value) {
    case ValidationSeverity::error:
      return "error";
    case ValidationSeverity::warning:
      return "warning";
  }
  throw std::runtime_error("unmapped validation severity");
}

std::vector<std::string> platform_caps_to_strings(std::uint32_t caps) {
  std::vector<std::string> out;
  for (const auto& [flag, name] : EnumTables::platform_caps()) {
    if (has_platform_cap(caps, flag)) {
      out.emplace_back(name);
    }
  }
  return out;
}

std::string format_validation_error(const ValidationError& error) {
  std::ostringstream oss;
  oss << to_string(error.severity) << "[" << error.code << "]";
  if (!error.entry.empty()) {
    oss << " entry='" << error.entry << "'";
  }
  if (!error.field.empty()) {
    oss << " field='" << error.field << "'";
  }
  oss << ": " << error.message;
  return oss.str();
}

std::string schema_as_json() {
  json schema;
  schema["schema_version"] = kCurrentSchemaVersion;
  schema["format"] = "json";
  schema["strict_unknown_fields"] = true;
  schema["root"] = json{{"required", json::array({"schema_version", "defaults", "entries"})},
                         {"fields",
                          json{{"schema_version", "uint32"},
                               {"defaults", "object"},
                               {"entries", "array<object>"}}}};
  schema["defaults_fields"] = json{{"language_origin", json::array({"c", "cpp", "rust", "binary"})},
                                    {"annotation_origin",
                                     json::array({"attribute", "pragma", "proc_macro", "external_manifest"})},
                                    {"protection_domain", json::array({"native", "vm1", "vm2"})},
                                    {"jit_policy", json::array({"off", "hot_only", "aggressive"})},
                                    {"plaintext_budget", json::array({"none", "transient_only"})},
                                    {"reaction_policy",
                                     json::array({"log",
                                                  "degrade",
                                                  "decoy_terminate",
                                                  "audit_only",
                                                  "audit_then_delayed_exit"})},
                                    {"integrity_level", json::array({"none", "basic", "strict"})},
                                    {"platform_caps", platform_caps_to_json(static_cast<std::uint32_t>(PlatformCaps::Windows) |
                                                                             PlatformCaps::Linux |
                                                                             PlatformCaps::Android |
                                                                             PlatformCaps::Ios |
                                                                             PlatformCaps::X86 |
                                                                             PlatformCaps::X64 |
                                                                             PlatformCaps::Arm |
                                                                             PlatformCaps::Arm64 |
                                                                             PlatformCaps::JitAllowed |
                                                                             PlatformCaps::ExecmemAllowed |
                                                                             PlatformCaps::WxEnforced)},
                                    {"sensitivity_level",
                                     json::array({"normal", "sensitive", "highly_sensitive"})},
                                    {"profile_seed", "uint64"},
                                    {"mobile_bridge_mode",
                                     json::array({"off", "android_jni", "ios_swift_objc", "both"})},
                                    {"event_types", "array<string>"}};
  schema["entry_fields"] = json{{"symbol_or_region", "string"},
                                 {"source_location",
                                  json{{"file", "string"}, {"line", "uint32"}, {"column", "uint32"}}},
                                 {"annotation_tags", json::array({"vm_func", "vm_string"})},
                                 {"event_types", "array<string>"}};
  schema["notes"] = json::array({"entries inherit missing scalar fields from defaults during load",
                                   "annotation_tags and event_types are semantic helper fields used by validators"});
  return schema.dump(2) + "\n";
}

void dump_schema(std::ostream& out) { out << schema_as_json(); }

}  // namespace vmp::policy
