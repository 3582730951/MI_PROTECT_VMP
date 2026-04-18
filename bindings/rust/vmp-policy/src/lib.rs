use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageOrigin {
    C,
    Cpp,
    Rust,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationOrigin {
    Attribute,
    Pragma,
    ProcMacro,
    ExternalManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionDomain {
    Native,
    Vm1,
    Vm2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JitPolicy {
    Off,
    HotOnly,
    Aggressive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaintextBudget {
    None,
    TransientOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactionPolicy {
    Log,
    Degrade,
    DecoyTerminate,
    AuditOnly,
    AuditThenDelayedExit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityLevel {
    None,
    Basic,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityLevel {
    Normal,
    Sensitive,
    HighlySensitive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileBridgeMode {
    Off,
    AndroidJni,
    IosSwiftObjc,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SourceLocation {
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: u32,
    #[serde(default)]
    pub column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDefaults {
    #[serde(default = "default_language_origin")]
    pub language_origin: LanguageOrigin,
    #[serde(default = "default_annotation_origin")]
    pub annotation_origin: AnnotationOrigin,
    #[serde(default = "default_protection_domain")]
    pub protection_domain: ProtectionDomain,
    #[serde(default = "default_jit_policy")]
    pub jit_policy: JitPolicy,
    #[serde(default = "default_plaintext_budget")]
    pub plaintext_budget: PlaintextBudget,
    #[serde(default = "default_reaction_policy")]
    pub reaction_policy: ReactionPolicy,
    #[serde(default = "default_integrity_level")]
    pub integrity_level: IntegrityLevel,
    #[serde(default)]
    pub platform_caps: Vec<String>,
    #[serde(default = "default_sensitivity_level")]
    pub sensitivity_level: SensitivityLevel,
    #[serde(default)]
    pub profile_seed: u64,
    #[serde(default = "default_mobile_bridge_mode")]
    pub mobile_bridge_mode: MobileBridgeMode,
    #[serde(default)]
    pub event_types: Vec<String>,
}

impl Default for PolicyDefaults {
    fn default() -> Self {
        Self {
            language_origin: default_language_origin(),
            annotation_origin: default_annotation_origin(),
            protection_domain: default_protection_domain(),
            jit_policy: default_jit_policy(),
            plaintext_budget: default_plaintext_budget(),
            reaction_policy: default_reaction_policy(),
            integrity_level: default_integrity_level(),
            platform_caps: Vec::new(),
            sensitivity_level: default_sensitivity_level(),
            profile_seed: 0,
            mobile_bridge_mode: default_mobile_bridge_mode(),
            event_types: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEntryRaw {
    pub symbol_or_region: String,
    pub language_origin: Option<LanguageOrigin>,
    pub annotation_origin: Option<AnnotationOrigin>,
    pub protection_domain: Option<ProtectionDomain>,
    pub jit_policy: Option<JitPolicy>,
    pub plaintext_budget: Option<PlaintextBudget>,
    pub reaction_policy: Option<ReactionPolicy>,
    pub integrity_level: Option<IntegrityLevel>,
    pub platform_caps: Option<Vec<String>>,
    pub sensitivity_level: Option<SensitivityLevel>,
    pub profile_seed: Option<u64>,
    pub mobile_bridge_mode: Option<MobileBridgeMode>,
    #[serde(default)]
    pub source_location: SourceLocation,
    #[serde(default)]
    pub annotation_tags: Vec<String>,
    #[serde(default)]
    pub event_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEntry {
    pub symbol_or_region: String,
    pub language_origin: LanguageOrigin,
    pub annotation_origin: AnnotationOrigin,
    pub protection_domain: ProtectionDomain,
    pub jit_policy: JitPolicy,
    pub plaintext_budget: PlaintextBudget,
    pub reaction_policy: ReactionPolicy,
    pub integrity_level: IntegrityLevel,
    pub platform_caps: Vec<String>,
    pub sensitivity_level: SensitivityLevel,
    pub profile_seed: u64,
    pub mobile_bridge_mode: MobileBridgeMode,
    pub source_location: SourceLocation,
    pub annotation_tags: Vec<String>,
    pub event_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyIRRaw {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub defaults: PolicyDefaults,
    pub entries: Vec<PolicyEntryRaw>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIR {
    pub schema_version: u32,
    pub defaults: PolicyDefaults,
    pub entries: Vec<PolicyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub severity: ValidationSeverity,
    pub code: String,
    pub entry: String,
    pub field: String,
    pub message: String,
}

fn default_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}
fn default_language_origin() -> LanguageOrigin {
    LanguageOrigin::Binary
}
fn default_annotation_origin() -> AnnotationOrigin {
    AnnotationOrigin::ExternalManifest
}
fn default_protection_domain() -> ProtectionDomain {
    ProtectionDomain::Native
}
fn default_jit_policy() -> JitPolicy {
    JitPolicy::Off
}
fn default_plaintext_budget() -> PlaintextBudget {
    PlaintextBudget::TransientOnly
}
fn default_reaction_policy() -> ReactionPolicy {
    ReactionPolicy::Log
}
fn default_integrity_level() -> IntegrityLevel {
    IntegrityLevel::None
}
fn default_sensitivity_level() -> SensitivityLevel {
    SensitivityLevel::Normal
}
fn default_mobile_bridge_mode() -> MobileBridgeMode {
    MobileBridgeMode::Off
}

impl PolicyIR {
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path_ref = path.as_ref();
        let text = fs::read_to_string(path_ref)
            .map_err(|e| format!("failed to read {}: {}", path_ref.display(), e))?;
        Self::load_from_string(&text).map_err(|e| format!("{}: {}", path_ref.display(), e))
    }

    pub fn load_from_string(text: &str) -> Result<Self, String> {
        let raw: PolicyIRRaw = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {}", e))?;
        if raw.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema_version {}, current schema_version is {}",
                raw.schema_version, CURRENT_SCHEMA_VERSION
            ));
        }
        let defaults = raw.defaults;
        let entries = raw
            .entries
            .into_iter()
            .map(|entry| PolicyEntry {
                symbol_or_region: entry.symbol_or_region,
                language_origin: entry.language_origin.unwrap_or(defaults.language_origin),
                annotation_origin: entry.annotation_origin.unwrap_or(defaults.annotation_origin),
                protection_domain: entry.protection_domain.unwrap_or(defaults.protection_domain),
                jit_policy: entry.jit_policy.unwrap_or(defaults.jit_policy),
                plaintext_budget: entry.plaintext_budget.unwrap_or(defaults.plaintext_budget),
                reaction_policy: entry.reaction_policy.unwrap_or(defaults.reaction_policy),
                integrity_level: entry.integrity_level.unwrap_or(defaults.integrity_level),
                platform_caps: entry.platform_caps.unwrap_or_else(|| defaults.platform_caps.clone()),
                sensitivity_level: entry.sensitivity_level.unwrap_or(defaults.sensitivity_level),
                profile_seed: entry.profile_seed.unwrap_or(defaults.profile_seed),
                mobile_bridge_mode: entry.mobile_bridge_mode.unwrap_or(defaults.mobile_bridge_mode),
                source_location: entry.source_location,
                annotation_tags: entry.annotation_tags,
                event_types: if entry.event_types.is_empty() {
                    defaults.event_types.clone()
                } else {
                    entry.event_types
                },
            })
            .collect();
        Ok(Self {
            schema_version: raw.schema_version,
            defaults,
            entries,
        })
    }

    pub fn validate(&self) -> Vec<ValidationError> {
        let mut out = Vec::new();
        for entry in &self.entries {
            let is_vm_func = entry.annotation_tags.iter().any(|tag| tag == "vm_func");
            let is_vm_string = entry.annotation_tags.iter().any(|tag| tag == "vm_string");

            if is_vm_func && entry.protection_domain == ProtectionDomain::Native {
                out.push(ValidationError::error(
                    entry,
                    "vm_func_native",
                    "protection_domain",
                    "VM_func entries must remain in vm1 or vm2 and cannot fall back to native",
                ));
            }
            if is_vm_string && entry.sensitivity_level != SensitivityLevel::HighlySensitive {
                out.push(ValidationError::error(
                    entry,
                    "vm_string_sensitivity",
                    "sensitivity_level",
                    "VM_string entries must use highly_sensitive sensitivity_level",
                ));
            }
            if matches!(entry.reaction_policy, ReactionPolicy::AuditThenDelayedExit)
                && !entry.event_types.iter().any(|tag| tag == "hw_breakpoint")
            {
                out.push(ValidationError::error(
                    entry,
                    "audit_then_delayed_exit_event_type",
                    "event_types",
                    "reaction_policy audit_then_delayed_exit requires event_types to contain 'hw_breakpoint'",
                ));
            }
            if entry.platform_caps.iter().any(|cap| cap == "ios")
                && !entry.platform_caps.iter().any(|cap| cap == "jit_allowed")
                && entry.jit_policy == JitPolicy::Aggressive
            {
                out.push(ValidationError::error(
                    entry,
                    "ios_jit_capability",
                    "jit_policy",
                    "iOS entries without jit_allowed must use jit_policy off or hot_only with interpreter fallback",
                ));
            }
            if entry.protection_domain == ProtectionDomain::Vm2 && entry.integrity_level != IntegrityLevel::Strict {
                out.push(ValidationError::error(
                    entry,
                    "vm2_integrity_level",
                    "integrity_level",
                    "vm2 entries must use integrity_level strict",
                ));
            }
            if entry.profile_seed == 0 {
                out.push(ValidationError::warning(
                    entry,
                    "profile_seed_zero",
                    "profile_seed",
                    "profile_seed is 0; offline/online profile correlation will be unstable",
                ));
            }
            if entry.sensitivity_level == SensitivityLevel::Normal
                && entry.plaintext_budget == PlaintextBudget::None
            {
                out.push(ValidationError::warning(
                    entry,
                    "normal_with_no_plaintext",
                    "plaintext_budget",
                    "sensitivity_level normal with plaintext_budget none is unusually strict",
                ));
            }
            if is_vm_string && !matches!(entry.plaintext_budget, PlaintextBudget::None | PlaintextBudget::TransientOnly) {
                out.push(ValidationError::error(
                    entry,
                    "vm_string_plaintext_budget",
                    "plaintext_budget",
                    "VM_string entries must use plaintext_budget none or transient_only",
                ));
            }
        }
        out
    }
}

impl ValidationError {
    fn error(entry: &PolicyEntry, code: &str, field: &str, message: &str) -> Self {
        Self {
            severity: ValidationSeverity::Error,
            code: code.to_string(),
            entry: entry.symbol_or_region.clone(),
            field: field.to_string(),
            message: message.to_string(),
        }
    }

    fn warning(entry: &PolicyEntry, code: &str, field: &str, message: &str) -> Self {
        Self {
            severity: ValidationSeverity::Warning,
            code: code.to_string(),
            entry: entry.symbol_or_region.clone(),
            field: field.to_string(),
            message: message.to_string(),
        }
    }
}

pub fn load_from_file(path: impl AsRef<Path>) -> Result<PolicyIR, String> {
    PolicyIR::load_from_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_and_validate_good_fixture() {
        let policy = PolicyIR::load_from_file("tests/policy/examples/good.json").unwrap();
        let errors = policy.validate();
        assert!(errors.iter().all(|e| e.severity == ValidationSeverity::Warning));
    }

    #[test]
    fn rejects_unknown_field() {
        let text = r#"{"schema_version":1,"defaults":{},"entries":[{"symbol_or_region":"foo","unknown":1}]}"#;
        let err = PolicyIR::load_from_string(text).unwrap_err();
        assert!(err.contains("unknown field"));
    }
}
