#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <vmp/policy/policy_ir.h>

namespace {

using vmp::policy::AnnotationOrigin;
using vmp::policy::IntegrityLevel;
using vmp::policy::JitPolicy;
using vmp::policy::LanguageOrigin;
using vmp::policy::MobileBridgeMode;
using vmp::policy::PlaintextBudget;
using vmp::policy::PolicyEntry;
using vmp::policy::PolicyIR;
using vmp::policy::ProtectionDomain;
using vmp::policy::ReactionPolicy;
using vmp::policy::SensitivityLevel;
using vmp::policy::PlatformCaps;

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

std::string read_file(const std::string& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to read " + path);
  }
  return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

bool has_error_code(const std::vector<vmp::policy::ValidationError>& errors, const std::string& code) {
  for (const auto& error : errors) {
    if (error.code == code && error.is_error()) {
      return true;
    }
  }
  return false;
}

void test_round_trip() {
  const auto original = vmp::policy::load_from_file("/workspace/vmp/tests/policy/examples/good.json");
  const auto text = vmp::policy::save_to_string(original);
  const auto round_trip = vmp::policy::load_from_string(text);
  require(original == round_trip, "round-trip serialization mismatch");
}

void test_combined_annotations() {
  PolicyEntry entry;
  entry.symbol_or_region = "combined";
  entry.language_origin = LanguageOrigin::cpp;
  entry.annotation_origin = AnnotationOrigin::attribute;
  entry.protection_domain = ProtectionDomain::native;
  entry.sensitivity_level = SensitivityLevel::normal;
  entry.plaintext_budget = PlaintextBudget::transient_only;
  vmp::policy::apply_vm_func_annotation(entry);
  vmp::policy::apply_vm_string_annotation(entry);
  require(entry.protection_domain == ProtectionDomain::vm1, "VM_func must force vm1+ execution domain");
  require(entry.sensitivity_level == SensitivityLevel::highly_sensitive,
          "VM_string must force highly_sensitive data handling");
  require(entry.annotation_tags.size() == 2, "combined annotations must preserve both tags");
}

void test_fixture(const std::string& file, bool expect_ok, const std::string& expected_error_code = {}) {
  try {
    const auto policy = vmp::policy::load_from_file(file);
    const auto errors = vmp::policy::validate(policy);
    const bool has_errors = std::any_of(errors.begin(), errors.end(), [](const auto& error) { return error.is_error(); });
    if (expect_ok) {
      require(!has_errors, "expected policy to validate: " + file);
    } else {
      require(has_error_code(errors, expected_error_code),
              "expected validation error code '" + expected_error_code + "' for " + file);
    }
  } catch (const std::exception&) {
    if (expect_ok) {
      throw;
    }
    if (!expected_error_code.empty()) {
      return;
    }
  }
}

void test_positive_and_negative_constraints() {
  test_fixture("/workspace/vmp/tests/policy/examples/good.json", true);
  test_fixture("/workspace/vmp/tests/policy/examples/good_ios_hot_only.json", true);
  test_fixture("/workspace/vmp/tests/policy/examples/bad_vm_func_native.json", false, "vm_func_native");
  test_fixture("/workspace/vmp/tests/policy/examples/bad_vm_string_sensitivity.json", false,
               "vm_string_sensitivity");
  test_fixture("/workspace/vmp/tests/policy/examples/bad_vm_string_plaintext_budget.json", false);
  test_fixture("/workspace/vmp/tests/policy/examples/bad_audit_event_type.json", false,
               "audit_then_delayed_exit_event_type");
  test_fixture("/workspace/vmp/tests/policy/examples/bad_ios_aggressive.json", false, "ios_jit_capability");
  test_fixture("/workspace/vmp/tests/policy/examples/bad_vm2_integrity.json", false, "vm2_integrity_level");
}

void test_schema_contains_expected_fields() {
  const auto schema = vmp::policy::schema_as_json();
  require(schema.find("language_origin") != std::string::npos, "schema missing language_origin");
  require(schema.find("platform_caps") != std::string::npos, "schema missing platform_caps");
  require(schema.find("audit_then_delayed_exit") != std::string::npos,
          "schema missing audit_then_delayed_exit");
}

}  // namespace

int main() {
  try {
    test_round_trip();
    test_combined_annotations();
    test_positive_and_negative_constraints();
    test_schema_contains_expected_fields();
    std::cout << "policy_cpp_test OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "policy_cpp_test failed: " << ex.what() << '\n';
    return 1;
  }
}
