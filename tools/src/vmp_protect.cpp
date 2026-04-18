#include <iostream>
#include <string>
#include <vector>

#include <vmp/policy/policy_ir.h>

namespace {

struct Options {
  std::string policy_path;
  std::string emit_policy_json_path;
  bool dump_schema = false;
  bool validate_only = false;
};

int usage(const char* argv0, const std::string& message = {}) {
  if (!message.empty()) {
    std::cerr << "error: " << message << '\n';
  }
  std::cerr << "usage: " << argv0
            << " [--dump-schema] [--policy <path>] [--emit-policy-json <path>] [--validate-only]"
            << std::endl;
  return 1;
}

Options parse_args(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--policy") {
      if (i + 1 >= argc) {
        throw std::runtime_error("--policy requires a path");
      }
      options.policy_path = argv[++i];
    } else if (arg == "--emit-policy-json") {
      if (i + 1 >= argc) {
        throw std::runtime_error("--emit-policy-json requires a path");
      }
      options.emit_policy_json_path = argv[++i];
    } else if (arg == "--dump-schema") {
      options.dump_schema = true;
    } else if (arg == "--validate-only") {
      options.validate_only = true;
    } else {
      throw std::runtime_error("unknown argument: " + arg);
    }
  }
  return options;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const Options options = parse_args(argc, argv);

    if (options.dump_schema) {
      vmp::policy::dump_schema(std::cout);
      if (options.policy_path.empty()) {
        return 0;
      }
    }

    if (options.policy_path.empty()) {
      std::cout << "NOT_IMPLEMENTED" << std::endl;
      return 0;
    }

    const auto policy_ir = vmp::policy::load_from_file(options.policy_path);
    const auto validation = vmp::policy::validate(policy_ir);

    bool has_error = false;
    for (const auto& item : validation) {
      std::ostream& out = item.is_error() ? std::cerr : std::cout;
      out << vmp::policy::format_validation_error(item) << '\n';
      has_error = has_error || item.is_error();
    }
    if (has_error) {
      return 2;
    }

    if (!options.emit_policy_json_path.empty()) {
      vmp::policy::save_to_file(policy_ir, options.emit_policy_json_path);
    }

    if (options.validate_only) {
      std::cout << "OK: policy loaded, " << policy_ir.entries.size() << " entries, schema=v"
                << policy_ir.schema_version << std::endl;
      return 0;
    }

    if (options.emit_policy_json_path.empty()) {
      std::cout << "OK: policy loaded, " << policy_ir.entries.size() << " entries, schema=v"
                << policy_ir.schema_version << std::endl;
      return 0;
    }

    return 0;
  } catch (const std::exception& ex) {
    return usage(argv[0], ex.what());
  }
}
