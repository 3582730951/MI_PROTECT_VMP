#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <vmp/backend/rewriter_backend.h>
#include <vmp/policy/policy_ir.h>
#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/audit/detector.h>
#include <vmp/runtime/audit/reaction.h>
#include <vmp/runtime/state/profile.h>
#include <vmp/runtime/state/state.h>

#include "string_protect_common.h"

namespace {

struct Options {
  std::string policy_path;
  std::string rust_target_dir;
  std::string emit_policy_json_path;
  std::string input_path;
  std::string output_path;
  bool dump_schema = false;
  bool validate_only = false;
  bool detector_selftest = false;
  bool protect_strings = false;
  std::string profile_out_path;
  std::string platform = VMP_PLATFORM_STR;
  std::string string_bin = "string_pool.bin";
  std::string string_idx = "string_pool.idx.json";
  std::string string_kdf = "key_derivation.json";
  std::string vm1_module;
  std::string vm2_module;
  bool lift = false;
};

struct RustTsvRecord {
  std::string crate_name;
  std::string kind;
  std::string path;
  std::string span_file;
  std::uint32_t span_line = 0;
  std::vector<std::string> extra_tags;
};

int usage(const char* argv0, const std::string& message = {}) {
  if (!message.empty()) {
    std::cerr << "error: " << message << '\n';
  }
  std::cerr << "usage: " << argv0
            << " [--dump-schema] [--policy <path>] [--rust-target-dir <dir>] [--emit-policy-json <path>] [--validate-only]"
            << " [--detector-selftest] [--platform <linux|windows|android|ios|macos>]"
            << " [--protect-strings --string-bin <bin> --string-idx <idx> --string-kdf <kdf>]"
            << " [--profile-out <path>]"
            << " [--input <path> --output <path> [--lift] [--strings-pool <bin> --strings-idx <json>] [--vm1-module <module.vm1>] [--vm2-module <module.vm2>]]"
            << std::endl;
  return 1;
}

Options parse_args(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--policy") {
      options.policy_path = argv[++i];
    } else if (arg == "--rust-target-dir") {
      options.rust_target_dir = argv[++i];
    } else if (arg == "--emit-policy-json") {
      options.emit_policy_json_path = argv[++i];
    } else if (arg == "--dump-schema") {
      options.dump_schema = true;
    } else if (arg == "--validate-only") {
      options.validate_only = true;
    } else if (arg == "--detector-selftest") {
      options.detector_selftest = true;
    } else if (arg == "--protect-strings") {
      options.protect_strings = true;
    } else if (arg == "--platform") {
      options.platform = argv[++i];
    } else if (arg == "--profile-out") {
      options.profile_out_path = argv[++i];
    } else if (arg == "--string-bin") {
      options.string_bin = argv[++i];
    } else if (arg == "--string-idx") {
      options.string_idx = argv[++i];
    } else if (arg == "--string-kdf") {
      options.string_kdf = argv[++i];
    } else if (arg == "--input") {
      options.input_path = argv[++i];
    } else if (arg == "--output") {
      options.output_path = argv[++i];
    } else if (arg == "--strings-pool") {
      options.string_bin = argv[++i];
    } else if (arg == "--strings-idx") {
      options.string_idx = argv[++i];
    } else if (arg == "--vm1-module") {
      options.vm1_module = argv[++i];
    } else if (arg == "--vm2-module") {
      options.vm2_module = argv[++i];
    } else if (arg == "--lift") {
      options.lift = true;
    } else {
      throw std::runtime_error("unknown argument: " + arg);
    }
  }
  return options;
}

std::string unescape_tsv_field(const std::string& input) {
  std::string out;
  out.reserve(input.size());
  for (std::size_t i = 0; i < input.size(); ++i) {
    const char ch = input[i];
    if (ch != '\\') {
      out.push_back(ch);
      continue;
    }
    if (i + 1 >= input.size()) {
      throw std::runtime_error("trailing backslash in TSV field");
    }
    const char next = input[++i];
    switch (next) {
      case 't': out.push_back('\t'); break;
      case 'n': out.push_back('\n'); break;
      case 'r': out.push_back('\r'); break;
      case '\\': out.push_back('\\'); break;
      default: throw std::runtime_error(std::string("unsupported TSV escape: \\") + next);
    }
  }
  return out;
}

bool has_annotation_dir(const std::filesystem::path& path) {
  for (const auto& part : path) {
    const auto name = part.string();
    if (name == "vmp_annotations" || name == "vmp-annotations") {
      return true;
    }
  }
  return false;
}

std::vector<std::filesystem::path> rust_tsv_files(const std::string& root) {
  std::vector<std::filesystem::path> out;
  const std::filesystem::path base(root);
  if (!std::filesystem::exists(base)) {
    throw std::runtime_error("--rust-target-dir does not exist: " + root);
  }
  for (auto it = std::filesystem::recursive_directory_iterator(base); it != std::filesystem::recursive_directory_iterator(); ++it) {
    if (!it->is_regular_file()) {
      continue;
    }
    if (it->path().extension() == ".tsv" && has_annotation_dir(it->path())) {
      out.push_back(it->path());
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

RustTsvRecord parse_rust_tsv_line(const std::string& file, std::size_t line_no, const std::string& line) {
  std::vector<std::string> parts;
  std::stringstream ss(line);
  std::string part;
  while (std::getline(ss, part, '\t')) {
    parts.push_back(part);
  }
  if (parts.size() != 6) {
    throw std::runtime_error(file + ":" + std::to_string(line_no) + ": malformed TSV line: expected 6 columns");
  }
  RustTsvRecord rec;
  rec.crate_name = unescape_tsv_field(parts[0]);
  rec.kind = unescape_tsv_field(parts[1]);
  rec.path = unescape_tsv_field(parts[2]);
  rec.span_file = unescape_tsv_field(parts[3]);
  rec.span_line = static_cast<std::uint32_t>(std::stoul(parts[4]));
  std::stringstream tags(unescape_tsv_field(parts[5]));
  while (std::getline(tags, part, ',')) {
    if (!part.empty()) {
      rec.extra_tags.push_back(part);
    }
  }
  return rec;
}



bool valid_platform(const std::string& platform) {
  static const std::set<std::string> kValid = {"linux", "windows", "android", "ios", "macos"};
  return kValid.find(platform) != kValid.end();
}

std::vector<RustTsvRecord> collect_rust_records(const std::string& root) {
  std::set<std::tuple<std::string, std::string, std::string, std::uint32_t>> seen;
  std::vector<RustTsvRecord> out;
  for (const auto& file : rust_tsv_files(root)) {
    std::ifstream input(file);
    std::string line;
    std::size_t line_no = 0;
    while (std::getline(input, line)) {
      ++line_no;
      if (line.find_first_not_of(" \t\r\n") == std::string::npos) {
        continue;
      }
      auto rec = parse_rust_tsv_line(file.string(), line_no, line);
      const auto key = std::make_tuple(rec.crate_name, rec.kind, rec.path, rec.span_line);
      if (seen.insert(key).second) {
        out.push_back(std::move(rec));
      }
    }
  }
  return out;
}

std::optional<std::string> rust_kind_of(const vmp::policy::PolicyEntry& entry) {
  for (const auto& tag : entry.annotation_tags) {
    if (tag.rfind("rust_kind:", 0) == 0) {
      return tag.substr(std::string("rust_kind:").size());
    }
  }
  if (entry.symbol_or_region.rfind("literal::", 0) == 0) {
    return std::string("literal");
  }
  return std::nullopt;
}

vmp::policy::PolicyEntry rust_record_to_entry(const RustTsvRecord& rec) {
  vmp::policy::PolicyEntry entry;
  entry.symbol_or_region = rec.path;
  entry.language_origin = vmp::policy::LanguageOrigin::rust;
  entry.annotation_origin = vmp::policy::AnnotationOrigin::proc_macro;
  entry.source_location.file = rec.span_file;
  entry.source_location.line = rec.span_line;
  entry.annotation_tags.push_back("rust_kind:" + rec.kind);
  for (const auto& tag : rec.extra_tags) {
    if (std::find(entry.annotation_tags.begin(), entry.annotation_tags.end(), tag) == entry.annotation_tags.end()) {
      entry.annotation_tags.push_back(tag);
    }
  }
  if (std::find(rec.extra_tags.begin(), rec.extra_tags.end(), "vm_func") != rec.extra_tags.end()) {
    vmp::policy::apply_vm_func_annotation(entry);
  }
  if (std::find(rec.extra_tags.begin(), rec.extra_tags.end(), "vm_string") != rec.extra_tags.end()) {
    vmp::policy::apply_vm_string_annotation(entry);
  }
  return entry;
}

std::string merge_key_for(const vmp::policy::PolicyEntry& entry) {
  const auto kind = rust_kind_of(entry).value_or("unknown");
  return vmp::policy::to_string(entry.language_origin) + "|" + entry.symbol_or_region + "|" + kind;
}

std::string describe_entry(const vmp::policy::PolicyEntry& entry) {
  std::ostringstream oss;
  oss << "symbol=" << entry.symbol_or_region << ", kind=" << rust_kind_of(entry).value_or("unknown")
      << ", protection_domain=" << vmp::policy::to_string(entry.protection_domain)
      << ", plaintext_budget=" << vmp::policy::to_string(entry.plaintext_budget)
      << ", sensitivity_level=" << vmp::policy::to_string(entry.sensitivity_level)
      << ", file=" << entry.source_location.file << ':' << entry.source_location.line;
  return oss.str();
}

void merge_rust_entries(vmp::policy::PolicyIR& policy_ir, const std::vector<vmp::policy::PolicyEntry>& rust_entries) {
  std::map<std::string, std::size_t> existing;
  for (std::size_t i = 0; i < policy_ir.entries.size(); ++i) {
    existing.emplace(merge_key_for(policy_ir.entries[i]), i);
  }
  for (const auto& entry : rust_entries) {
    const auto key = merge_key_for(entry);
    const auto it = existing.find(key);
    if (it == existing.end()) {
      existing.emplace(key, policy_ir.entries.size());
      policy_ir.entries.push_back(entry);
      continue;
    }
    const auto& current = policy_ir.entries[it->second];
    if (!(current == entry)) {
      std::ostringstream diff;
      diff << "rust merge conflict for key " << key << '\n'
           << "  existing: " << describe_entry(current) << '\n'
           << "  incoming: " << describe_entry(entry);
      throw std::runtime_error(diff.str());
    }
  }
}

int run_detector_selftest() {
  namespace audit = vmp::runtime::audit;
  audit::AuditWriter writer(audit::AuditWriter::default_path());
  audit::ReactionDispatcher dispatcher(writer, audit::ReactionPolicy::audit_then_delayed_exit);

  std::atomic<int> exit_calls{0};
  dispatcher.set_exit_fn([&exit_calls]() noexcept { exit_calls.fetch_add(1); });
  dispatcher.set_delay_selector([]() noexcept { return std::chrono::milliseconds(1000); });
  dispatcher.set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) noexcept { fn(); });

  audit::NullDetector detector;
  detector.set_sink([&dispatcher](const audit::AnalysisEventRecord& record) {
    vmp::runtime::state::RuntimeEventPayload payload;
    payload.name = record.event_type;
    payload.note = record.context_note;
    payload.program_counter = record.program_counter;
    vmp::runtime::state::RuntimeState::instance().observe(vmp::runtime::state::RuntimeEventKind::detection_event, payload);
    dispatcher.dispatch(record);
  });
  detector.start();

  detector.fire(audit::make_event("hw_breakpoint", "selftest_hw", 0x1111, "vm_core", "sensitive_entry", 4,
                                  "x64", "linux", 4242, 101, "2026-04-18", "10:00:00"));
  detector.fire(audit::make_event("integrity_mismatch", "selftest_integrity", 0x2222, "vm_core",
                                  "checksum_guard", -8, "x64", "linux", 4242, 102, "2026-04-18",
                                  "10:00:01"));
  detector.fire(audit::make_event("unknown", "selftest_unknown", 0, "", "", 0, "x64", "linux", 4242,
                                  103, "2026-04-18", "10:00:02"));

  writer.flush();
  std::cout << "audit:ok exits_triggered=" << exit_calls.load() << std::endl;
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const Options options = parse_args(argc, argv);

    if (options.detector_selftest) {
      return run_detector_selftest();
    }

    if (options.dump_schema) {
      vmp::policy::dump_schema(std::cout);
      if (options.policy_path.empty()) {
        return 0;
      }
    }

    if (options.policy_path.empty()) {
      return usage(argv[0], "--policy is required unless --dump-schema or --detector-selftest is used");
    }

    auto raw_policy = vmp::tools::strings_tool::json::parse(vmp::tools::strings_tool::read_text(options.policy_path));
    if (raw_policy.contains("entries") && raw_policy["entries"].is_array()) {
      for (auto& entry : raw_policy["entries"]) {
        if (entry.is_object()) {
          entry.erase("string_id");
          entry.erase("value");
        }
      }
    }
    auto policy_ir = vmp::policy::load_from_string(raw_policy.dump());

    if (!options.rust_target_dir.empty()) {
      std::vector<vmp::policy::PolicyEntry> rust_entries;
      for (const auto& record : collect_rust_records(options.rust_target_dir)) {
        rust_entries.push_back(rust_record_to_entry(record));
      }
      merge_rust_entries(policy_ir, rust_entries);
    }

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
    if (!options.profile_out_path.empty()) {
      vmp::runtime::state::OfflineProfile baseline_profile;
      baseline_profile.source_seed = policy_ir.defaults.profile_seed;
      baseline_profile.meta["schema"] = "vp1";
      baseline_profile.meta["generator"] = "vmp-protect";
      baseline_profile.meta["platform"] = options.platform;
      vmp::runtime::state::save_to_file(baseline_profile, options.profile_out_path);
    }

    const bool has_rewrite = !options.input_path.empty() || !options.output_path.empty();
    if (has_rewrite && (options.input_path.empty() || options.output_path.empty())) {
      return usage(argv[0], "--input and --output must be provided together");
    }

    if (options.validate_only && !options.protect_strings && !has_rewrite) {
      std::cout << "OK: policy loaded, " << policy_ir.entries.size() << " entries, schema=v"
                << policy_ir.schema_version << std::endl;
      return 0;
    }

    std::size_t protected_count = 0;
    if (options.protect_strings && !has_rewrite) {
      auto master_key = vmp::tools::strings_tool::resolve_master_key();
      const auto outputs = vmp::tools::strings_tool::protect_policy_strings(options.policy_path, options.string_bin,
                                                                            options.string_idx, options.string_kdf,
                                                                            master_key);
      vmp::runtime::strings::secure_memzero(master_key.data(), master_key.size());
      protected_count = outputs.protected_count;
    }

    if (has_rewrite) {
      vmp::backend::rewriter::BinaryRewriter rewriter;
      vmp::backend::rewriter::RewriteOptions rewrite_options;
      rewrite_options.strings_pool_path = options.string_bin;
      rewrite_options.strings_index_path = options.string_idx;
      rewrite_options.strings_kdf_path = options.string_kdf;
      rewrite_options.vm1_module_path = options.vm1_module;
      rewrite_options.vm2_module_path = options.vm2_module;
      rewrite_options.enable_lift = options.lift;
      const auto container = rewriter.load(options.input_path);
      const auto rewritten = rewriter.apply(container, policy_ir, rewrite_options);
      rewriter.write(rewritten, options.output_path);
      std::cout << "OK: policy loaded, " << policy_ir.entries.size() << " entries, schema=v" << policy_ir.schema_version
                << " format=" << vmp::backend::rewriter::to_string(vmp::backend::rewriter::kind_of(rewritten))
                << " rewritten=" << options.output_path << std::endl;
      return 0;
    }

    std::cout << "OK: policy loaded, " << policy_ir.entries.size() << " entries, schema=v" << policy_ir.schema_version;
    if (options.protect_strings) {
      std::cout << " strings:protected=" << protected_count;
    }
    std::cout << std::endl;
    return 0;
  } catch (const std::exception& ex) {
    const std::string message = ex.what();
    if (message.find("binary_format_unknown") != std::string::npos) {
      std::cerr << message << std::endl;
      return 2;
    }
    return usage(argv[0], message);
  }
}
