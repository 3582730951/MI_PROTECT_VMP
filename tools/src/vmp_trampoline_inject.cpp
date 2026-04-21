#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <vmp/backend/rewriter_backend.h>
#include <vmp/policy/policy_ir.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/obfstr.h>

namespace {

struct Options {
  std::string policy_path;
  std::string input_path;
  std::string output_path;
  std::string dispatcher_symbol = vmp::runtime::strings::obf::decode(VMP_OBFSTR("vmp_dispatch_token_sysv2"));
  std::string key_context_hex;
};

int usage(const char* argv0, const std::string& message = {}) {
  if (!message.empty()) {
    std::cerr << "error: " << message << '\n';
  }
  std::cerr << "usage: " << argv0
            << " --policy <path> --input <path> --output <path>"
            << " [--dispatcher-symbol <symbol>] [--key-context-id <32-hex>]"
            << std::endl;
  return 1;
}

Options parse_args(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--policy" && i + 1 < argc) {
      options.policy_path = argv[++i];
    } else if (arg == "--input" && i + 1 < argc) {
      options.input_path = argv[++i];
    } else if (arg == "--output" && i + 1 < argc) {
      options.output_path = argv[++i];
    } else if (arg == "--dispatcher-symbol" && i + 1 < argc) {
      options.dispatcher_symbol = argv[++i];
    } else if (arg == "--key-context-id" && i + 1 < argc) {
      options.key_context_hex = argv[++i];
    } else {
      throw std::runtime_error("unknown or incomplete argument: " + arg);
    }
  }
  if (options.policy_path.empty() || options.input_path.empty() || options.output_path.empty()) {
    throw std::runtime_error("--policy, --input, and --output are required");
  }
  return options;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const auto options = parse_args(argc, argv);
    auto policy = vmp::policy::load_from_file(options.policy_path);
    const auto validation = vmp::policy::validate(policy);
    for (const auto& issue : validation) {
      if (issue.is_error()) {
        throw std::runtime_error(vmp::policy::format_validation_error(issue));
      }
    }

    vmp::backend::rewriter::RewriteOptions rewrite_options;
    rewrite_options.enable_trampoline = true;
    rewrite_options.trampoline_dispatcher_symbol = options.dispatcher_symbol;
    if (!options.key_context_hex.empty()) {
      rewrite_options.trampoline_key_context_id = vmp::runtime::strings::hex_decode(options.key_context_hex);
    }

    vmp::backend::rewriter::BinaryRewriter rewriter;
    auto container = rewriter.load(options.input_path);
    auto rewritten = rewriter.apply(container, policy, rewrite_options);
    rewriter.write(rewritten, options.output_path);

    std::cout << "vmp-trampoline-inject OK input=" << options.input_path
              << " output=" << options.output_path
              << " dispatcher=" << options.dispatcher_symbol << '\n';
    return 0;
  } catch (const std::exception& ex) {
    return usage(argv[0], ex.what());
  }
}
