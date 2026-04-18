#include <iostream>

#include <vmp/policy/policy_ir.h>

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: policy_cpp_summary <policy.json>\n";
    return 1;
  }
  try {
    const auto policy = vmp::policy::load_from_file(argv[1]);
    const auto& first = policy.entries.at(0);
    std::cout << "{\"schema_version\":" << policy.schema_version << ",\"entry_count\":" << policy.entries.size()
              << ",\"first\":{\"symbol_or_region\":\"" << first.symbol_or_region
              << "\",\"language_origin\":\"" << vmp::policy::to_string(first.language_origin)
              << "\",\"protection_domain\":\"" << vmp::policy::to_string(first.protection_domain)
              << "\",\"sensitivity_level\":\"" << vmp::policy::to_string(first.sensitivity_level)
              << "\",\"annotation_tags\":[";
    for (std::size_t i = 0; i < first.annotation_tags.size(); ++i) {
      if (i != 0) {
        std::cout << ',';
      }
      std::cout << '"' << first.annotation_tags[i] << '"';
    }
    std::cout << "]}}\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }
}
