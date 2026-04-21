#include <vmp/runtime/obfuscation/mba.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <vmp/runtime/obfuscation/bogus_flow.h>
#include <vmp/runtime/obfuscation/opaque.h>

namespace vmp::runtime::obfuscation {
namespace {

struct TempRegisters {
  int one = -1;
  int work0 = -1;
  int work1 = -1;

  [[nodiscard]] bool valid() const noexcept { return one >= 0 && work0 >= 0 && work1 >= 0; }
};

std::string trim(std::string_view value) {
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
    value.remove_prefix(1);
  }
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
    value.remove_suffix(1);
  }
  return std::string(value);
}

std::string strip_comment(std::string_view line) {
  const auto hash = line.find('#');
  const auto semi = line.find(';');
  const auto slash = line.find("//");
  auto cut = std::string_view::npos;
  if (hash != std::string_view::npos) cut = hash;
  if (semi != std::string_view::npos) cut = std::min(cut, semi);
  if (slash != std::string_view::npos) cut = std::min(cut, slash);
  return trim(cut == std::string_view::npos ? line : line.substr(0, cut));
}

std::vector<std::string> split_operands(std::string_view text) {
  std::vector<std::string> out;
  std::string current;
  int bracket_depth = 0;
  bool in_string = false;
  for (char ch : text) {
    if (ch == '"') {
      in_string = !in_string;
      current.push_back(ch);
      continue;
    }
    if (!in_string) {
      if (ch == '[') ++bracket_depth;
      if (ch == ']') --bracket_depth;
      if (ch == ',' && bracket_depth == 0) {
        out.push_back(trim(current));
        current.clear();
        continue;
      }
    }
    current.push_back(ch);
  }
  if (!current.empty()) {
    out.push_back(trim(current));
  }
  return out;
}

std::pair<std::vector<std::string>, std::string> extract_labels_and_body(const std::string& raw_line) {
  std::vector<std::string> labels;
  auto line = trim(raw_line);
  while (!line.empty()) {
    const auto colon = line.find(':');
    if (colon == std::string::npos) {
      break;
    }
    const auto candidate = trim(std::string_view(line).substr(0, colon));
    if (candidate.empty() || candidate.find_first_of(" \t") != std::string::npos) {
      break;
    }
    labels.push_back(candidate);
    line = trim(std::string_view(line).substr(colon + 1));
  }
  return {labels, line};
}

std::string join_lines(const std::vector<std::string>& lines) {
  std::ostringstream oss;
  for (const auto& line : lines) {
    oss << line << '\n';
  }
  return oss.str();
}

std::string hex_u64(std::uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::nouppercase << value;
  return oss.str();
}

std::uint64_t parse_u64_text(const std::string& text) {
  std::size_t idx = 0;
  int base = 10;
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    base = 16;
  } else if (text.size() > 3 && text[0] == '-' && text[1] == '0' && (text[2] == 'x' || text[2] == 'X')) {
    base = 16;
  }
  if (!text.empty() && text[0] == '-') {
    const auto signed_value = std::stoll(text, &idx, base);
    if (idx != text.size()) {
      throw std::runtime_error("obfuscation: invalid integer '" + text + "'");
    }
    return static_cast<std::uint64_t>(signed_value);
  }
  const auto unsigned_value = std::stoull(text, &idx, base);
  if (idx != text.size()) {
    throw std::runtime_error("obfuscation: invalid integer '" + text + "'");
  }
  return static_cast<std::uint64_t>(unsigned_value);
}

std::uint64_t mix_u64(std::uint64_t value) {
  value += 0x9e3779b97f4a7c15ull;
  value = (value ^ (value >> 30u)) * 0xbf58476d1ce4e5b9ull;
  value = (value ^ (value >> 27u)) * 0x94d049bb133111ebull;
  return value ^ (value >> 31u);
}

std::pair<std::uint64_t, std::uint64_t> split_constant_add(std::uint64_t value, std::uint64_t salt) {
  const auto lhs = mix_u64(value ^ salt ^ 0x6d62615f636f6e73ull);
  const auto rhs = value - lhs;
  return {lhs, rhs};
}

TempRegisters pick_vm1_temps(std::string_view source) {
  std::set<int> used;
  std::istringstream input{std::string(source)};
  std::string line;
  while (std::getline(input, line)) {
    const auto stripped = strip_comment(line);
    for (std::size_t i = 0; i < stripped.size(); ++i) {
      if (stripped.compare(i, 2, "vr") != 0 || (i > 0 && std::isalnum(static_cast<unsigned char>(stripped[i - 1])))) {
        continue;
      }
      std::size_t j = i + 2;
      while (j < stripped.size() && std::isdigit(static_cast<unsigned char>(stripped[j]))) {
        ++j;
      }
      if (j == i + 2) {
        continue;
      }
      used.insert(std::stoi(stripped.substr(i + 2, j - i - 2)));
      i = j - 1;
    }
  }
  std::vector<int> free_regs;
  for (int reg = 31; reg >= 0; --reg) {
    if (used.find(reg) == used.end()) {
      free_regs.push_back(reg);
    }
  }
  if (free_regs.size() < 3u) {
    return {};
  }
  return TempRegisters{free_regs[0], free_regs[1], free_regs[2]};
}

TempRegisters pick_vm2_temps(std::string_view source) {
  std::set<int> used;
  std::istringstream input{std::string(source)};
  std::string line;
  while (std::getline(input, line)) {
    const auto stripped = strip_comment(line);
    for (std::size_t i = 0; i < stripped.size(); ++i) {
      if (stripped[i] != 'r' || (i > 0 && std::isalnum(static_cast<unsigned char>(stripped[i - 1])))) {
        continue;
      }
      std::size_t j = i + 1;
      while (j < stripped.size() && std::isdigit(static_cast<unsigned char>(stripped[j]))) {
        ++j;
      }
      if (j == i + 1) {
        continue;
      }
      used.insert(std::stoi(stripped.substr(i + 1, j - i - 1)));
      i = j - 1;
    }
  }
  std::vector<int> free_regs;
  for (int reg = 31; reg >= 0; --reg) {
    if (used.find(reg) == used.end()) {
      free_regs.push_back(reg);
    }
  }
  if (free_regs.size() < 3u) {
    return {};
  }
  return TempRegisters{free_regs[0], free_regs[1], free_regs[2]};
}

std::string vm1_reg(int index) {
  return "vr" + std::to_string(index);
}

std::string vm2_reg(int index) {
  return "r" + std::to_string(index);
}

void emit_vm1_add_recursive(std::vector<std::string>& out,
                            const std::string& dst,
                            const std::string& lhs,
                            const std::string& rhs,
                            const std::string& work,
                            const std::string& spare,
                            const std::string& one,
                            unsigned depth) {
  if (depth <= 1u) {
    out.push_back("add " + dst + ", " + lhs + ", " + rhs);
    return;
  }
  out.push_back("and " + work + ", " + lhs + ", " + rhs);
  out.push_back("xor " + dst + ", " + lhs + ", " + rhs);
  out.push_back("shl " + work + ", " + work + ", " + one);
  emit_vm1_add_recursive(out, dst, dst, work, spare, work, one, depth - 1u);
}

void emit_vm1_sub_recursive(std::vector<std::string>& out,
                            const std::string& dst,
                            const std::string& lhs,
                            const std::string& rhs,
                            const std::string& work,
                            const std::string& spare,
                            const std::string& one,
                            unsigned depth) {
  if (depth <= 1u) {
    out.push_back("sub " + dst + ", " + lhs + ", " + rhs);
    return;
  }
  out.push_back("not " + work + ", " + lhs);
  out.push_back("and " + work + ", " + work + ", " + rhs);
  out.push_back("xor " + dst + ", " + lhs + ", " + rhs);
  out.push_back("shl " + work + ", " + work + ", " + one);
  emit_vm1_sub_recursive(out, dst, dst, work, spare, work, one, depth - 1u);
}

void emit_vm2_add_recursive(std::vector<std::string>& out,
                            const std::string& dst,
                            const std::string& lhs,
                            const std::string& rhs,
                            const std::string& work,
                            const std::string& spare,
                            const std::string& one,
                            unsigned depth) {
  if (depth <= 1u) {
    out.push_back("iadd " + dst + ", " + lhs + ", " + rhs);
    return;
  }
  out.push_back("iand " + work + ", " + lhs + ", " + rhs);
  out.push_back("ixor " + dst + ", " + lhs + ", " + rhs);
  out.push_back("ishl " + work + ", " + work + ", " + one);
  emit_vm2_add_recursive(out, dst, dst, work, spare, work, one, depth - 1u);
}

void emit_vm2_sub_recursive(std::vector<std::string>& out,
                            const std::string& dst,
                            const std::string& lhs,
                            const std::string& rhs,
                            const std::string& work,
                            const std::string& spare,
                            const std::string& one,
                            unsigned depth) {
  if (depth <= 1u) {
    out.push_back("isub " + dst + ", " + lhs + ", " + rhs);
    return;
  }
  out.push_back("inot " + work + ", " + lhs);
  out.push_back("iand " + work + ", " + work + ", " + rhs);
  out.push_back("ixor " + dst + ", " + lhs + ", " + rhs);
  out.push_back("ishl " + work + ", " + work + ", " + one);
  emit_vm2_sub_recursive(out, dst, dst, work, spare, work, one, depth - 1u);
}

void emit_vm1_opaque_guard(std::vector<std::string>& out,
                           const std::string& seed_reg,
                           const TempRegisters& temps,
                           std::size_t opaque_index) {
  const auto real_label = "__vmp_vm1_opaque_real_" + std::to_string(opaque_index);
  const auto dead_imm = hex_u64(opaque_handler_mix(0x56314d31ull ^ opaque_index, 0x0f0a5510ull));
  const auto one = vm1_reg(temps.one);
  const auto t0 = vm1_reg(temps.work0);
  const auto t1 = vm1_reg(temps.work1);
  out.push_back("mov " + t0 + ", " + seed_reg);
  out.push_back("add " + t1 + ", " + t0 + ", " + one);
  out.push_back("mul " + t0 + ", " + t0 + ", " + t1);
  out.push_back("and " + t0 + ", " + t0 + ", " + one);
  out.push_back("xor " + t1 + ", " + t1 + ", " + t1);
  out.push_back("jeq " + t0 + ", " + t1 + ", @" + real_label);
  out.push_back("ldi_u64 " + t1 + ", " + dead_imm);
  out.push_back("xor " + t0 + ", " + t0 + ", " + t1);
  out.push_back("sub " + t0 + ", " + t0 + ", " + one);
  out.push_back(real_label + ":");
}

void emit_vm2_opaque_guard(std::vector<std::string>& out,
                           const std::string& seed_reg,
                           const TempRegisters& temps,
                           std::size_t opaque_index) {
  const auto real_label = "__vmp_vm2_opaque_real_" + std::to_string(opaque_index);
  const auto dead_imm = hex_u64(opaque_handler_mix(0x56324d32ull ^ opaque_index, 0x00faced1ull));
  const auto one = vm2_reg(temps.one);
  const auto t0 = vm2_reg(temps.work0);
  const auto t1 = vm2_reg(temps.work1);
  out.push_back("imov " + t0 + ", " + seed_reg);
  out.push_back("iadd " + t1 + ", " + t0 + ", " + one);
  out.push_back("imul " + t0 + ", " + t0 + ", " + t1);
  out.push_back("iand " + t0 + ", " + t0 + ", " + one);
  out.push_back("ixor " + t1 + ", " + t1 + ", " + t1);
  out.push_back("icmp " + t0 + ", " + t1);
  out.push_back("jp p0, @" + real_label);
  out.push_back("ildimm " + t1 + ", " + dead_imm);
  out.push_back("ixor " + t0 + ", " + t0 + ", " + t1);
  out.push_back("isub " + t0 + ", " + t0 + ", " + one);
  out.push_back(real_label + ":");
}

std::vector<std::string> rewrite_vm1_body(const std::string& body,
                                          const TempRegisters& temps,
                                          unsigned depth,
                                          bool inject_opaque_predicates,
                                          std::size_t& opaque_index,
                                          std::uint64_t& salt_counter,
                                          std::size_t& bogus_candidate_index,
                                          std::size_t bogus_selection_phase) {
  const auto space = body.find_first_of(" \t");
  const auto op = space == std::string::npos ? body : trim(std::string_view(body).substr(0, space));
  const auto operands = space == std::string::npos ? std::vector<std::string>{}
                                                   : split_operands(trim(std::string_view(body).substr(space + 1)));
  const auto one = vm1_reg(temps.one);
  const auto t0 = vm1_reg(temps.work0);
  const auto t1 = vm1_reg(temps.work1);

  auto finalize = [&](const std::vector<std::string>& real_body,
                      const std::string& seed_reg,
                      bool candidate) -> std::vector<std::string> {
    if (!inject_opaque_predicates) {
      return real_body;
    }
    if (candidate) {
      const auto site_index = bogus_candidate_index++;
      if (bogus_flow_should_inject(site_index, bogus_selection_phase)) {
        return inject_vm1_bogus_flow(op,
                                     operands,
                                     real_body,
                                     BogusFlowSiteConfig{seed_reg, one, t0, t1, site_index});
      }
    }
    std::vector<std::string> out;
    emit_vm1_opaque_guard(out, seed_reg, temps, opaque_index++);
    out.insert(out.end(), real_body.begin(), real_body.end());
    return out;
  };

  if ((op == "ldi_u64" || op == "ldi64") && operands.size() == 2u) {
    std::vector<std::string> real_body;
    const auto imm = parse_u64_text(operands[1]);
    const auto parts = split_constant_add(imm, ++salt_counter);
    real_body.push_back("ldi_u64 " + operands[0] + ", " + hex_u64(parts.first));
    real_body.push_back("ldi_u64 " + t0 + ", " + hex_u64(parts.second));
    emit_vm1_add_recursive(real_body, operands[0], operands[0], t0, t1, t0, one, std::max(2u, depth));
    return finalize(real_body, operands[0], true);
  }

  if ((op == "add" || op == "sub") && operands.size() == 3u) {
    std::vector<std::string> real_body;
    if (op == "add") {
      emit_vm1_add_recursive(real_body, operands[0], operands[1], operands[2], t0, t1, one, std::max(2u, depth));
    } else {
      emit_vm1_sub_recursive(real_body, operands[0], operands[1], operands[2], t0, t1, one, std::max(2u, depth));
    }
    return finalize(real_body, operands[1], true);
  }

  std::vector<std::string> out;
  out.push_back(body);
  return out;
}

std::vector<std::string> rewrite_vm2_body(const std::string& body,
                                          const TempRegisters& temps,
                                          unsigned depth,
                                          bool inject_opaque_predicates,
                                          std::size_t& opaque_index,
                                          std::uint64_t& salt_counter,
                                          std::size_t& bogus_candidate_index,
                                          std::size_t bogus_selection_phase) {
  const auto space = body.find_first_of(" \t");
  const auto op = space == std::string::npos ? body : trim(std::string_view(body).substr(0, space));
  const auto operands = space == std::string::npos ? std::vector<std::string>{}
                                                   : split_operands(trim(std::string_view(body).substr(space + 1)));
  const auto one = vm2_reg(temps.one);
  const auto t0 = vm2_reg(temps.work0);
  const auto t1 = vm2_reg(temps.work1);

  auto finalize = [&](const std::vector<std::string>& real_body,
                      const std::string& seed_reg,
                      bool candidate) -> std::vector<std::string> {
    if (!inject_opaque_predicates) {
      return real_body;
    }
    if (candidate) {
      const auto site_index = bogus_candidate_index++;
      if (bogus_flow_should_inject(site_index, bogus_selection_phase)) {
        return inject_vm2_bogus_flow(op,
                                     operands,
                                     real_body,
                                     BogusFlowSiteConfig{seed_reg, one, t0, t1, site_index});
      }
    }
    std::vector<std::string> out;
    emit_vm2_opaque_guard(out, seed_reg, temps, opaque_index++);
    out.insert(out.end(), real_body.begin(), real_body.end());
    return out;
  };

  if (op == "ildimm" && operands.size() == 2u) {
    std::vector<std::string> real_body;
    const auto imm = parse_u64_text(operands[1]);
    const auto parts = split_constant_add(imm, ++salt_counter);
    real_body.push_back("ildimm " + operands[0] + ", " + hex_u64(parts.first));
    real_body.push_back("ildimm " + t0 + ", " + hex_u64(parts.second));
    emit_vm2_add_recursive(real_body, operands[0], operands[0], t0, t1, t0, one, std::max(2u, depth));
    return finalize(real_body, operands[0], true);
  }

  if ((op == "iadd" || op == "isub") && operands.size() == 3u) {
    std::vector<std::string> real_body;
    if (op == "iadd") {
      emit_vm2_add_recursive(real_body, operands[0], operands[1], operands[2], t0, t1, one, std::max(2u, depth));
    } else {
      emit_vm2_sub_recursive(real_body, operands[0], operands[1], operands[2], t0, t1, one, std::max(2u, depth));
    }
    return finalize(real_body, operands[1], true);
  }

  std::vector<std::string> out;
  out.push_back(body);
  return out;
}

template <typename Rewriter, typename RegName>
std::string rewrite_program(std::string_view source,
                            const TempRegisters& temps,
                            Rewriter rewriter,
                            RegName reg_name) {
  if (!temps.valid()) {
    return std::string(source);
  }

  std::istringstream input{std::string(source)};
  std::vector<std::string> out;
  std::string raw_line;
  std::size_t opaque_index = 0;
  std::size_t bogus_candidate_index = 0;
  const auto bogus_selection_phase = bogus_flow_selection_phase(source);
  std::uint64_t salt_counter = 0;
  bool has_entry_label = false;

  {
    std::istringstream scan{std::string(source)};
    std::string scan_line;
    while (std::getline(scan, scan_line)) {
      const auto [labels, body] = extract_labels_and_body(strip_comment(scan_line));
      (void)body;
      if (std::find(labels.begin(), labels.end(), "entry") != labels.end()) {
        has_entry_label = true;
        break;
      }
    }
  }

  bool inserted_init = false;
  if (!has_entry_label) {
    out.push_back(reg_name(temps.one) + ", 1");
  }

  while (std::getline(input, raw_line)) {
    const auto stripped = strip_comment(raw_line);
    if (stripped.empty()) {
      continue;
    }
    auto [labels, body] = extract_labels_and_body(stripped);
    for (const auto& label : labels) {
      out.push_back(label + ":");
    }
    if (!inserted_init && std::find(labels.begin(), labels.end(), "entry") != labels.end()) {
      out.push_back(reg_name(temps.one) + ", 1");
      inserted_init = true;
    }
    if (body.empty()) {
      continue;
    }
    const auto rewritten = rewriter(body, opaque_index, salt_counter, bogus_candidate_index, bogus_selection_phase);
    out.insert(out.end(), rewritten.begin(), rewritten.end());
  }

  return join_lines(out);
}

}  // namespace

std::string obfuscate_vm1_assembly(std::string_view source, unsigned depth, bool inject_opaque_predicates) {
  const auto temps = pick_vm1_temps(source);
  if (!temps.valid()) {
    return std::string(source);
  }
  return rewrite_program(
      source,
      temps,
      [&](const std::string& body,
          std::size_t& opaque_index,
          std::uint64_t& salt_counter,
          std::size_t& bogus_candidate_index,
          std::size_t bogus_selection_phase) {
        return rewrite_vm1_body(body,
                                temps,
                                depth,
                                inject_opaque_predicates,
                                opaque_index,
                                salt_counter,
                                bogus_candidate_index,
                                bogus_selection_phase);
      },
      [&](int one_reg) { return "ldi_u64 " + vm1_reg(one_reg); });
}

std::string obfuscate_vm2_assembly(std::string_view source, unsigned depth, bool inject_opaque_predicates) {
  const auto temps = pick_vm2_temps(source);
  if (!temps.valid()) {
    return std::string(source);
  }
  return rewrite_program(
      source,
      temps,
      [&](const std::string& body,
          std::size_t& opaque_index,
          std::uint64_t& salt_counter,
          std::size_t& bogus_candidate_index,
          std::size_t bogus_selection_phase) {
        return rewrite_vm2_body(body,
                                temps,
                                depth,
                                inject_opaque_predicates,
                                opaque_index,
                                salt_counter,
                                bogus_candidate_index,
                                bogus_selection_phase);
      },
      [&](int one_reg) { return "ildimm " + vm2_reg(one_reg); });
}

}  // namespace vmp::runtime::obfuscation
