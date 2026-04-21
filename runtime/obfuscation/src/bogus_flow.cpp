#include <vmp/runtime/obfuscation/bogus_flow.h>

#include <sstream>

namespace vmp::runtime::obfuscation {
namespace {

std::uint64_t mix_u64(std::uint64_t value) noexcept {
  value += 0x9e3779b97f4a7c15ull;
  value = (value ^ (value >> 30u)) * 0xbf58476d1ce4e5b9ull;
  value = (value ^ (value >> 27u)) * 0x94d049bb133111ebull;
  return value ^ (value >> 31u);
}

std::string hex_u64(std::uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::nouppercase << value;
  return oss.str();
}

std::string choose_distinct_operand(const std::vector<std::string>& operands,
                                    std::string_view avoid_a,
                                    std::string_view avoid_b,
                                    const std::string& fallback) {
  for (const auto& operand : operands) {
    if (operand != avoid_a && operand != avoid_b) {
      return operand;
    }
  }
  return fallback;
}

void emit_vm1_opaque_prefix(std::vector<std::string>& out,
                            const BogusFlowSiteConfig& config,
                            std::string_view real_label) {
  out.push_back("mov " + config.work0_reg + ", " + config.seed_reg);
  out.push_back("add " + config.work1_reg + ", " + config.work0_reg + ", " + config.one_reg);
  out.push_back("mul " + config.work0_reg + ", " + config.work0_reg + ", " + config.work1_reg);
  out.push_back("and " + config.work0_reg + ", " + config.work0_reg + ", " + config.one_reg);
  out.push_back("xor " + config.work1_reg + ", " + config.work1_reg + ", " + config.work1_reg);
  out.push_back("jeq " + config.work0_reg + ", " + config.work1_reg + ", @" + std::string(real_label));
}

void emit_vm2_opaque_prefix(std::vector<std::string>& out,
                            const BogusFlowSiteConfig& config,
                            std::string_view real_label) {
  out.push_back("imov " + config.work0_reg + ", " + config.seed_reg);
  out.push_back("iadd " + config.work1_reg + ", " + config.work0_reg + ", " + config.one_reg);
  out.push_back("imul " + config.work0_reg + ", " + config.work0_reg + ", " + config.work1_reg);
  out.push_back("iand " + config.work0_reg + ", " + config.work0_reg + ", " + config.one_reg);
  out.push_back("ixor " + config.work1_reg + ", " + config.work1_reg + ", " + config.work1_reg);
  out.push_back("icmp " + config.work0_reg + ", " + config.work1_reg);
  out.push_back("jp p0, @" + std::string(real_label));
}

std::vector<std::string> build_vm1_dead_body(std::string_view opcode,
                                             const std::vector<std::string>& operands,
                                             const BogusFlowSiteConfig& config) {
  std::vector<std::string> out;
  const auto wrong_imm = hex_u64(mix_u64(0x56314d42ull ^ config.site_index));
  if ((opcode == "ldi_u64" || opcode == "ldi64") && operands.size() == 2u) {
    const auto& dst = operands[0];
    out.push_back("ldi_u64 " + config.work0_reg + ", " + wrong_imm);
    out.push_back("add " + config.work1_reg + ", " + dst + ", " + config.one_reg);
    out.push_back("xor " + dst + ", " + config.work0_reg + ", " + config.work1_reg);
    out.push_back("sub " + dst + ", " + dst + ", " + config.one_reg);
    return out;
  }

  if (opcode == "add" && operands.size() == 3u) {
    const auto& dst = operands[0];
    const auto& lhs = operands[1];
    const auto& rhs = operands[2];
    const auto wrong_rhs = choose_distinct_operand(operands, lhs, rhs, config.work0_reg);
    out.push_back("add " + dst + ", " + lhs + ", " + wrong_rhs);
    out.push_back("xor " + config.work0_reg + ", " + dst + ", " + rhs);
    out.push_back("sub " + dst + ", " + config.work0_reg + ", " + config.one_reg);
    out.push_back("add " + config.work1_reg + ", " + dst + ", " + lhs);
    return out;
  }

  if (opcode == "sub" && operands.size() == 3u) {
    const auto& dst = operands[0];
    const auto& lhs = operands[1];
    const auto& rhs = operands[2];
    const auto wrong_lhs = choose_distinct_operand(operands, lhs, rhs, config.work0_reg);
    out.push_back("sub " + dst + ", " + wrong_lhs + ", " + rhs);
    out.push_back("xor " + config.work0_reg + ", " + lhs + ", " + dst);
    out.push_back("add " + dst + ", " + config.work0_reg + ", " + config.one_reg);
    out.push_back("sub " + config.work1_reg + ", " + dst + ", " + rhs);
    return out;
  }

  return out;
}

std::vector<std::string> build_vm2_dead_body(std::string_view opcode,
                                             const std::vector<std::string>& operands,
                                             const BogusFlowSiteConfig& config) {
  std::vector<std::string> out;
  const auto wrong_imm = hex_u64(mix_u64(0x56324d42ull ^ config.site_index));
  if (opcode == "ildimm" && operands.size() == 2u) {
    const auto& dst = operands[0];
    out.push_back("ildimm " + config.work0_reg + ", " + wrong_imm);
    out.push_back("iadd " + config.work1_reg + ", " + dst + ", " + config.one_reg);
    out.push_back("ixor " + dst + ", " + config.work0_reg + ", " + config.work1_reg);
    out.push_back("isub " + dst + ", " + dst + ", " + config.one_reg);
    return out;
  }

  if (opcode == "iadd" && operands.size() == 3u) {
    const auto& dst = operands[0];
    const auto& lhs = operands[1];
    const auto& rhs = operands[2];
    const auto wrong_rhs = choose_distinct_operand(operands, lhs, rhs, config.work0_reg);
    out.push_back("iadd " + dst + ", " + lhs + ", " + wrong_rhs);
    out.push_back("ixor " + config.work0_reg + ", " + dst + ", " + rhs);
    out.push_back("isub " + dst + ", " + config.work0_reg + ", " + config.one_reg);
    out.push_back("iadd " + config.work1_reg + ", " + dst + ", " + lhs);
    return out;
  }

  if (opcode == "isub" && operands.size() == 3u) {
    const auto& dst = operands[0];
    const auto& lhs = operands[1];
    const auto& rhs = operands[2];
    const auto wrong_lhs = choose_distinct_operand(operands, lhs, rhs, config.work0_reg);
    out.push_back("isub " + dst + ", " + wrong_lhs + ", " + rhs);
    out.push_back("ixor " + config.work0_reg + ", " + lhs + ", " + dst);
    out.push_back("iadd " + dst + ", " + config.work0_reg + ", " + config.one_reg);
    out.push_back("isub " + config.work1_reg + ", " + dst + ", " + rhs);
    return out;
  }

  return out;
}

template <typename PrefixEmitter, typename DeadBodyBuilder>
std::vector<std::string> inject_bogus_flow_impl(std::string_view opcode,
                                                const std::vector<std::string>& operands,
                                                const std::vector<std::string>& real_body,
                                                const BogusFlowSiteConfig& config,
                                                PrefixEmitter prefix_emitter,
                                                DeadBodyBuilder dead_builder,
                                                std::string_view dead_prefix,
                                                std::string_view real_prefix,
                                                std::string_view join_prefix) {
  const auto dead_label = std::string(dead_prefix) + std::to_string(config.site_index);
  const auto real_label = std::string(real_prefix) + std::to_string(config.site_index);
  const auto join_label = std::string(join_prefix) + std::to_string(config.site_index);

  std::vector<std::string> out;
  prefix_emitter(out, config, real_label);
  out.push_back(dead_label + ":");
  const auto dead_body = dead_builder(opcode, operands, config);
  out.insert(out.end(), dead_body.begin(), dead_body.end());
  out.push_back("jmp @" + join_label);
  out.push_back(real_label + ":");
  out.insert(out.end(), real_body.begin(), real_body.end());
  out.push_back(join_label + ":");
  return out;
}

}  // namespace

std::size_t bogus_flow_selection_phase(std::string_view source) noexcept {
  std::uint64_t digest = 0x424f475553464c57ull;
  for (unsigned char byte : source) {
    digest = mix_u64(digest ^ static_cast<std::uint64_t>(byte));
  }
  return static_cast<std::size_t>(digest % 5u);
}

bool bogus_flow_should_inject(std::size_t candidate_index, std::size_t selection_phase) noexcept {
  const auto slot = (candidate_index + selection_phase) % 5u;
  return slot == 1u || slot == 3u;
}

std::vector<std::string> inject_vm1_bogus_flow(std::string_view opcode,
                                               const std::vector<std::string>& operands,
                                               const std::vector<std::string>& real_body,
                                               const BogusFlowSiteConfig& config) {
  return inject_bogus_flow_impl(
      opcode,
      operands,
      real_body,
      config,
      emit_vm1_opaque_prefix,
      build_vm1_dead_body,
      "__vmp_vm1_bogus_dead_",
      "__vmp_vm1_bogus_real_",
      "__vmp_vm1_bogus_join_");
}

std::vector<std::string> inject_vm2_bogus_flow(std::string_view opcode,
                                               const std::vector<std::string>& operands,
                                               const std::vector<std::string>& real_body,
                                               const BogusFlowSiteConfig& config) {
  return inject_bogus_flow_impl(
      opcode,
      operands,
      real_body,
      config,
      emit_vm2_opaque_prefix,
      build_vm2_dead_body,
      "__vmp_vm2_bogus_dead_",
      "__vmp_vm2_bogus_real_",
      "__vmp_vm2_bogus_join_");
}

}  // namespace vmp::runtime::obfuscation
