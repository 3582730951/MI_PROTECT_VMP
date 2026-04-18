#include <vmp/arch/x64/x64.h>

#include <array>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace vmp::arch::x64 {
namespace common = vmp::arch::common;
namespace vm1 = vmp::runtime::vm1;
namespace vm2 = vmp::runtime::vm2;
namespace {

struct Operand {
  enum class Kind { reg, imm, mem } kind = Kind::reg;
  std::uint8_t reg = 0;
  std::uint8_t width = 8;
  std::int32_t disp = 0;
  std::uint64_t imm = 0;
  bool rip_relative = false;
};

struct Instruction {
  std::size_t offset = 0;
  std::size_t size = 0;
  std::string mnemonic;
  Operand dst{};
  Operand src{};
  std::uint8_t subop = 0;
  std::uint8_t jcc = 0;
  std::uint64_t target = 0;
};

constexpr std::uint8_t kTmp0 = 30;
constexpr std::uint8_t kTmp1 = 31;

std::uint8_t reg_index(int reg) {
  static constexpr std::array<std::uint8_t, 16> map{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}};
  return map[static_cast<std::size_t>(reg & 0xF)];
}

struct Decoder {
  const common::FunctionView& view;
  std::size_t off = 0;
  bool rex_w = false;
  std::uint8_t rex_r = 0;
  std::uint8_t rex_x = 0;
  std::uint8_t rex_b = 0;

  bool eof() const noexcept { return off >= view.code.size(); }
  std::uint8_t b(std::size_t i) const { return view.code.at(i); }
  std::uint8_t next() { return view.code.at(off++); }

  Instruction decode_one() {
    Instruction insn;
    insn.offset = off;
    rex_w = false; rex_r = rex_x = rex_b = 0;
    while (!eof()) {
      const auto p = b(off);
      if (p >= 0x40 && p <= 0x4F) {
        rex_w = (p & 0x8u) != 0;
        rex_r = (p >> 2) & 1u;
        rex_x = (p >> 1) & 1u;
        rex_b = p & 1u;
        ++off;
        continue;
      }
      if (p == 0x66 || p == 0x67) {
        ++off;
        continue;
      }
      break;
    }
    const auto opcode = next();
    const auto opw = rex_w ? 8u : 4u;
    auto read_imm = [&](std::size_t width) { return common::read_integer(view, off, width); };
    auto modrm_operand = [&](bool reg_is_dst) {
      const auto modrm = next();
      const std::uint8_t mod = (modrm >> 6) & 0x3u;
      const std::uint8_t reg = ((modrm >> 3) & 0x7u) | (rex_r << 3u);
      const std::uint8_t rm = (modrm & 0x7u) | (rex_b << 3u);
      Operand regop; regop.kind = Operand::Kind::reg; regop.reg = reg_index(reg); regop.width = opw;
      Operand rmop;
      if (mod == 3) {
        rmop.kind = Operand::Kind::reg;
        rmop.reg = reg_index(rm);
        rmop.width = opw;
      } else {
        rmop.kind = Operand::Kind::mem;
        rmop.width = opw;
        rmop.reg = reg_index(rm);
        if ((rm & 7u) == 4u) {
          const auto sib = next();
          const std::uint8_t base = (sib & 0x7u) | (rex_b << 3u);
          if (((sib >> 3) & 0x7u) != 4u || rex_x != 0) {
            throw std::runtime_error("x64_lifter: unsupported SIB scale/index");
          }
          rmop.reg = reg_index(base);
          if ((base & 7u) == 5u && mod == 0) {
            rmop.rip_relative = true;
            rmop.reg = 0;
            rmop.disp = static_cast<std::int32_t>(common::read_integer(view, off, 4));
            off += 4;
          }
        } else if ((rm & 7u) == 5u && mod == 0) {
          rmop.rip_relative = true;
          rmop.reg = 0;
          rmop.disp = static_cast<std::int32_t>(common::read_integer(view, off, 4));
          off += 4;
        }
        if (mod == 1) {
          rmop.disp = static_cast<std::int8_t>(next());
        } else if (mod == 2) {
          rmop.disp = static_cast<std::int32_t>(common::read_integer(view, off, 4));
          off += 4;
        }
      }
      insn.subop = reg;
      if (reg_is_dst) { insn.dst = regop; insn.src = rmop; } else { insn.dst = rmop; insn.src = regop; }
    };

    switch (opcode) {
      case 0x89: insn.mnemonic = "mov"; modrm_operand(false); break;
      case 0x8B: insn.mnemonic = "mov"; modrm_operand(true); break;
      case 0x01: insn.mnemonic = "add"; modrm_operand(false); break;
      case 0x03: insn.mnemonic = "add"; modrm_operand(true); break;
      case 0x29: insn.mnemonic = "sub"; modrm_operand(false); break;
      case 0x2B: insn.mnemonic = "sub"; modrm_operand(true); break;
      case 0x21: insn.mnemonic = "and"; modrm_operand(false); break;
      case 0x23: insn.mnemonic = "and"; modrm_operand(true); break;
      case 0x09: insn.mnemonic = "or"; modrm_operand(false); break;
      case 0x0B: insn.mnemonic = "or"; modrm_operand(true); break;
      case 0x31: insn.mnemonic = "xor"; modrm_operand(false); break;
      case 0x33: insn.mnemonic = "xor"; modrm_operand(true); break;
      case 0x39: insn.mnemonic = "cmp"; modrm_operand(false); break;
      case 0x3B: insn.mnemonic = "cmp"; modrm_operand(true); break;
      case 0xC1: {
        const auto modrm = next();
        const std::uint8_t mod = (modrm >> 6) & 0x3u;
        const std::uint8_t subop = (modrm >> 3) & 0x7u;
        const std::uint8_t rm = (modrm & 0x7u) | (rex_b << 3u);
        if (mod != 3) throw std::runtime_error("x64_lifter: only register shifts supported");
        insn.dst.kind = Operand::Kind::reg; insn.dst.reg = reg_index(rm); insn.dst.width = opw;
        insn.src.kind = Operand::Kind::imm; insn.src.width = 1; insn.src.imm = next();
        insn.subop = subop;
        insn.mnemonic = (subop == 4) ? "shl" : (subop == 5) ? "shr" : (subop == 7) ? "sar" : "badshift";
        break;
      }
      case 0x69:
      case 0x6B: {
        const auto modrm = next();
        const std::uint8_t mod = (modrm >> 6) & 0x3u;
        const std::uint8_t reg = ((modrm >> 3) & 0x7u) | (rex_r << 3u);
        const std::uint8_t rm = (modrm & 0x7u) | (rex_b << 3u);
        if (mod != 3) throw std::runtime_error("x64_lifter: imul mem unsupported");
        insn.mnemonic = "imul";
        insn.dst = Operand{Operand::Kind::reg, reg_index(reg), static_cast<std::uint8_t>(opw), 0, 0, false};
        insn.src = Operand{Operand::Kind::reg, reg_index(rm), static_cast<std::uint8_t>(opw), 0, 0, false};
        insn.subop = 0xFFu;
        insn.target = read_imm(opcode == 0x69 ? 4 : 1);
        off += opcode == 0x69 ? 4 : 1;
        break;
      }
      case 0x0F: {
        const auto ext = next();
        if (ext == 0xAF) {
          insn.mnemonic = "imul";
          modrm_operand(true);
          break;
        }
        if (ext >= 0x80 && ext <= 0x8F) {
          insn.mnemonic = "jcc";
          insn.jcc = ext & 0xFu;
          const auto rel = static_cast<std::int32_t>(read_imm(4));
          off += 4;
          insn.target = view.base_addr + off + rel;
          break;
        }
        throw std::runtime_error("x64_lifter: unsupported 0F opcode");
      }
      case 0xE9: {
        insn.mnemonic = "jmp";
        const auto rel = static_cast<std::int32_t>(read_imm(4));
        off += 4;
        insn.target = view.base_addr + off + rel;
        break;
      }
      case 0xEB: {
        insn.mnemonic = "jmp";
        const auto rel = static_cast<std::int8_t>(next());
        insn.target = view.base_addr + off + rel;
        break;
      }
      case 0xE8: {
        insn.mnemonic = "call";
        const auto rel = static_cast<std::int32_t>(read_imm(4));
        off += 4;
        insn.target = view.base_addr + off + rel;
        break;
      }
      case 0xC3: insn.mnemonic = "ret"; break;
      default:
        if (opcode >= 0x70 && opcode <= 0x7F) {
          insn.mnemonic = "jcc";
          insn.jcc = opcode & 0xFu;
          const auto rel = static_cast<std::int8_t>(next());
          insn.target = view.base_addr + off + rel;
          break;
        }
        if (opcode >= 0xB8 && opcode <= 0xBF) {
          insn.mnemonic = "mov";
          insn.dst.kind = Operand::Kind::reg;
          insn.dst.reg = reg_index((opcode - 0xB8u) | (rex_b << 3u));
          insn.dst.width = opw;
          insn.src.kind = Operand::Kind::imm;
          insn.src.width = opw;
          insn.src.imm = read_imm(opw);
          off += opw;
          break;
        }
        throw std::runtime_error("x64_lifter: unsupported opcode");
    }
    insn.size = off - insn.offset;
    return insn;
  }
};

std::string addr_label(std::uint64_t addr) {
  std::ostringstream oss;
  oss << "L_" << std::hex << addr;
  return oss.str();
}

void emit_load_operand(std::ostringstream& out, const Operand& op, std::uint8_t dst) {
  switch (op.kind) {
    case Operand::Kind::reg:
      if (dst != op.reg) out << "  mov vr" << unsigned(dst) << ", vr" << unsigned(op.reg) << "\n";
      break;
    case Operand::Kind::imm:
      out << "  ldi_u64 vr" << unsigned(dst) << ", " << op.imm << "\n";
      break;
    case Operand::Kind::mem:
      if (op.rip_relative) {
        out << "  ldi_u64 vr" << unsigned(dst) << ", " << static_cast<std::uint64_t>(static_cast<std::int64_t>(op.disp)) << "\n";
      } else if (op.reg == 4) {
        out << "  load_mem" << (unsigned(op.width) * 8u) << " vr" << unsigned(dst) << ", [sp"
            << (op.disp >= 0 ? "+" : "") << op.disp << "]\n";
      } else {
        out << "  load_mem" << (unsigned(op.width) * 8u) << " vr" << unsigned(dst) << ", [vr" << unsigned(op.reg)
            << (op.disp >= 0 ? "+" : "") << op.disp << "]\n";
      }
      break;
  }
}

void emit_store_operand(std::ostringstream& out, const Operand& op, std::uint8_t src) {
  if (op.kind == Operand::Kind::reg) {
    out << "  mov vr" << unsigned(op.reg) << ", vr" << unsigned(src) << "\n";
    return;
  }
  if (op.kind != Operand::Kind::mem || op.rip_relative) {
    throw std::runtime_error("x64_lifter: unsupported store target");
  }
  if (op.reg == 4) {
    out << "  store_mem" << (unsigned(op.width) * 8u) << " [sp" << (op.disp >= 0 ? "+" : "") << op.disp
        << "], vr" << unsigned(src) << "\n";
  } else {
    out << "  store_mem" << (unsigned(op.width) * 8u) << " [vr" << unsigned(op.reg) << (op.disp >= 0 ? "+" : "")
        << op.disp << "], vr" << unsigned(src) << "\n";
  }
}

void emit_prologue(std::ostringstream& out, common::CallingConvention cc) {
  if (cc == common::CallingConvention::sysv_x64) {
    out << "  mov vr7, vr0\n";
    out << "  mov vr6, vr1\n";
    out << "  mov vr1, vr3\n";
    out << "  mov vr8, vr4\n";
    out << "  mov vr9, vr5\n";
  } else if (cc == common::CallingConvention::msvc_x64) {
    out << "  mov vr9, vr3\n";
    out << "  mov vr8, vr2\n";
    out << "  mov vr2, vr1\n";
    out << "  mov vr1, vr0\n";
  }
}

std::string jcc_name(std::uint8_t code) {
  switch (code) {
    case 0x4: return "jeq";
    case 0x5: return "jne";
    case 0xC: return "jlt";
    case 0xE: return "jle";
    case 0xF: return "jgt";
    case 0xD: return "jge";
    default: return {};
  }
}

void carry_relocation(vm1::Vm1Module& module, const common::FunctionView& view, std::size_t offset, std::size_t width) {
  if (const auto* reloc = common::find_overlapping_relocation(view, offset, width)) {
    vm1::ConstPoolEntry entry;
    entry.kind = vm1::ConstKind::none;
    const auto payload = common::const_tag_payload(*reloc);
    entry.bytes.assign(payload.begin(), payload.end());
    module.const_pool.push_back(std::move(entry));
  }
}

void carry_relocation(vm2::Vm2Module& module, const common::FunctionView& view, std::size_t offset, std::size_t width) {
  if (const auto* reloc = common::find_overlapping_relocation(view, offset, width)) {
    vm2::Vm2ConstPoolEntry entry{};
    const auto payload = common::const_tag_payload(*reloc);
    for (std::size_t i = 0; i < payload.size() && i < entry.bytes.size(); ++i) entry.bytes[i] = static_cast<std::uint8_t>(payload[i]);
    module.const_pool.push_back(entry);
  }
}

}  // namespace

std::string X64Lifter::isa_name() const { return "x86_64"; }

bool X64Lifter::can_lift(const common::FunctionView& view) const {
  return view.endian == common::ArchEndianness::little &&
         (view.cc == common::CallingConvention::sysv_x64 || view.cc == common::CallingConvention::msvc_x64);
}

common::LiftedFunction X64Lifter::lift(const common::FunctionView& view) const {
  if (!can_lift(view)) throw std::runtime_error("x64_lifter: incompatible function view");
  common::LiftedFunction lifted;
  std::ostringstream text;
  std::unordered_map<std::uint64_t, std::string> labels;
  std::vector<Instruction> insns;
  try {
    Decoder dec{view};
    while (!dec.eof()) {
      insns.push_back(dec.decode_one());
    }
  } catch (const std::exception& ex) {
    lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode, insns.empty() ? 0 : insns.back().offset, ex.what()});
    return lifted;
  }
  for (const auto& insn : insns) {
    if (insn.mnemonic == "jmp" || insn.mnemonic == "jcc" || insn.mnemonic == "call") labels.emplace(insn.target, addr_label(insn.target));
  }
  text << "entry:\n";
  emit_prologue(text, view.cc);
  Operand last_cmp_lhs{}; Operand last_cmp_rhs{}; bool have_cmp = false;
  for (const auto& insn : insns) {
    const auto pc_addr = view.base_addr + insn.offset;
    if (const auto it = labels.find(pc_addr); it != labels.end()) text << it->second << ":\n";
    if (insn.mnemonic == "mov") {
      emit_load_operand(text, insn.src, kTmp0);
      emit_store_operand(text, insn.dst, kTmp0);
      if (insn.src.kind == Operand::Kind::imm) {
        carry_relocation(lifted.module, view, insn.offset + insn.size - insn.src.width, insn.src.width);
      }
    } else if (insn.mnemonic == "add" || insn.mnemonic == "sub" || insn.mnemonic == "and" || insn.mnemonic == "or" || insn.mnemonic == "xor") {
      emit_load_operand(text, insn.dst, kTmp0);
      emit_load_operand(text, insn.src, kTmp1);
      text << "  " << insn.mnemonic << " vr" << unsigned(kTmp0) << ", vr" << unsigned(kTmp0) << ", vr" << unsigned(kTmp1) << "\n";
      emit_store_operand(text, insn.dst, kTmp0);
    } else if (insn.mnemonic == "imul") {
      emit_load_operand(text, insn.dst, kTmp0);
      emit_load_operand(text, insn.src, kTmp1);
      text << "  mul vr" << unsigned(kTmp0) << ", vr" << unsigned(kTmp0) << ", vr" << unsigned(kTmp1) << "\n";
      if (insn.subop == 0xFFu) {
        text << "  ldi_u64 vr" << unsigned(kTmp1) << ", " << insn.target << "\n";
        text << "  mul vr" << unsigned(kTmp0) << ", vr" << unsigned(kTmp0) << ", vr" << unsigned(kTmp1) << "\n";
      }
      emit_store_operand(text, insn.dst, kTmp0);
    } else if (insn.mnemonic == "shl" || insn.mnemonic == "shr" || insn.mnemonic == "sar") {
      emit_load_operand(text, insn.dst, kTmp0);
      emit_load_operand(text, insn.src, kTmp1);
      text << "  " << insn.mnemonic << " vr" << unsigned(kTmp0) << ", vr" << unsigned(kTmp0) << ", vr" << unsigned(kTmp1) << "\n";
      emit_store_operand(text, insn.dst, kTmp0);
    } else if (insn.mnemonic == "cmp") {
      last_cmp_lhs = insn.dst;
      last_cmp_rhs = insn.src;
      have_cmp = true;
    } else if (insn.mnemonic == "jcc") {
      const auto cc_name = jcc_name(insn.jcc);
      if (!have_cmp || cc_name.empty()) {
        lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode, insn.offset, "x64_lifter: jcc without supported cmp"});
        return lifted;
      }
      emit_load_operand(text, last_cmp_lhs, kTmp0);
      emit_load_operand(text, last_cmp_rhs, kTmp1);
      text << "  " << cc_name << " vr" << unsigned(kTmp0) << ", vr" << unsigned(kTmp1) << ", @" << labels.at(insn.target) << "\n";
    } else if (insn.mnemonic == "jmp") {
      text << "  jmp @" << labels.at(insn.target) << "\n";
    } else if (insn.mnemonic == "call") {
      text << "  call @" << labels.at(insn.target) << ", 0\n";
    } else if (insn.mnemonic == "ret") {
      text << (domain_ == common::TargetDomain::vm2 ? "  bret\n" : "  ret\n");
    } else {
      lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode, insn.offset, "x64_lifter: unsupported instruction"});
      return lifted;
    }
  }
  if (domain_ == common::TargetDomain::vm2) {
    std::string vm2_text = text.str();
    auto repl = [&](const std::string& from, const std::string& to) {
      std::size_t pos = 0;
      while ((pos = vm2_text.find(from, pos)) != std::string::npos) { vm2_text.replace(pos, from.size(), to); pos += to.size(); }
    };
    repl("vr", "r");
    repl("ldi_u64", "ildimm");
    repl("mov ", "imov ");
    repl("add ", "iadd "); repl("sub ", "isub "); repl("mul ", "imul "); repl("div ", "idiv ");
    repl("and ", "iand "); repl("or ", "ior "); repl("xor ", "ixor "); repl("shl ", "ishl ");
    repl("shr ", "ishr "); repl("sar ", "isar "); repl("load_mem64", "imemld64"); repl("store_mem64", "imemst64");
    repl("ret", "bret");
    try {
      lifted.vm2_module = vm2::assemble_module_text(vm2_text);
    } catch (const std::exception& ex) {
      lifted.diagnostics.push_back({common::DiagnosticKind::malformed_instruction, 0, ex.what()});
      return lifted;
    }
    for (const auto& insn : insns) {
      if (insn.mnemonic == "mov" && insn.src.kind == Operand::Kind::imm) {
        carry_relocation(*lifted.vm2_module, view, insn.offset + insn.size - insn.src.width, insn.src.width);
      }
    }
    return lifted;
  }
  try {
    lifted.module = vm1::assemble_module_text(text.str());
  } catch (const std::exception& ex) {
    lifted.diagnostics.push_back({common::DiagnosticKind::malformed_instruction, 0, ex.what()});
    return lifted;
  }
  for (const auto& insn : insns) {
    if (insn.mnemonic == "mov" && insn.src.kind == Operand::Kind::imm) {
      carry_relocation(lifted.module, view, insn.offset + insn.size - insn.src.width, insn.src.width);
    }
  }
  return lifted;
}

const char* ArchFacade::status() const noexcept { return "x64_ready"; }

}  // namespace vmp::arch::x64
