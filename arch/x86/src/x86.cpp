#include <vmp/arch/x86/x86.h>

#include <vmp/arch/common/label_resolver.h>

#include <array>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace vmp::arch::x86 {
namespace common = vmp::arch::common;
namespace vm1 = vmp::runtime::vm1;
namespace {

struct Operand {
  enum class Kind { reg, imm, mem } kind = Kind::reg;
  std::uint8_t reg = 0;
  std::uint8_t width = 4;
  std::int32_t disp = 0;
  std::uint64_t imm = 0;
};
struct Instruction {
  std::size_t offset = 0;
  std::size_t size = 0;
  std::string mnemonic;
  Operand dst{};
  Operand src{};
  std::uint8_t jcc = 0;
  std::uint64_t target = 0;
  std::optional<common::PcRelativeTarget> pc_relative_target;
};
constexpr std::uint8_t kTmp0 = 30;
constexpr std::uint8_t kTmp1 = 31;
std::uint8_t reg_index(int reg) { static constexpr std::array<std::uint8_t,8> map{{0,1,2,3,4,5,6,7}}; return map[reg&7]; }

common::DiagnosticKind map_resolver_kind(common::ResolverDiagnosticKind kind) {
  switch (kind) {
    case common::ResolverDiagnosticKind::out_of_range: return common::DiagnosticKind::out_of_range;
    case common::ResolverDiagnosticKind::unresolved_label: return common::DiagnosticKind::unresolved_label;
    case common::ResolverDiagnosticKind::duplicate_label: return common::DiagnosticKind::duplicate_label;
  }
  return common::DiagnosticKind::malformed_instruction;
}

struct Decoder {
  const common::FunctionView& view; std::size_t off=0;
  bool eof() const noexcept { return off >= view.code.size(); }
  std::uint8_t next() { return view.code.at(off++); }
  std::uint8_t peek() const { return view.code.at(off); }
  Instruction decode_one() {
    Instruction i; i.offset = off;
    while (!eof() && (peek()==0x66 || peek()==0x67)) ++off;
    const auto opcode = next();
    auto modrm = [&](bool reg_dst) {
      const auto mr = next();
      const auto mod=(mr>>6)&3u; const auto reg=(mr>>3)&7u; const auto rm=mr&7u;
      Operand rop{Operand::Kind::reg, reg_index(reg), 4,0,0}; Operand mop;
      if (mod==3) { mop = Operand{Operand::Kind::reg, reg_index(rm), 4,0,0}; }
      else { mop.kind=Operand::Kind::mem; mop.width=4; mop.reg=reg_index(rm); if (rm==4) throw std::runtime_error("x86_lifter: SIB unsupported"); if (mod==0 && rm==5) { mop.reg=4; mop.disp=static_cast<std::int32_t>(common::read_integer(view, off, 4)); off+=4; } else if (mod==1) mop.disp=static_cast<std::int8_t>(next()); else if (mod==2) { mop.disp=static_cast<std::int32_t>(common::read_integer(view, off,4)); off+=4; } }
      if (reg_dst) { i.dst=rop; i.src=mop; } else { i.dst=mop; i.src=rop; }
    };
    switch (opcode) {
      case 0x89: i.mnemonic="mov"; modrm(false); break;
      case 0x8B: i.mnemonic="mov"; modrm(true); break;
      case 0x01: i.mnemonic="add"; modrm(false); break;
      case 0x03: i.mnemonic="add"; modrm(true); break;
      case 0x29: i.mnemonic="sub"; modrm(false); break;
      case 0x2B: i.mnemonic="sub"; modrm(true); break;
      case 0x21: i.mnemonic="and"; modrm(false); break;
      case 0x23: i.mnemonic="and"; modrm(true); break;
      case 0x09: i.mnemonic="or"; modrm(false); break;
      case 0x0B: i.mnemonic="or"; modrm(true); break;
      case 0x31: i.mnemonic="xor"; modrm(false); break;
      case 0x33: i.mnemonic="xor"; modrm(true); break;
      case 0x39: i.mnemonic="cmp"; modrm(false); break;
      case 0x3B: i.mnemonic="cmp"; modrm(true); break;
      case 0xE8: i.mnemonic="call"; { auto rel=static_cast<std::int32_t>(common::read_integer(view,off,4)); off+=4; i.target=view.base_addr+off+rel; } break;
      case 0xE9: i.mnemonic="jmp"; { auto rel=static_cast<std::int32_t>(common::read_integer(view,off,4)); off+=4; i.target=view.base_addr+off+rel; } break;
      case 0xEB: i.mnemonic="jmp"; { auto rel=static_cast<std::int8_t>(next()); i.target=view.base_addr+off+rel; } break;
      case 0xC3: i.mnemonic="ret"; break;
      case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
        i.mnemonic="push"; i.src=Operand{Operand::Kind::reg, reg_index(opcode-0x50),4,0,0}; break;
      case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        i.mnemonic="pop"; i.dst=Operand{Operand::Kind::reg, reg_index(opcode-0x58),4,0,0}; break;
      case 0xC1: {
        const auto mr=next(); const auto mod=(mr>>6)&3u; const auto sub=(mr>>3)&7u; const auto rm=mr&7u; if(mod!=3) throw std::runtime_error("x86_lifter: shift mem unsupported");
        i.dst=Operand{Operand::Kind::reg, reg_index(rm),4,0,0}; i.src=Operand{Operand::Kind::imm,0,1,0,next()};
        i.mnemonic = sub==4?"shl":sub==5?"shr":sub==7?"sar":"badshift"; break; }
      case 0x69: case 0x6B: {
        const auto mr=next(); const auto mod=(mr>>6)&3u; const auto reg=(mr>>3)&7u; const auto rm=mr&7u; if(mod!=3) throw std::runtime_error("x86_lifter: imul mem unsupported");
        i.mnemonic="imul"; i.dst=Operand{Operand::Kind::reg, reg_index(reg),4,0,0}; i.src=Operand{Operand::Kind::reg, reg_index(rm),4,0,0}; i.target=common::read_integer(view,off, opcode==0x69?4:1); off += opcode==0x69?4:1; break; }
      default:
        if (opcode>=0xB8 && opcode<=0xBF) { i.mnemonic="mov"; i.dst=Operand{Operand::Kind::reg, reg_index(opcode-0xB8),4,0,0}; i.src=Operand{Operand::Kind::imm,0,4,0,common::read_integer(view,off,4)}; off+=4; }
        else if (opcode>=0x70 && opcode<=0x7F) { i.mnemonic="jcc"; i.jcc=opcode&0xFu; auto rel=static_cast<std::int8_t>(next()); i.target=view.base_addr+off+rel; }
        else if (opcode==0x0F) { auto ext=next(); if(ext>=0x80 && ext<=0x8F) { i.mnemonic="jcc"; i.jcc=ext&0xFu; auto rel=static_cast<std::int32_t>(common::read_integer(view,off,4)); off+=4; i.target=view.base_addr+off+rel; } else if(ext==0xAF) { i.mnemonic="imul"; modrm(true);} else throw std::runtime_error("x86_lifter: unsupported 0F opcode"); }
        else throw std::runtime_error("x86_lifter: unsupported opcode");
    }
    i.size=off-i.offset; return i;
  }
};
std::string label(std::uint64_t a){ std::ostringstream oss; oss<<"L_"<<std::hex<<a; return oss.str(); }
void loadop(std::ostringstream& out,const Operand& op,std::uint8_t dst){ if(op.kind==Operand::Kind::reg){ if(dst!=op.reg) out<<"  mov vr"<<unsigned(dst)<<", vr"<<unsigned(op.reg)<<"\n";} else if(op.kind==Operand::Kind::imm){ out<<"  ldi_u64 vr"<<unsigned(dst)<<", "<<op.imm<<"\n";} else if(op.reg==4){ out<<"  load_mem32 vr"<<unsigned(dst)<<", [sp"<<(op.disp>=0?"+":"")<<op.disp<<"]\n";} else { out<<"  load_mem32 vr"<<unsigned(dst)<<", [vr"<<unsigned(op.reg)<<(op.disp>=0?"+":"")<<op.disp<<"]\n"; } }
void storeop(std::ostringstream& out,const Operand& op,std::uint8_t src){ if(op.kind==Operand::Kind::reg){ out<<"  mov vr"<<unsigned(op.reg)<<", vr"<<unsigned(src)<<"\n"; } else if(op.reg==4){ out<<"  store_mem32 [sp"<<(op.disp>=0?"+":"")<<op.disp<<"], vr"<<unsigned(src)<<"\n"; } else { out<<"  store_mem32 [vr"<<unsigned(op.reg)<<(op.disp>=0?"+":"")<<op.disp<<"], vr"<<unsigned(src)<<"\n"; } }
std::string jcc_name(std::uint8_t c){ switch(c){ case 0x4:return "jeq"; case 0x5:return "jne"; case 0xC:return "jlt"; case 0xE:return "jle"; case 0xF:return "jgt"; case 0xD:return "jge"; default:return {}; } }
}
std::string X86Lifter::isa_name() const { return "x86"; }
bool X86Lifter::can_lift(const common::FunctionView& view) const { return view.endian==common::ArchEndianness::little && (view.cc==common::CallingConvention::cdecl_x86 || view.cc==common::CallingConvention::stdcall_x86); }
common::LiftedFunction X86Lifter::lift(const common::FunctionView& view) const {
  if(!can_lift(view)) throw std::runtime_error("x86_lifter: incompatible function view");
  common::LiftedFunction lifted; std::vector<Instruction> insns; try{ Decoder d{view}; while(!d.eof()) insns.push_back(d.decode_one()); }catch(const std::exception& ex){ lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode, insns.empty()?0:insns.back().offset, ex.what()}); return lifted; }
  for (auto& i : insns) {
    const auto start = i.offset;
    const auto end = start + i.size;
    std::vector<std::uint8_t> slice(view.code.begin() + static_cast<std::ptrdiff_t>(start),
                                    view.code.begin() + static_cast<std::ptrdiff_t>(end));
    i.pc_relative_target = decode_instruction(slice, view.base_addr + start).pc_relative_target;
    if (i.pc_relative_target.has_value() &&
        (i.pc_relative_target->kind == common::PcRelativeTarget::Kind::branch ||
         i.pc_relative_target->kind == common::PcRelativeTarget::Kind::call)) {
      i.target = i.pc_relative_target->computed_absolute;
    }
  }
  std::unordered_map<std::uint64_t,std::string> labels; for(const auto& i:insns) if(i.mnemonic=="jcc"||i.mnemonic=="jmp"||i.mnemonic=="call") labels.emplace(i.target,label(i.target));
  std::ostringstream out; out<<"entry:\n"; Operand cmp_l{}, cmp_r{}; bool have_cmp=false; for(const auto& i:insns){ auto addr=view.base_addr+i.offset; if(labels.count(addr)) out<<labels[addr]<<":\n"; if(i.mnemonic=="mov"){ loadop(out,i.src,kTmp0); storeop(out,i.dst,kTmp0); if(i.src.kind==Operand::Kind::imm){ if(const auto* r=common::find_overlapping_relocation(view,i.offset+i.size-4,4)){ vm1::ConstPoolEntry e; e.kind=vm1::ConstKind::none; auto p=common::const_tag_payload(*r); e.bytes.assign(p.begin(),p.end()); lifted.module.const_pool.push_back(std::move(e)); } } } else if(i.mnemonic=="add"||i.mnemonic=="sub"||i.mnemonic=="and"||i.mnemonic=="or"||i.mnemonic=="xor"){ loadop(out,i.dst,kTmp0); loadop(out,i.src,kTmp1); out<<"  "<<i.mnemonic<<" vr"<<unsigned(kTmp0)<<", vr"<<unsigned(kTmp0)<<", vr"<<unsigned(kTmp1)<<"\n"; storeop(out,i.dst,kTmp0);} else if(i.mnemonic=="imul"){ loadop(out,i.dst,kTmp0); loadop(out,i.src,kTmp1); out<<"  mul vr"<<unsigned(kTmp0)<<", vr"<<unsigned(kTmp0)<<", vr"<<unsigned(kTmp1)<<"\n"; if(i.target){ out<<"  ldi_u64 vr"<<unsigned(kTmp1)<<", "<<i.target<<"\n"; out<<"  mul vr"<<unsigned(kTmp0)<<", vr"<<unsigned(kTmp0)<<", vr"<<unsigned(kTmp1)<<"\n"; } storeop(out,i.dst,kTmp0);} else if(i.mnemonic=="shl"||i.mnemonic=="shr"||i.mnemonic=="sar"){ loadop(out,i.dst,kTmp0); loadop(out,i.src,kTmp1); out<<"  "<<i.mnemonic<<" vr"<<unsigned(kTmp0)<<", vr"<<unsigned(kTmp0)<<", vr"<<unsigned(kTmp1)<<"\n"; storeop(out,i.dst,kTmp0);} else if(i.mnemonic=="cmp"){ cmp_l=i.dst; cmp_r=i.src; have_cmp=true; } else if(i.mnemonic=="jcc"){ auto n=jcc_name(i.jcc); if(!have_cmp||n.empty()){ lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode,i.offset,"x86_lifter: unsupported jcc"}); return lifted;} loadop(out,cmp_l,kTmp0); loadop(out,cmp_r,kTmp1); out<<"  "<<n<<" vr"<<unsigned(kTmp0)<<", vr"<<unsigned(kTmp1)<<", @"<<labels.at(i.target)<<"\n"; } else if(i.mnemonic=="jmp"){ out<<"  jmp @"<<labels.at(i.target)<<"\n"; } else if(i.mnemonic=="call"){ out<<"  call @"<<labels.at(i.target)<<", 0\n"; } else if(i.mnemonic=="push"){ loadop(out,i.src,kTmp0); out<<"  ldi_u64 vr"<<unsigned(kTmp1)<<", 4\n  sub vr4, vr4, vr"<<unsigned(kTmp1)<<"\n"; out<<"  store_mem32 [vr4+0], vr"<<unsigned(kTmp0)<<"\n"; } else if(i.mnemonic=="pop"){ out<<"  load_mem32 vr"<<unsigned(i.dst.reg)<<", [vr4+0]\n"; out<<"  ldi_u64 vr"<<unsigned(kTmp1)<<", 4\n  add vr4, vr4, vr"<<unsigned(kTmp1)<<"\n"; } else if(i.mnemonic=="ret"){ out<<"  ret\n"; } else { lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode,i.offset,"x86_lifter: unsupported instruction"}); return lifted; } }
  try {
    lifted.module = vm1::assemble_module_text(out.str());
  } catch (const common::ResolutionError& ex) {
    for (const auto& diagnostic : ex.result().diagnostics) {
      lifted.diagnostics.push_back({map_resolver_kind(diagnostic.kind), diagnostic.instruction_index, diagnostic.detail});
    }
  } catch (const std::exception& ex) {
    lifted.diagnostics.push_back({common::DiagnosticKind::malformed_instruction,0,ex.what()});
  }
  return lifted;
}
const char* ArchFacade::status() const noexcept { return "x86_ready"; }
}  // namespace vmp::arch::x86
