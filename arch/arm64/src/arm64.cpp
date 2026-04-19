#include <vmp/arch/arm64/arm64.h>

#include <vmp/arch/common/label_resolver.h>

#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace vmp::arch::arm64 {
namespace common = vmp::arch::common;
namespace vm1 = vmp::runtime::vm1;
namespace {
struct Decoded { std::size_t offset=0; std::uint32_t word=0; std::string kind; std::uint8_t rd=0,rn=0,rm=0,cond=0; std::uint32_t imm=0; std::uint64_t target=0; bool is64=true; std::optional<common::PcRelativeTarget> pc_relative_target; };
struct DataSpan { std::size_t begin=0,end=0; };
std::string label(std::uint64_t a){ std::ostringstream oss; oss<<"L_"<<std::hex<<a; return oss.str(); }
std::string cond_name(std::uint8_t c){ switch(c){ case 0:return "jeq"; case 1:return "jne"; case 0xA:return "jge"; case 0xB:return "jlt"; case 0xC:return "jgt"; case 0xD:return "jle"; default:return {}; } }
common::DiagnosticKind map_resolver_kind(common::ResolverDiagnosticKind kind) {
  switch (kind) {
    case common::ResolverDiagnosticKind::out_of_range: return common::DiagnosticKind::out_of_range;
    case common::ResolverDiagnosticKind::unresolved_label: return common::DiagnosticKind::unresolved_label;
    case common::ResolverDiagnosticKind::duplicate_label: return common::DiagnosticKind::duplicate_label;
  }
  return common::DiagnosticKind::malformed_instruction;
}
std::vector<std::uint8_t> le32(std::uint32_t value) {
  return {
      static_cast<std::uint8_t>(value & 0xFFu),
      static_cast<std::uint8_t>((value >> 8) & 0xFFu),
      static_cast<std::uint8_t>((value >> 16) & 0xFFu),
      static_cast<std::uint8_t>((value >> 24) & 0xFFu),
  };
}
}
std::string Arm64Lifter::isa_name() const { return "arm64"; }
bool Arm64Lifter::can_lift(const common::FunctionView& view) const { return view.endian==common::ArchEndianness::little && view.cc==common::CallingConvention::aapcs64; }
common::LiftedFunction Arm64Lifter::lift(const common::FunctionView& view) const {
  if(!can_lift(view)) throw std::runtime_error("arm64_lifter: incompatible function view");
  common::LiftedFunction lifted; if(view.code.size()%4u!=0u){ lifted.diagnostics.push_back({common::DiagnosticKind::malformed_instruction,0,"arm64_lifter: code size not word aligned"}); return lifted; }
  std::vector<Decoded> insns; std::unordered_map<std::uint64_t,std::string> labels; std::vector<DataSpan> data_spans;
  const auto span_end_at = [&](std::size_t off) -> std::optional<std::size_t> {
    std::optional<std::size_t> end;
    for (const auto& span : data_spans) {
      if (off >= span.begin && off < span.end) {
        end = std::max(end.value_or(span.end), span.end);
      }
    }
    return end;
  };
  const auto mark_data_span = [&](std::size_t begin, std::size_t width) {
    if (width == 0 || begin >= view.code.size()) return;
    const auto end = std::min(view.code.size(), begin + width);
    if (begin >= end) return;
    data_spans.push_back({begin, end});
  };
  for(std::size_t off=0; off<view.code.size();){
    if (const auto skip = span_end_at(off); skip.has_value()) { off = *skip; continue; }
    auto w=static_cast<std::uint32_t>(common::read_integer(view,off,4)); Decoded d; d.offset=off; d.word=w; d.rd=w&0x1Fu; d.rn=(w>>5)&0x1Fu; d.rm=(w>>16)&0x1Fu; d.is64=((w>>31)&1u)!=0u; d.pc_relative_target = decode_instruction(le32(w), view.base_addr + off).pc_relative_target;
    if((w & 0x7C000000u)==0x14000000u){ d.kind=((w>>31)&1u)?"bl":"b"; std::int32_t imm26=w&0x03FFFFFFu; if(imm26 & 0x02000000) imm26 |= ~0x03FFFFFF; d.target=view.base_addr+off+((std::int64_t)imm26<<2); labels.emplace(d.target,label(d.target)); }
    else if((w & 0xFF000010u)==0x54000000u){ d.kind="b.cond"; std::int32_t imm19=(w>>5)&0x7FFFF; if(imm19&0x40000) imm19|=~0x7FFFF; d.cond=w&0xFu; d.target=view.base_addr+off+((std::int64_t)imm19<<2); labels.emplace(d.target,label(d.target)); }
    else if((w & 0x1F000000u)==0x10000000u){ d.kind=((w>>31)&1u)?"adrp":"adr"; d.target=d.pc_relative_target.has_value()?d.pc_relative_target->computed_absolute:0; if(d.target>=view.base_addr && d.target<view.base_addr+view.code.size()) labels.emplace(d.target,label(d.target)); }
    else if((w & 0x3B000000u)==0x18000000u){ d.kind="ldr_lit"; d.target=d.pc_relative_target.has_value()?d.pc_relative_target->computed_absolute:0; d.is64=(((w >> 30) & 0x3u) == 1u); if(d.target>=view.base_addr && d.target + (d.is64 ? 8u : 4u) <= view.base_addr + view.code.size()) mark_data_span(static_cast<std::size_t>(d.target - view.base_addr), d.is64 ? 8u : 4u); }
    else if((w & 0xFFFFFC1Fu)==0xD503201Fu){ d.kind="nop"; }
    else if((w & 0xFFFFFC1Fu)==0xD65F0000u){ d.kind="ret"; d.rn=(w>>5)&0x1Fu; }
    else if((w & 0x1F200000u)==0x0B000000u || (w & 0x1F200000u)==0x4B000000u){ d.kind=((w & 0x40000000u) != 0u) ? "sub" : "add"; }
    else if((w & 0xFFE0FC00u)==0x9B007C00u){ d.kind="mul"; }
    else if((w & 0xFFE0FC00u)==0x9AC00C00u){ d.kind="sdiv"; }
    else if((w & 0xFFE0FC00u)==0x9AC00800u){ d.kind="udiv"; }
    else if((w & 0x1F200000u)==0x0A000000u || (w & 0x1F200000u)==0x2A000000u || (w & 0x1F200000u)==0x4A000000u){ d.kind=(w & 0x40000000u) ? "eor" : ((w & 0x20000000u) ? "orr" : "and"); }
    else if((w & 0xFFC00000u)==0xD3400000u){ d.kind="lsr"; d.imm=(w>>10)&0x3Fu; }
    else if((w & 0xFFC00000u)==0x93400000u){ d.kind="asr"; d.imm=(w>>10)&0x3Fu; }
    else if((w & 0xFFC00000u)==0xD37CE000u){ d.kind="lsl"; d.imm=64-(((w>>10)&0x3Fu)+1); }
    else if((w & 0x3B000000u)==0x39000000u){ d.kind=((w>>22)&1u)?"ldr":"str"; d.imm=((w>>10)&0xFFFu) * (((w>>30)&0x3u)==3?8:4); }
    else { lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode,off,"arm64_lifter: unsupported opcode"}); return lifted; }
    insns.push_back(d);
    off += 4;
  }
  std::ostringstream out; out<<"entry:\n"; Decoded last_cmp{}; bool have_cmp=false; for(const auto& d:insns){ auto addr=view.base_addr+d.offset; if(labels.count(addr)) out<<labels[addr]<<":\n"; if(d.kind=="add"||d.kind=="sub"){ out<<"  "<<d.kind<<" vr"<<unsigned(d.rd)<<", vr"<<unsigned(d.rn)<<", vr"<<unsigned(d.rm)<<"\n"; last_cmp=d; have_cmp=(d.kind=="sub" && d.rd==31); } else if(d.kind=="mul"){ out<<"  mul vr"<<unsigned(d.rd)<<", vr"<<unsigned(d.rn)<<", vr"<<unsigned(d.rm)<<"\n"; } else if(d.kind=="sdiv"||d.kind=="udiv"){ out<<"  div vr"<<unsigned(d.rd)<<", vr"<<unsigned(d.rn)<<", vr"<<unsigned(d.rm)<<"\n"; } else if(d.kind=="and"){ out<<"  and vr"<<unsigned(d.rd)<<", vr"<<unsigned(d.rn)<<", vr"<<unsigned(d.rm)<<"\n"; } else if(d.kind=="orr"){ out<<"  or vr"<<unsigned(d.rd)<<", vr"<<unsigned(d.rn)<<", vr"<<unsigned(d.rm)<<"\n"; } else if(d.kind=="eor"){ out<<"  xor vr"<<unsigned(d.rd)<<", vr"<<unsigned(d.rn)<<", vr"<<unsigned(d.rm)<<"\n"; } else if(d.kind=="lsl"||d.kind=="lsr"||d.kind=="asr"){ out<<"  ldi_u64 vr31, "<<d.imm<<"\n"; out<<"  "<<(d.kind=="lsr"?"shr":d.kind=="asr"?"sar":"shl")<<" vr"<<unsigned(d.rd)<<", vr"<<unsigned(d.rn)<<", vr31\n"; } else if(d.kind=="ldr"){ if(d.rn==31) out<<"  load_mem64 vr"<<unsigned(d.rd)<<", [sp+"<<d.imm<<"]\n"; else out<<"  load_mem64 vr"<<unsigned(d.rd)<<", [vr"<<unsigned(d.rn)<<"+"<<d.imm<<"]\n"; } else if(d.kind=="ldr_lit"){ if(d.target < view.base_addr || d.target + (d.is64 ? 8u : 4u) > view.base_addr + view.code.size()){ lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode,d.offset,"arm64_lifter: literal target out of range"}); return lifted; } const auto literal_offset = static_cast<std::size_t>(d.target - view.base_addr); const auto literal = common::read_integer(view, literal_offset, d.is64 ? 8u : 4u); out<<"  ldi_u64 vr"<<unsigned(d.rd)<<", "<<literal<<"\n"; } else if(d.kind=="str"){ if(d.rn==31) out<<"  store_mem64 [sp+"<<d.imm<<"], vr"<<unsigned(d.rd)<<"\n"; else out<<"  store_mem64 [vr"<<unsigned(d.rn)<<"+"<<d.imm<<"], vr"<<unsigned(d.rd)<<"\n"; } else if(d.kind=="adr"||d.kind=="adrp"){ if(const auto it = labels.find(d.target); it != labels.end()) out<<"  ldi_u64 vr"<<unsigned(d.rd)<<", @"<<it->second<<"\n"; else out<<"  ldi_u64 vr"<<unsigned(d.rd)<<", "<<d.target<<"\n"; } else if(d.kind=="b"){ out<<"  jmp @"<<labels.at(d.target)<<"\n"; } else if(d.kind=="bl"){ out<<"  call @"<<labels.at(d.target)<<", 0\n"; } else if(d.kind=="nop"){ out<<"  nop\n"; } else if(d.kind=="ret"){ out<<"  ret\n"; } else if(d.kind=="b.cond"){ auto n=cond_name(d.cond); if(!have_cmp||n.empty()){ lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode,d.offset,"arm64_lifter: unsupported conditional branch"}); return lifted; } out<<"  "<<n<<" vr"<<unsigned(last_cmp.rn)<<", vr"<<unsigned(last_cmp.rm)<<", @"<<labels.at(d.target)<<"\n"; } }
  try {
    lifted.module = vm1::assemble_module_text(out.str());
  } catch (const common::ResolutionError& ex) {
    for (const auto& diagnostic : ex.result().diagnostics) {
      lifted.diagnostics.push_back({map_resolver_kind(diagnostic.kind), diagnostic.instruction_index, diagnostic.detail});
    }
  } catch(const std::exception& ex){ lifted.diagnostics.push_back({common::DiagnosticKind::malformed_instruction,0,ex.what()}); }
  return lifted;
}
const char* ArchFacade::status() const noexcept { return "arm64_ready"; }
}  // namespace vmp::arch::arm64
