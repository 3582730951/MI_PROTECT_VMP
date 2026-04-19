#include <vmp/arch/arm/arm.h>

#include <vmp/arch/common/label_resolver.h>

#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace vmp::arch::arm {
namespace common = vmp::arch::common;
namespace vm1 = vmp::runtime::vm1;
namespace {
struct Decoded { std::size_t offset=0; std::uint32_t word=0; std::string kind; std::uint8_t rd=0,rn=0,rm=0; std::uint32_t imm=0; std::uint64_t target=0; std::uint8_t cond=0xEu; std::optional<common::PcRelativeTarget> pc_relative_target; };
struct DataSpan { std::size_t begin=0,end=0; };
std::string label(std::uint64_t a){ std::ostringstream oss; oss<<"L_"<<std::hex<<a; return oss.str(); }
std::string cond_name(std::uint8_t c){ switch(c){ case 0x0:return "jeq"; case 0x1:return "jne"; case 0xA:return "jge"; case 0xB:return "jlt"; case 0xC:return "jgt"; case 0xD:return "jle"; case 0xE:return ""; default:return {}; } }
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
std::string ArmLifter::isa_name() const { return "armv7"; }
bool ArmLifter::can_lift(const common::FunctionView& view) const { return view.endian==common::ArchEndianness::little && view.cc==common::CallingConvention::aapcs32 && (view.base_addr % 2u)==0; }
common::LiftedFunction ArmLifter::lift(const common::FunctionView& view) const {
  if(!can_lift(view)) throw std::runtime_error("arm_lifter: incompatible function view");
  common::LiftedFunction lifted; if(view.code.size()%4u!=0u){ lifted.diagnostics.push_back({common::DiagnosticKind::malformed_instruction,0,"arm_lifter: code size not word aligned"}); return lifted; }
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
    auto w=static_cast<std::uint32_t>(common::read_integer(view,off,4)); if((w & 0xFFFF0000u)==0x00000000u){ lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_thumb_mode,off,"arm_lifter: thumb not supported"}); return lifted; } Decoded d; d.offset=off; d.word=w; d.cond=(w>>28)&0xFu; d.pc_relative_target = decode_instruction(le32(w), view.base_addr + off, ExecutionMode::arm).pc_relative_target;
    if((w & 0x0FFFFFF0u)==0x012FFF10u){ d.kind="bx"; d.rm=w&0xFu; }
    else if((w & 0x0E000000u)==0x0A000000u){ d.kind=((w>>24)&1u)?"bl":"b"; std::int32_t imm24=w&0xFFFFFFu; if(imm24&0x800000) imm24|=~0xFFFFFF; d.target=view.base_addr+off+8+((std::int64_t)imm24<<2); if(d.pc_relative_target.has_value()) d.target=d.pc_relative_target->computed_absolute; labels.emplace(d.target,label(d.target)); }
    else if((w & 0x0C100000u)==0x04100000u){ d.kind=((w>>20)&1u)?"ldr":"str"; d.rn=(w>>16)&0xFu; d.rd=(w>>12)&0xFu; d.imm=w&0xFFFu; if(d.pc_relative_target.has_value()) d.target=d.pc_relative_target->computed_absolute; if(d.kind=="ldr" && d.rn==15 && d.target>=view.base_addr && d.target + 4u <= view.base_addr + view.code.size()) mark_data_span(static_cast<std::size_t>(d.target - view.base_addr), 4u); }
    else if((w & 0x0C000000u)==0x00000000u){ d.rn=(w>>16)&0xFu; d.rd=(w>>12)&0xFu; d.rm=w&0xFu; const auto opcode=(w>>21)&0xFu; if(opcode==0xD) d.kind="mov"; else if(opcode==0x4) d.kind="add"; else if(opcode==0x2) d.kind="sub"; else if(opcode==0x0) d.kind="and"; else if(opcode==0xC) d.kind="orr"; else if(opcode==0x1) d.kind="eor"; else if(opcode==0xA) d.kind="cmp"; else { lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode,off,"arm_lifter: unsupported data op"}); return lifted; } }
    else { lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode,off,"arm_lifter: unsupported opcode"}); return lifted; }
    insns.push_back(d);
    off += 4;
  }
  std::ostringstream out; out<<"entry:\n"; Decoded last_cmp{}; bool have_cmp=false; for(const auto& d:insns){ auto addr=view.base_addr+d.offset; if(labels.count(addr)) out<<labels[addr]<<":\n"; if(d.cond!=0xEu && d.kind!="b"){ lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode,d.offset,"arm_lifter: conditional execution only supported for branches"}); return lifted; } if(d.kind=="mov"){ out<<"  mov vr"<<unsigned(d.rd)<<", vr"<<unsigned(d.rm)<<"\n"; } else if(d.kind=="add"||d.kind=="sub"||d.kind=="and"||d.kind=="eor"){ out<<"  "<<(d.kind=="eor"?"xor":d.kind)<<" vr"<<unsigned(d.rd)<<", vr"<<unsigned(d.rn)<<", vr"<<unsigned(d.rm)<<"\n"; } else if(d.kind=="orr"){ out<<"  or vr"<<unsigned(d.rd)<<", vr"<<unsigned(d.rn)<<", vr"<<unsigned(d.rm)<<"\n"; } else if(d.kind=="cmp"){ last_cmp=d; have_cmp=true; } else if(d.kind=="ldr"){ if(d.rn==15 && d.pc_relative_target.has_value()){ if(d.target < view.base_addr || d.target + 4u > view.base_addr + view.code.size()){ lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode,d.offset,"arm_lifter: literal target out of range"}); return lifted; } const auto literal_offset = static_cast<std::size_t>(d.target - view.base_addr); const auto literal = common::read_integer(view, literal_offset, 4); out<<"  ldi_u64 vr"<<unsigned(d.rd)<<", "<<literal<<"\n"; } else if(d.rn==13) out<<"  load_mem32 vr"<<unsigned(d.rd)<<", [sp+"<<d.imm<<"]\n"; else out<<"  load_mem32 vr"<<unsigned(d.rd)<<", [vr"<<unsigned(d.rn)<<"+"<<d.imm<<"]\n"; } else if(d.kind=="str"){ if(d.rn==13) out<<"  store_mem32 [sp+"<<d.imm<<"], vr"<<unsigned(d.rd)<<"\n"; else out<<"  store_mem32 [vr"<<unsigned(d.rn)<<"+"<<d.imm<<"], vr"<<unsigned(d.rd)<<"\n"; } else if(d.kind=="b"){ if(d.cond==0xEu) out<<"  jmp @"<<labels.at(d.target)<<"\n"; else { auto n=cond_name(d.cond); if(!have_cmp||n.empty()){ lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode,d.offset,"arm_lifter: branch condition unsupported"}); return lifted; } out<<"  "<<n<<" vr"<<unsigned(last_cmp.rn)<<", vr"<<unsigned(last_cmp.rm)<<", @"<<labels.at(d.target)<<"\n"; } } else if(d.kind=="bl"){ out<<"  call @"<<labels.at(d.target)<<", 0\n"; } else if(d.kind=="bx"){ if(d.rm!=14){ lifted.diagnostics.push_back({common::DiagnosticKind::unsupported_opcode,d.offset,"arm_lifter: bx only supports lr"}); return lifted; } out<<"  ret\n"; } }
  try {
    lifted.module = vm1::assemble_module_text(out.str());
  } catch (const common::ResolutionError& ex) {
    for (const auto& diagnostic : ex.result().diagnostics) {
      lifted.diagnostics.push_back({map_resolver_kind(diagnostic.kind), diagnostic.instruction_index, diagnostic.detail});
    }
  } catch(const std::exception& ex){ lifted.diagnostics.push_back({common::DiagnosticKind::malformed_instruction,0,ex.what()}); }
  return lifted;
}
const char* ArchFacade::status() const noexcept { return "arm_ready"; }
}  // namespace vmp::arch::arm
