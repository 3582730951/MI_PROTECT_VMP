#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace vmp::runtime::vm1 {

inline constexpr std::array<std::uint8_t, 4> kVm1Magic{{'V', 'M', '1', 'B'}};
inline constexpr std::uint16_t kVm1LegacyVersion = 3;
inline constexpr std::uint16_t kVm1Version = 4;
inline constexpr std::size_t kVm1GeneralRegisterCount = 32;
inline constexpr std::size_t kVm1FloatRegisterCount = 4;
inline constexpr std::size_t kVm1VectorRegisterCount = 16;
inline constexpr std::size_t kVm1DefaultStackSize = 64u * 1024u;
inline constexpr std::size_t kOpcodeMapSeedSize = 16u;
inline constexpr std::uint16_t VMP_FLAG_OPCODE_ENCRYPTED = 0x0001u;

enum class Opcode : std::uint16_t {
  nop = 0x0000,
  ldi64 = 0x0001,
  ldi_u64 = 0x0002,
  ldi_f64 = 0x0003,
  mov = 0x0004,

  add = 0x0100,
  sub = 0x0101,
  mul = 0x0102,
  div = 0x0103,
  mod = 0x0104,
  neg = 0x0105,

  bit_and = 0x0200,
  bit_or = 0x0201,
  bit_xor = 0x0202,
  shl = 0x0203,
  shr = 0x0204,
  sar = 0x0205,
  bit_not = 0x0206,
  popcnt = 0x0207,
  clz = 0x0208,
  ctz = 0x0209,
  bswap = 0x020A,

  cmp = 0x0300,
  test = 0x0301,
  setcc = 0x0302,

  load_mem8 = 0x0400,
  load_mem16 = 0x0401,
  load_mem32 = 0x0402,
  load_mem64 = 0x0403,
  store_mem8 = 0x0404,
  store_mem16 = 0x0405,
  store_mem32 = 0x0406,
  store_mem64 = 0x0407,
  load_sext8 = 0x0408,
  load_sext16 = 0x0409,
  load_sext32 = 0x040A,
  lea = 0x040B,

  jmp = 0x0500,
  jeq = 0x0501,
  jne = 0x0502,
  jlt = 0x0503,
  jle = 0x0504,
  jgt = 0x0505,
  jge = 0x0506,
  call = 0x0507,
  ret = 0x0508,
  call_indirect = 0x0509,
  jmp_indirect = 0x050A,

  fadd = 0x0600,
  fsub = 0x0601,
  fmul = 0x0602,
  fdiv = 0x0603,
  fsqrt = 0x0604,
  i64_to_f64 = 0x0605,
  f64_to_i64 = 0x0606,
  fcmp = 0x0607,

  vadd128 = 0x0700,
  vxor128 = 0x0701,
  vshuffle128 = 0x0702,

  memcpy = 0x0800,
  memset = 0x0801,
  strcmp = 0x0802,
  strlen = 0x0803,

  cas_u64 = 0x0900,
  xchg_u64 = 0x0901,
  fence = 0x0902,

  breakpoint = 0x0A00,
  trap = 0x0A01,
  syscall_proxy = 0x0A02,

  domain_call = 0x0B00,
  domain_ret = 0x0B01,
  bridge_args = 0x0B02,

  load_transient_string = 0x0C00,
  release_transient_string = 0x0C01,
  transient_read8 = 0x0C02,
  transient_wipe = 0x0C03,
};

enum class ConstKind : std::uint8_t {
  none = 0,
  transient_string = 1,
  opcode_map_marker = 0xFE,
};

enum class MemoryBase : std::uint8_t {
  stack_pointer = 0xFF,
};

constexpr bool is_valid_general_register(std::uint8_t index) noexcept {
  return index < kVm1GeneralRegisterCount;
}

constexpr bool is_valid_float_register(std::uint8_t index) noexcept {
  return index < kVm1FloatRegisterCount;
}

constexpr bool is_valid_vector_register(std::uint8_t index) noexcept {
  return index < kVm1VectorRegisterCount;
}

}  // namespace vmp::runtime::vm1
