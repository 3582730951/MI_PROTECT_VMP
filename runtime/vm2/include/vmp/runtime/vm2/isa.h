#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace vmp::runtime::vm2 {

inline constexpr std::array<std::uint8_t, 4> kVm2Magic{{'V', 'M', 'P', '2'}};
inline constexpr std::uint16_t kVm2LegacyVersion = 3;
inline constexpr std::uint16_t kVm2Version = 4;
inline constexpr std::size_t kVm2GeneralRegisterCount = 32;
inline constexpr std::size_t kVm2VectorRegisterCount = 16;
inline constexpr std::size_t kVm2FloatRegisterCount = 8;
inline constexpr std::size_t kVm2PredicateCount = 8;
inline constexpr std::size_t kVm2DefaultStackSize = 128u * 1024u;
inline constexpr std::size_t kVm2KeyContextIdSize = 16u;
inline constexpr std::size_t kOpcodeMapSeedSize = 16u;
inline constexpr std::uint16_t VMP_FLAG_OPCODE_ENCRYPTED = 0x0001u;

union Vec128 {
  struct {
    std::uint64_t lo;
    std::uint64_t hi;
  } u64;
  std::array<std::uint64_t, 2> lanes;
};
static_assert(sizeof(Vec128) == 16, "Vec128 must be 16 bytes");

enum class Opcode : std::uint16_t {
  nop = 0x1000,
  ildimm = 0x1001,
  vldimm = 0x1002,
  imov = 0x1003,
  dldimm = 0x1004,
  dmov = 0x1005,

  iadd = 0x1100,
  isub = 0x1101,
  imul = 0x1102,
  idiv = 0x1103,
  imod = 0x1104,
  ineg = 0x1105,

  iand = 0x1200,
  ior = 0x1201,
  ixor = 0x1202,
  ishl = 0x1203,
  ishr = 0x1204,
  isar = 0x1205,
  inot = 0x1206,
  ipopcnt = 0x1207,
  iclz = 0x1208,
  ictz = 0x1209,
  ibswap = 0x120A,

  icmp = 0x1300,
  itest = 0x1301,
  isetcc = 0x1302,

  imemld8 = 0x1400,
  imemld16 = 0x1401,
  imemld32 = 0x1402,
  imemld64 = 0x1403,
  imemst8 = 0x1404,
  imemst16 = 0x1405,
  imemst32 = 0x1406,
  imemst64 = 0x1407,
  vmemld128 = 0x1408,
  vmemst128 = 0x1409,

  jmp = 0x1500,
  jp = 0x1501,
  jnp = 0x1502,
  blnk = 0x1503,
  bret = 0x1504,
  pcall = 0x1505,
  pret = 0x1506,

  dadd = 0x1600,
  dsub = 0x1601,
  dmul = 0x1602,
  ddiv = 0x1603,
  dsqrt = 0x1604,
  i64tof = 0x1605,
  f64toi = 0x1606,
  dcmp = 0x1607,

  vadd128 = 0x1700,
  vsub128 = 0x1701,
  vmul128 = 0x1702,
  vxor128 = 0x1703,

  imemcpy = 0x1800,
  imemset = 0x1801,
  istrcmp = 0x1802,
  istrlen = 0x1803,

  icas64 = 0x1900,
  ixchg64 = 0x1901,
  ifence = 0x1902,

  brk = 0x1A00,
  ftrap = 0x1A01,
  syscall_proxy = 0x1A02,

  xcall = 0x1B00,
  xret = 0x1B01,
  bridgeargs = 0x1B02,

  tsload = 0x1C00,
  tsrelease = 0x1C01,
  tsread8 = 0x1C02,
  tswipe = 0x1C03,
};

enum class MemoryBase : std::uint8_t {
  sp = 0xFE,
};

constexpr bool is_valid_general_register(std::uint8_t index) noexcept {
  return index < kVm2GeneralRegisterCount;
}

constexpr bool is_valid_vector_register(std::uint8_t index) noexcept {
  return index < kVm2VectorRegisterCount;
}

constexpr bool is_valid_float_register(std::uint8_t index) noexcept {
  return index < kVm2FloatRegisterCount;
}

constexpr bool is_valid_predicate(std::uint8_t index) noexcept {
  return index < kVm2PredicateCount;
}

inline constexpr int kVm2HandlerTableIdentity = 0x56324D32;

}  // namespace vmp::runtime::vm2
