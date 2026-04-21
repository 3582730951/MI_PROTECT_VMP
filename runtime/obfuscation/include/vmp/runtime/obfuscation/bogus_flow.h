#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <vmp/runtime/obfuscation/mba.h>
#include <vmp/runtime/obfuscation/opaque.h>

namespace vmp::runtime::obfuscation {

struct BogusFlowSiteConfig {
  std::string seed_reg;
  std::string one_reg;
  std::string work0_reg;
  std::string work1_reg;
  std::size_t site_index = 0;
};

std::size_t bogus_flow_selection_phase(std::string_view source) noexcept;
bool bogus_flow_should_inject(std::size_t candidate_index, std::size_t selection_phase) noexcept;

std::vector<std::string> inject_vm1_bogus_flow(std::string_view opcode,
                                               const std::vector<std::string>& operands,
                                               const std::vector<std::string>& real_body,
                                               const BogusFlowSiteConfig& config);
std::vector<std::string> inject_vm2_bogus_flow(std::string_view opcode,
                                               const std::vector<std::string>& operands,
                                               const std::vector<std::string>& real_body,
                                               const BogusFlowSiteConfig& config);

#ifndef VMP_ENABLE_BOGUS_HANDLER_FLOW
#define VMP_ENABLE_BOGUS_HANDLER_FLOW VMP_ENABLE_OPAQUE_HANDLER_PREDICATES
#endif

#define VMP_APPLY_HANDLER_BOGUS_FLOW(variant_value,                                                \
                                     sink_ref,                                                     \
                                     real_path_expr,                                               \
                                     opaque_seed_expr,                                             \
                                     salt_a_expr,                                                  \
                                     salt_b_expr,                                                  \
                                     tertiary_expr)                                                \
  do {                                                                                             \
    constexpr unsigned vmp_bogus_variant__ = (variant_value);                                      \
    const bool vmp_bogus_real_path__ = (real_path_expr);                                           \
    const std::uint64_t vmp_bogus_opaque_seed__ = static_cast<std::uint64_t>(opaque_seed_expr);   \
    const std::uint64_t vmp_bogus_salt_a__ = static_cast<std::uint64_t>(salt_a_expr);             \
    const std::uint64_t vmp_bogus_salt_b__ = static_cast<std::uint64_t>(salt_b_expr);             \
    const std::uint64_t vmp_bogus_tertiary__ = static_cast<std::uint64_t>(tertiary_expr);         \
    if (!vmp_bogus_real_path__) {                                                                   \
      volatile std::uint64_t vmp_bogus0__ =                                                        \
          vmp::runtime::obfuscation::mba_add_u64(static_cast<std::uint64_t>(sink_ref) ^           \
                                                     vmp_bogus_opaque_seed__,                       \
                                                 vmp_bogus_salt_a__ ^ vmp_bogus_tertiary__);       \
      volatile std::uint64_t vmp_bogus1__ =                                                        \
          vmp::runtime::obfuscation::mba_sub_u64(vmp_bogus0__,                                     \
                                                 vmp_bogus_salt_b__ ^ (vmp_bogus_tertiary__ | 1ull)); \
      if (vmp::runtime::obfuscation::opaque_even_product_predicate(                                \
              static_cast<std::uint64_t>(vmp_bogus1__) ^ vmp_bogus_tertiary__)) {                  \
        if constexpr (vmp_bogus_variant__ == 0u) {                                                 \
          vmp_bogus0__ =                                                                           \
              vmp::runtime::obfuscation::mba_add_u64(vmp_bogus1__, vmp_bogus_salt_a__ | 1ull);    \
          vmp_bogus1__ =                                                                           \
              vmp::runtime::obfuscation::mba_sub_u64(vmp_bogus0__ ^ vmp_bogus_salt_b__,           \
                                                     vmp_bogus_tertiary__ + 1ull);                 \
          vmp_bogus0__ =                                                                           \
              vmp::runtime::obfuscation::mba_add_u64(vmp_bogus1__,                                  \
                                                     vmp_bogus_opaque_seed__ ^ vmp_bogus_salt_a__); \
          vmp_bogus1__ =                                                                           \
              vmp::runtime::obfuscation::mba_sub_u64(                                              \
                  vmp_bogus0__,                                                                    \
                  vmp::runtime::obfuscation::mba_mul2_u64(                                         \
                      (vmp_bogus_salt_b__ ^ vmp_bogus_tertiary__) | 1ull));                       \
          vmp_bogus0__ =                                                                           \
              vmp::runtime::obfuscation::mba_add_u64(vmp_bogus1__ ^ vmp_bogus_tertiary__,         \
                                                     vmp_bogus_salt_b__ + 3ull);                   \
        } else if constexpr (vmp_bogus_variant__ == 1u) {                                          \
          vmp_bogus0__ =                                                                           \
              vmp::runtime::obfuscation::mba_sub_u64(vmp_bogus1__ ^ vmp_bogus_salt_a__,           \
                                                     vmp_bogus_opaque_seed__ | 1ull);              \
          vmp_bogus1__ =                                                                           \
              vmp::runtime::obfuscation::mba_add_u64(vmp_bogus0__,                                  \
                                                     vmp_bogus_salt_b__ ^ vmp_bogus_tertiary__);   \
          vmp_bogus0__ =                                                                           \
              vmp::runtime::obfuscation::mba_sub_u64(                                              \
                  vmp_bogus1__,                                                                    \
                  vmp::runtime::obfuscation::mba_mul2_u64(                                         \
                      (vmp_bogus_salt_a__ ^ vmp_bogus_tertiary__) | 1ull));                       \
          vmp_bogus1__ =                                                                           \
              vmp::runtime::obfuscation::mba_add_u64(vmp_bogus0__ ^ vmp_bogus_opaque_seed__,      \
                                                     vmp_bogus_salt_b__ | 1ull);                   \
          vmp_bogus0__ =                                                                           \
              vmp::runtime::obfuscation::mba_sub_u64(vmp_bogus1__ ^ vmp_bogus_tertiary__,         \
                                                     vmp_bogus_salt_a__ + 3ull);                   \
        } else {                                                                                   \
          vmp_bogus0__ =                                                                           \
              vmp::runtime::obfuscation::mba_add_u64(vmp_bogus1__ ^ vmp_bogus_tertiary__,         \
                                                     vmp_bogus_salt_b__ | 1ull);                   \
          vmp_bogus1__ =                                                                           \
              vmp::runtime::obfuscation::mba_sub_u64(vmp_bogus0__,                                  \
                                                     vmp_bogus_opaque_seed__ ^ vmp_bogus_salt_a__); \
          vmp_bogus0__ =                                                                           \
              vmp::runtime::obfuscation::mba_add_u64(                                              \
                  vmp_bogus1__,                                                                    \
                  vmp::runtime::obfuscation::mba_mul2_u64(                                         \
                      (vmp_bogus_salt_a__ ^ vmp_bogus_salt_b__) | 1ull));                         \
          vmp_bogus1__ =                                                                           \
              vmp::runtime::obfuscation::mba_sub_u64(vmp_bogus0__ ^ vmp_bogus_tertiary__,         \
                                                     vmp_bogus_salt_a__ + 1ull);                   \
          vmp_bogus0__ =                                                                           \
              vmp::runtime::obfuscation::mba_add_u64(vmp_bogus1__ ^ vmp_bogus_opaque_seed__,      \
                                                     vmp_bogus_salt_b__ + 5ull);                   \
        }                                                                                          \
      } else {                                                                                     \
        vmp_bogus0__ =                                                                             \
            vmp::runtime::obfuscation::mba_add_u64(vmp_bogus1__ ^ vmp_bogus_salt_a__,             \
                                                   vmp_bogus_opaque_seed__ | 1ull);                \
        vmp_bogus1__ =                                                                             \
            vmp::runtime::obfuscation::mba_sub_u64(vmp_bogus0__,                                    \
                                                   vmp_bogus_salt_b__ ^ vmp_bogus_tertiary__);     \
        vmp_bogus0__ =                                                                             \
            vmp::runtime::obfuscation::mba_add_u64(                                                \
                vmp_bogus1__,                                                                      \
                vmp::runtime::obfuscation::mba_mul2_u64(                                           \
                    (vmp_bogus_salt_a__ ^ vmp_bogus_salt_b__ ^ vmp_bogus_tertiary__) | 1ull));   \
        vmp_bogus1__ =                                                                             \
            vmp::runtime::obfuscation::mba_sub_u64(vmp_bogus0__ ^ vmp_bogus_opaque_seed__,        \
                                                   vmp_bogus_tertiary__ + 7ull);                   \
      }                                                                                            \
      sink_ref = vmp::runtime::obfuscation::mba_add_u64(vmp_bogus1__,                               \
                                                        vmp_bogus0__ ^ vmp_bogus_salt_b__);        \
      sink_ref ^= vmp::runtime::obfuscation::mba_mul2_u64(                                         \
          (vmp_bogus0__ ^ vmp_bogus_opaque_seed__) | 1ull);                                        \
      sink_ref = vmp::runtime::obfuscation::mba_sub_u64(static_cast<std::uint64_t>(sink_ref),     \
                                                        vmp_bogus_tertiary__ | 1ull);              \
      sink_ref = vmp::runtime::obfuscation::mba_add_u64(static_cast<std::uint64_t>(sink_ref),     \
                                                        vmp_bogus0__ ^ (vmp_bogus_salt_a__ | 1ull)); \
      sink_ref ^= vmp::runtime::obfuscation::mba_mul2_u64(                                         \
          (vmp_bogus1__ ^ vmp_bogus_salt_b__ ^ vmp_bogus_tertiary__) | 1ull);                     \
      sink_ref = vmp::runtime::obfuscation::mba_sub_u64(static_cast<std::uint64_t>(sink_ref),     \
                                                        vmp_bogus_opaque_seed__ ^ 0x101ull);       \
    } else {                                                                                       \
      sink_ref ^= ((vmp_bogus_opaque_seed__ ^ vmp_bogus_salt_a__ ^ vmp_bogus_salt_b__ ^          \
                    vmp_bogus_tertiary__) &                                                         \
                   0ull);                                                                          \
      sink_ref += (((vmp_bogus_salt_a__ >> 3u) ^ (vmp_bogus_salt_b__ << 1u) ^                      \
                    vmp_bogus_tertiary__) &                                                         \
                   0ull);                                                                          \
    }                                                                                              \
  } while (false)

template <unsigned Variant>
inline void apply_handler_bogus_flow(volatile std::uint64_t& sink,
                                     bool real_path,
                                     std::uint64_t opaque_seed,
                                     std::uint64_t salt_a,
                                     std::uint64_t salt_b,
                                     std::uint64_t tertiary) noexcept {
  VMP_APPLY_HANDLER_BOGUS_FLOW(Variant, sink, real_path, opaque_seed, salt_a, salt_b, tertiary);
}

}  // namespace vmp::runtime::obfuscation
