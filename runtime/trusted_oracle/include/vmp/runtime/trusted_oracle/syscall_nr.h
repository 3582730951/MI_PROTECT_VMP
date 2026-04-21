#pragma once

#include <cstdint>

namespace vmp::runtime::trusted_oracle::sysnr {

enum class Abi : std::uint8_t {
  unsupported = 0,
  linux_x64,
  linux_arm64,
  windows_x64,
  ios_arm64,
};

#if defined(__linux__) && defined(__x86_64__)
inline constexpr Abi kCurrentAbi = Abi::linux_x64;
inline constexpr std::uint64_t kRead = 0;
inline constexpr std::uint64_t kOpen = 2;
inline constexpr std::uint64_t kClose = 3;
inline constexpr std::uint64_t kRtSigaction = 13;
inline constexpr std::uint64_t kClockGettime = 228;
inline constexpr std::uint64_t kPtrace = 101;
inline constexpr std::uint64_t kPrctl = 157;
inline constexpr std::uint64_t kArchPrctl = 158;
inline constexpr std::uint64_t kGettid = 186;
inline constexpr std::uint64_t kGetrandom = 318;
inline constexpr bool kHasOpenAtFallback = false;
inline constexpr std::uint64_t kOpenAt = 257;
#elif defined(__linux__) && defined(__aarch64__)
inline constexpr Abi kCurrentAbi = Abi::linux_arm64;
inline constexpr std::uint64_t kRead = 63;
inline constexpr std::uint64_t kOpen = static_cast<std::uint64_t>(-1);
inline constexpr std::uint64_t kClose = 57;
inline constexpr std::uint64_t kRtSigaction = 134;
inline constexpr std::uint64_t kClockGettime = 113;
inline constexpr std::uint64_t kPtrace = 117;
inline constexpr std::uint64_t kPrctl = 167;
inline constexpr std::uint64_t kArchPrctl = static_cast<std::uint64_t>(-1);
inline constexpr std::uint64_t kGettid = 178;
inline constexpr std::uint64_t kGetrandom = 278;
inline constexpr bool kHasOpenAtFallback = true;
inline constexpr std::uint64_t kOpenAt = 56;
#elif defined(_WIN32) && defined(_M_X64)
inline constexpr Abi kCurrentAbi = Abi::windows_x64;
inline constexpr std::uint64_t kRead = 0;
inline constexpr std::uint64_t kOpen = 0;
inline constexpr std::uint64_t kClose = 0;
inline constexpr std::uint64_t kRtSigaction = 0;
inline constexpr std::uint64_t kClockGettime = 0;
inline constexpr std::uint64_t kPtrace = 0;
inline constexpr std::uint64_t kPrctl = 0;
inline constexpr std::uint64_t kArchPrctl = 0;
inline constexpr std::uint64_t kGettid = 0;
inline constexpr std::uint64_t kGetrandom = 0;
inline constexpr bool kHasOpenAtFallback = false;
inline constexpr std::uint64_t kOpenAt = 0;
#elif defined(__APPLE__) && defined(__aarch64__)
inline constexpr Abi kCurrentAbi = Abi::ios_arm64;
inline constexpr std::uint64_t kRead = 3;
inline constexpr std::uint64_t kOpen = 5;
inline constexpr std::uint64_t kClose = 6;
inline constexpr std::uint64_t kRtSigaction = 46;
inline constexpr std::uint64_t kClockGettime = 116;
inline constexpr std::uint64_t kPtrace = 26;
inline constexpr std::uint64_t kPrctl = 0;
inline constexpr std::uint64_t kArchPrctl = 0;
inline constexpr std::uint64_t kGettid = 286;
inline constexpr std::uint64_t kGetrandom = 500;
inline constexpr bool kHasOpenAtFallback = false;
inline constexpr std::uint64_t kOpenAt = 0;
#else
inline constexpr Abi kCurrentAbi = Abi::unsupported;
inline constexpr std::uint64_t kRead = 0;
inline constexpr std::uint64_t kOpen = 0;
inline constexpr std::uint64_t kClose = 0;
inline constexpr std::uint64_t kRtSigaction = 0;
inline constexpr std::uint64_t kClockGettime = 0;
inline constexpr std::uint64_t kPtrace = 0;
inline constexpr std::uint64_t kPrctl = 0;
inline constexpr std::uint64_t kArchPrctl = 0;
inline constexpr std::uint64_t kGettid = 0;
inline constexpr std::uint64_t kGetrandom = 0;
inline constexpr bool kHasOpenAtFallback = false;
inline constexpr std::uint64_t kOpenAt = 0;
#endif

}  // namespace vmp::runtime::trusted_oracle::sysnr
