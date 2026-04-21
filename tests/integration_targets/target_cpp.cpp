#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <vmp/bindings/cpp/annotate.h>

#if defined(_WIN32)
#define VMP_EXPORT
#define VMP_NOINLINE __declspec(noinline)
#else
#define VMP_EXPORT
#define VMP_NOINLINE __attribute__((noinline))
#endif

extern "C" const char kTargetCppString[] = "cpp-target::runtime::omega-17";
extern "C" VMP_VM_STRING VMP_EXPORT const char kProtectedCppString[] = "cpp-target::vm-string::omega-17";

static std::uint64_t rotl64(std::uint64_t value, unsigned bits) {
  bits &= 63u;
  if (bits == 0u) {
    return value;
  }
  return (value << bits) | (value >> (64u - bits));
}

static std::uint64_t fib40_value() {
  std::uint64_t a = 0;
  std::uint64_t b = 1;
  for (unsigned i = 0; i < 40u; ++i) {
    const auto next = a + b;
    a = b;
    b = next;
  }
  return a;
}

template <typename T, std::size_t N>
static void insertion_sort(std::array<T, N>& values) {
  for (std::size_t i = 1; i < N; ++i) {
    const T key = values[i];
    std::size_t j = i;
    while (j > 0 && values[j - 1] > key) {
      values[j] = values[j - 1];
      --j;
    }
    values[j] = key;
  }
}

extern "C" VMP_VM_FUNC VMP_VM_STRING VMP_EXPORT VMP_NOINLINE std::uint64_t protected_mix_cpp(std::uint64_t x,
                                                                                                  std::uint64_t y) {
  std::uint64_t value = (x + UINT64_C(0x6a09e667f3bcc909)) ^ (y * UINT64_C(0x100000001b3));
  value = rotl64(value, 9u);
  return value ^ (x << 5u) ^ (y << 17u);
}

static std::uint64_t parse_iterations(int argc, char** argv) {
  if (argc < 2) {
    return 1000u;
  }
  char* end = nullptr;
  unsigned long long value = std::strtoull(argv[1], &end, 10);
  if (end == argv[1] || (end && *end != '\0') || value == 0ull) {
    return 1000u;
  }
  return static_cast<std::uint64_t>(value);
}

int main(int argc, char** argv) {
  const auto iterations = parse_iterations(argc, argv);
  const auto fib40 = fib40_value();
  const std::string secret = kTargetCppString;
  std::uint64_t checksum = UINT64_C(0xcafebabe12345678);

  for (std::uint64_t i = 0; i < iterations; ++i) {
    std::array<int, 4> values{{
        static_cast<int>((static_cast<unsigned char>(secret[0]) + i) % 97u),
        static_cast<int>((static_cast<unsigned char>(secret[1]) + i * 2u) % 97u),
        static_cast<int>((static_cast<unsigned char>(secret[2]) + i * 3u) % 97u),
        static_cast<int>((static_cast<unsigned char>(secret[3]) + i * 4u) % 97u),
    }};
    insertion_sort(values);

    try {
      const auto start = static_cast<std::size_t>(i % 3u);
      std::string joined = secret.substr(start, 3u);
      if (joined.size() < 2u) {
        throw static_cast<int>(i);
      }
      checksum ^= protected_mix_cpp(fib40 + joined.size(), static_cast<std::uint64_t>(values.back()) + i);
      checksum = rotl64(checksum, static_cast<unsigned>((i % 7u) + 1u));
      checksum += static_cast<unsigned char>(joined.front());
      checksum += static_cast<std::uint64_t>(values.front() + values.back());
    } catch (...) {
      checksum ^= UINT64_C(0xdeadbeefcafef00d);
    }
  }

  std::printf("target_cpp fib40=%llu checksum=%llu secret_len=%llu\n",
              static_cast<unsigned long long>(fib40),
              static_cast<unsigned long long>(checksum),
              static_cast<unsigned long long>(secret.size()));
  return 0;
}
