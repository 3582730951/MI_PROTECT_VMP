#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vmp/bindings/cpp/annotate.h>

#if defined(_WIN32)
#define VMP_EXPORT
#define VMP_NOINLINE __declspec(noinline)
#else
#define VMP_EXPORT
#define VMP_NOINLINE __attribute__((noinline))
#endif

const char kTargetCString[] = "c-target::runtime::delta-42";
VMP_VM_STRING VMP_EXPORT const char kProtectedCString[] = "c-target::vm-string::delta-42";

static uint64_t rotl64(uint64_t value, unsigned bits) {
  bits &= 63u;
  if (bits == 0u) {
    return value;
  }
  return (value << bits) | (value >> (64u - bits));
}

static uint64_t fib40_value(void) {
  uint64_t a = 0;
  uint64_t b = 1;
  for (unsigned i = 0; i < 40u; ++i) {
    const uint64_t next = a + b;
    a = b;
    b = next;
  }
  return a;
}

VMP_VM_FUNC VMP_EXPORT VMP_NOINLINE uint64_t protected_mix_c(uint64_t x, uint64_t y) {
  uint64_t value = x ^ (y * UINT64_C(0x9e3779b97f4a7c15));
  value = rotl64(value, 7u);
  value ^= (x + UINT64_C(0x51ed2705)) ^ (y << 11u);
  return value + UINT64_C(0xa24baed4963ee407);
}

static uint64_t parse_iterations(int argc, char** argv) {
  if (argc < 2) {
    return 1000u;
  }
  char* end = NULL;
  unsigned long long value = strtoull(argv[1], &end, 10);
  if (end == argv[1] || (end && *end != '\0') || value == 0ull) {
    return 1000u;
  }
  return (uint64_t)value;
}

int main(int argc, char** argv) {
  const uint64_t iterations = parse_iterations(argc, argv);
  const uint64_t fib40 = fib40_value();
  const size_t secret_len = strlen(kTargetCString);
  uint64_t checksum = UINT64_C(0x123456789abcdef0);

  for (uint64_t i = 0; i < iterations; ++i) {
    const size_t block_len = 24u + (size_t)(i & 7u);
    unsigned char* block = (unsigned char*)malloc(block_len);
    if (!block) {
      fputs("target_c allocation failure\n", stderr);
      return 2;
    }

    uint64_t local = 0;
    for (size_t j = 0; j < block_len; ++j) {
      block[j] = (unsigned char)(((i * 3u) + (uint64_t)(j * 7u) + (unsigned char)kTargetCString[j % secret_len]) & 0xffu);
      local += block[j];
    }

    checksum ^= (fib40 + local + i) * UINT64_C(0x9e3779b185ebca87);
    checksum = rotl64(checksum, (unsigned)((i % 13u) + 1u));
    checksum += protected_mix_c(local + fib40, secret_len + i);
    checksum ^= (uint64_t)block[i % block_len] << ((i % 8u) * 8u);
    free(block);
  }

  printf("target_c fib40=%" PRIu64 " checksum=%" PRIu64 " secret_len=%llu\n", fib40, checksum, (unsigned long long)secret_len);
  return 0;
}
