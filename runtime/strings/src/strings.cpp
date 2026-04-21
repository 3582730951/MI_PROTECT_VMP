#include <vmp/runtime/strings/cipher.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <random>
#include <sstream>
#include <stdexcept>

#if !defined(_WIN32)
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <vmp/runtime/strings/keyctx.h>

namespace vmp::runtime::strings {
namespace {

thread_local StringPool* g_current_pool = nullptr;
std::atomic<bool> g_plaintext_budget_lock{false};

constexpr std::array<std::uint32_t, 8> kSha256Init{{
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
}};

constexpr std::array<std::uint32_t, 64> kSha256K{{
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u,
}};

inline std::uint32_t rotl32(std::uint32_t x, int n) noexcept { return (x << n) | (x >> (32 - n)); }
inline std::uint32_t rotr32(std::uint32_t x, int n) noexcept { return (x >> n) | (x << (32 - n)); }

std::array<std::uint32_t, 16> chacha_state(const std::array<std::uint8_t, 32>& key,
                                           const Nonce& nonce,
                                           std::uint32_t counter) {
  std::array<std::uint32_t, 16> state{{0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u}};
  for (std::size_t i = 0; i < 8; ++i) {
    state[4 + i] = static_cast<std::uint32_t>(key[i * 4]) |
                   (static_cast<std::uint32_t>(key[i * 4 + 1]) << 8u) |
                   (static_cast<std::uint32_t>(key[i * 4 + 2]) << 16u) |
                   (static_cast<std::uint32_t>(key[i * 4 + 3]) << 24u);
  }
  state[12] = counter;
  state[13] = static_cast<std::uint32_t>(nonce[0]) | (static_cast<std::uint32_t>(nonce[1]) << 8u) |
              (static_cast<std::uint32_t>(nonce[2]) << 16u) | (static_cast<std::uint32_t>(nonce[3]) << 24u);
  state[14] = static_cast<std::uint32_t>(nonce[4]) | (static_cast<std::uint32_t>(nonce[5]) << 8u) |
              (static_cast<std::uint32_t>(nonce[6]) << 16u) | (static_cast<std::uint32_t>(nonce[7]) << 24u);
  state[15] = static_cast<std::uint32_t>(nonce[8]) | (static_cast<std::uint32_t>(nonce[9]) << 8u) |
              (static_cast<std::uint32_t>(nonce[10]) << 16u) | (static_cast<std::uint32_t>(nonce[11]) << 24u);
  return state;
}

void quarter_round(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) {
  a += b; d ^= a; d = rotl32(d, 16);
  c += d; b ^= c; b = rotl32(b, 12);
  a += b; d ^= a; d = rotl32(d, 8);
  c += d; b ^= c; b = rotl32(b, 7);
}

std::array<std::uint8_t, 64> chacha20_block(const std::array<std::uint8_t, 32>& key,
                                            const Nonce& nonce,
                                            std::uint32_t counter) {
  auto working = chacha_state(key, nonce, counter);
  const auto initial = working;
  for (int i = 0; i < 10; ++i) {
    quarter_round(working[0], working[4], working[8], working[12]);
    quarter_round(working[1], working[5], working[9], working[13]);
    quarter_round(working[2], working[6], working[10], working[14]);
    quarter_round(working[3], working[7], working[11], working[15]);
    quarter_round(working[0], working[5], working[10], working[15]);
    quarter_round(working[1], working[6], working[11], working[12]);
    quarter_round(working[2], working[7], working[8], working[13]);
    quarter_round(working[3], working[4], working[9], working[14]);
  }
  std::array<std::uint8_t, 64> out{};
  for (std::size_t i = 0; i < 16; ++i) {
    const auto word = working[i] + initial[i];
    out[i * 4] = static_cast<std::uint8_t>(word & 0xffu);
    out[i * 4 + 1] = static_cast<std::uint8_t>((word >> 8u) & 0xffu);
    out[i * 4 + 2] = static_cast<std::uint8_t>((word >> 16u) & 0xffu);
    out[i * 4 + 3] = static_cast<std::uint8_t>((word >> 24u) & 0xffu);
  }
  return out;
}

std::array<std::uint8_t, 32> as_key32(const std::vector<std::uint8_t>& key) {
  if (key.size() != 32) {
    throw std::runtime_error("strings: key must be 32 bytes");
  }
  std::array<std::uint8_t, 32> out{};
  std::copy(key.begin(), key.end(), out.begin());
  return out;
}

std::uint32_t read_le32(const std::uint8_t* ptr) noexcept {
  return static_cast<std::uint32_t>(ptr[0]) | (static_cast<std::uint32_t>(ptr[1]) << 8u) |
         (static_cast<std::uint32_t>(ptr[2]) << 16u) | (static_cast<std::uint32_t>(ptr[3]) << 24u);
}

void write_le32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 24u) & 0xffu));
}

std::vector<std::uint8_t> concat_nonce_record(const Nonce& nonce, const std::vector<std::uint8_t>& record) {
  std::vector<std::uint8_t> data;
  data.insert(data.end(), nonce.begin(), nonce.end());
  data.insert(data.end(), record.begin(), record.end());
  return data;
}

std::vector<std::uint8_t> random_bytes(std::size_t size) {
  std::vector<std::uint8_t> out(size);
  std::random_device rd;
  for (auto& b : out) {
    b = static_cast<std::uint8_t>(rd());
  }
  return out;
}

}  // namespace

void secure_memzero(void* ptr, std::size_t size) noexcept {
  if (ptr == nullptr || size == 0) {
    return;
  }
  volatile std::uint8_t* p = static_cast<volatile std::uint8_t*>(ptr);
  while (size-- > 0) {
    *p++ = 0;
  }
  std::atomic_signal_fence(std::memory_order_seq_cst);
}

std::vector<std::uint8_t> to_bytes(std::string_view text) {
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

std::string hex_encode(const std::vector<std::uint8_t>& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (auto byte : bytes) {
    out.push_back(kHex[(byte >> 4) & 0x0f]);
    out.push_back(kHex[byte & 0x0f]);
  }
  return out;
}

std::vector<std::uint8_t> hex_decode(const std::string& hex) {
  auto nibble = [](char ch) -> std::uint8_t {
    if (ch >= '0' && ch <= '9') return static_cast<std::uint8_t>(ch - '0');
    if (ch >= 'a' && ch <= 'f') return static_cast<std::uint8_t>(10 + ch - 'a');
    if (ch >= 'A' && ch <= 'F') return static_cast<std::uint8_t>(10 + ch - 'A');
    throw std::runtime_error("strings: invalid hex");
  };
  if (hex.size() % 2 != 0) {
    throw std::runtime_error("strings: hex length must be even");
  }
  std::vector<std::uint8_t> out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4u) | nibble(hex[i + 1])));
  }
  return out;
}

void set_global_plaintext_budget_lock(bool locked) noexcept { g_plaintext_budget_lock.store(locked, std::memory_order_release); }

bool global_plaintext_budget_locked() noexcept { return g_plaintext_budget_lock.load(std::memory_order_acquire); }

Nonce u32_to_nonce(std::uint32_t value) noexcept {
  Nonce nonce{};
  nonce[0] = static_cast<std::uint8_t>(value & 0xffu);
  nonce[1] = static_cast<std::uint8_t>((value >> 8u) & 0xffu);
  nonce[2] = static_cast<std::uint8_t>((value >> 16u) & 0xffu);
  nonce[3] = static_cast<std::uint8_t>((value >> 24u) & 0xffu);
  nonce[11] = 0x42;
  return nonce;
}

bool constant_time_equal(const std::uint8_t* lhs, const std::uint8_t* rhs, std::size_t size) noexcept {
  if (lhs == nullptr || rhs == nullptr) {
    return lhs == rhs && size == 0;
  }
  volatile std::uint8_t diff = 0;
  for (std::size_t i = 0; i < size; ++i) {
    diff |= static_cast<std::uint8_t>(lhs[i] ^ rhs[i]);
  }
  return diff == 0;
}

bool constant_time_equal(const std::vector<std::uint8_t>& lhs, const std::vector<std::uint8_t>& rhs) noexcept {
  volatile std::uint8_t diff = static_cast<std::uint8_t>(lhs.size() ^ rhs.size());
  const auto limit = std::max(lhs.size(), rhs.size());
  for (std::size_t i = 0; i < limit; ++i) {
    const auto l = i < lhs.size() ? lhs[i] : 0u;
    const auto r = i < rhs.size() ? rhs[i] : 0u;
    diff |= static_cast<std::uint8_t>(l ^ r);
  }
  return diff == 0;
}

std::vector<std::uint8_t> sha256(const std::vector<std::uint8_t>& data) {
  std::vector<std::uint8_t> padded = data;
  const std::uint64_t bit_len = static_cast<std::uint64_t>(padded.size()) * 8u;
  padded.push_back(0x80u);
  while ((padded.size() % 64u) != 56u) {
    padded.push_back(0);
  }
  for (int shift = 56; shift >= 0; shift -= 8) {
    padded.push_back(static_cast<std::uint8_t>((bit_len >> shift) & 0xffu));
  }

  auto h = kSha256Init;
  std::array<std::uint32_t, 64> w{};
  for (std::size_t offset = 0; offset < padded.size(); offset += 64) {
    for (int i = 0; i < 16; ++i) {
      const auto* ptr = padded.data() + offset + static_cast<std::size_t>(i * 4);
      w[i] = (static_cast<std::uint32_t>(ptr[0]) << 24u) | (static_cast<std::uint32_t>(ptr[1]) << 16u) |
             (static_cast<std::uint32_t>(ptr[2]) << 8u) | static_cast<std::uint32_t>(ptr[3]);
    }
    for (int i = 16; i < 64; ++i) {
      const std::uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    auto a = h[0]; auto b = h[1]; auto c = h[2]; auto d = h[3];
    auto e = h[4]; auto f = h[5]; auto g = h[6]; auto hh = h[7];
    for (int i = 0; i < 64; ++i) {
      const std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const std::uint32_t ch = (e & f) ^ ((~e) & g);
      const std::uint32_t temp1 = hh + S1 + ch + kSha256K[i] + w[i];
      const std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temp2 = S0 + maj;
      hh = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }

  std::vector<std::uint8_t> out(32);
  for (std::size_t i = 0; i < h.size(); ++i) {
    out[i * 4] = static_cast<std::uint8_t>((h[i] >> 24u) & 0xffu);
    out[i * 4 + 1] = static_cast<std::uint8_t>((h[i] >> 16u) & 0xffu);
    out[i * 4 + 2] = static_cast<std::uint8_t>((h[i] >> 8u) & 0xffu);
    out[i * 4 + 3] = static_cast<std::uint8_t>(h[i] & 0xffu);
  }
  return out;
}

std::vector<std::uint8_t> hmac_sha256(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& data) {
  std::vector<std::uint8_t> block = key;
  if (block.size() > 64) {
    block = sha256(block);
  }
  block.resize(64, 0);
  std::vector<std::uint8_t> ipad(64, 0x36u);
  std::vector<std::uint8_t> opad(64, 0x5cu);
  for (std::size_t i = 0; i < 64; ++i) {
    ipad[i] ^= block[i];
    opad[i] ^= block[i];
  }
  ipad.insert(ipad.end(), data.begin(), data.end());
  auto inner = sha256(ipad);
  opad.insert(opad.end(), inner.begin(), inner.end());
  auto out = sha256(opad);
  secure_memzero(block.data(), block.size());
  secure_memzero(ipad.data(), ipad.size());
  secure_memzero(opad.data(), opad.size());
  secure_memzero(inner.data(), inner.size());
  return out;
}

std::vector<std::uint8_t> hkdf_extract_sha256(const std::vector<std::uint8_t>& salt,
                                              const std::vector<std::uint8_t>& ikm) {
  std::vector<std::uint8_t> real_salt = salt;
  if (real_salt.empty()) {
    real_salt.assign(32, 0);
  }
  return hmac_sha256(real_salt, ikm);
}

std::vector<std::uint8_t> hkdf_expand_sha256(const std::vector<std::uint8_t>& prk,
                                             const std::vector<std::uint8_t>& info,
                                             std::size_t out_len) {
  if (out_len == 0) {
    return {};
  }
  if (out_len > 255u * 32u) {
    throw std::runtime_error("strings: hkdf output too large");
  }
  std::vector<std::uint8_t> out;
  std::vector<std::uint8_t> t;
  std::uint8_t counter = 1;
  while (out.size() < out_len) {
    std::vector<std::uint8_t> input = t;
    input.insert(input.end(), info.begin(), info.end());
    input.push_back(counter++);
    t = hmac_sha256(prk, input);
    const auto to_copy = std::min<std::size_t>(t.size(), out_len - out.size());
    out.insert(out.end(), t.begin(), t.begin() + static_cast<std::ptrdiff_t>(to_copy));
  }
  secure_memzero(t.data(), t.size());
  return out;
}

std::vector<std::uint8_t> chacha20_xor(const std::vector<std::uint8_t>& key,
                                       const Nonce& nonce,
                                       std::uint32_t counter,
                                       const std::vector<std::uint8_t>& input) {
  const auto key32 = as_key32(key);
  std::vector<std::uint8_t> out(input.size());
  std::size_t offset = 0;
  std::uint32_t block_counter = counter;
  while (offset < input.size()) {
    const auto block = chacha20_block(key32, nonce, block_counter++);
    const auto block_len = std::min<std::size_t>(64, input.size() - offset);
    for (std::size_t i = 0; i < block_len; ++i) {
      out[offset + i] = static_cast<std::uint8_t>(input[offset + i] ^ block[i]);
    }
    offset += block_len;
  }
  return out;
}

EncryptedStringRecord encrypt_string_record(const std::array<std::uint8_t, 32>& key,
                                            const Nonce& nonce,
                                            const std::vector<std::uint8_t>& plaintext) {
  if (plaintext.size() > 0xffff'ffffu - 4u) {
    throw std::runtime_error("strings: plaintext too large");
  }
  std::vector<std::uint8_t> payload;
  payload.reserve(4 + plaintext.size());
  write_le32(payload, static_cast<std::uint32_t>(plaintext.size()));
  payload.insert(payload.end(), plaintext.begin(), plaintext.end());
  const auto enc = chacha20_xor(std::vector<std::uint8_t>(key.begin(), key.end()), nonce, 0, payload);
  const auto tag = hmac_sha256(std::vector<std::uint8_t>(key.begin(), key.end()), concat_nonce_record(nonce, enc));
  EncryptedStringRecord out;
  out.ciphertext = enc;
  out.ciphertext.insert(out.ciphertext.end(), tag.begin(), tag.end());
  secure_memzero(payload.data(), payload.size());
  return out;
}

std::vector<std::uint8_t> decrypt_string_record(const std::array<std::uint8_t, 32>& key,
                                                const Nonce& nonce,
                                                const std::vector<std::uint8_t>& record) {
  if (record.size() < 4 + 32) {
    throw std::runtime_error("strings: encrypted record too small");
  }
  const auto enc_len = record.size() - 32u;
  std::vector<std::uint8_t> enc(record.begin(), record.begin() + static_cast<std::ptrdiff_t>(enc_len));
  std::vector<std::uint8_t> tag(record.begin() + static_cast<std::ptrdiff_t>(enc_len), record.end());
  const auto expected = hmac_sha256(std::vector<std::uint8_t>(key.begin(), key.end()), concat_nonce_record(nonce, enc));
  if (!constant_time_equal(expected, tag)) {
    secure_memzero(enc.data(), enc.size());
    throw std::runtime_error("strings: authentication failed");
  }
  auto payload = chacha20_xor(std::vector<std::uint8_t>(key.begin(), key.end()), nonce, 0, enc);
  const auto plain_len = read_le32(payload.data());
  if (payload.size() != 4u + plain_len) {
    secure_memzero(payload.data(), payload.size());
    throw std::runtime_error("strings: length prefix mismatch");
  }
  std::vector<std::uint8_t> plaintext(payload.begin() + 4, payload.end());
  secure_memzero(enc.data(), enc.size());
  secure_memzero(payload.data(), payload.size());
  return plaintext;
}

TransientView::TransientView(std::vector<std::uint8_t> plaintext) {
  size_ = plaintext.size();
  if (size_ <= kTransientInlineLimit) {
    uses_inline_ = true;
    data_ = inline_storage_.data();
  } else {
    allocate_large(size_);
  }
  if (size_ != 0) {
    std::memcpy(data_, plaintext.data(), size_);
    secure_memzero(plaintext.data(), plaintext.size());
  }
}

TransientView::~TransientView() { reset(); }

TransientView::TransientView(TransientView&& other) noexcept { move_from(std::move(other)); }

TransientView& TransientView::operator=(TransientView&& other) noexcept {
  if (this != &other) {
    reset();
    move_from(std::move(other));
  }
  return *this;
}

std::vector<std::uint8_t> TransientView::debug_zeroized_snapshot() {
  std::vector<std::uint8_t> snapshot;
  if (data_ == nullptr) {
    return snapshot;
  }
  secure_memzero(data_, size_);
  snapshot.assign(data_, data_ + static_cast<std::ptrdiff_t>(size_));
#if !defined(_WIN32)
  if (!uses_inline_ && mapped_region_ != nullptr) {
    ::munlock(mapped_region_, mapped_size_);
    ::munmap(mapped_region_, mapped_size_);
  }
#endif
  data_ = nullptr;
  size_ = 0;
  mapped_region_ = nullptr;
  mapped_size_ = 0;
  uses_inline_ = true;
  return snapshot;
}

void TransientView::allocate_large(std::size_t size) {
#if defined(_WIN32)
  throw std::runtime_error("strings: large transient buffers unsupported on this platform");
#else
  mapped_size_ = size;
  mapped_region_ = ::mmap(nullptr, mapped_size_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapped_region_ == MAP_FAILED) {
    mapped_region_ = nullptr;
    throw std::runtime_error(std::string("strings: mmap failed: ") + std::strerror(errno));
  }
  (void)::mlock(mapped_region_, mapped_size_);
  data_ = static_cast<std::uint8_t*>(mapped_region_);
  uses_inline_ = false;
#endif
}

void TransientView::move_from(TransientView&& other) noexcept {
  size_ = other.size_;
  uses_inline_ = other.uses_inline_;
  mapped_region_ = other.mapped_region_;
  mapped_size_ = other.mapped_size_;
  if (other.uses_inline_) {
    std::copy(other.inline_storage_.begin(), other.inline_storage_.end(), inline_storage_.begin());
    data_ = inline_storage_.data();
    secure_memzero(other.inline_storage_.data(), other.inline_storage_.size());
  } else {
    data_ = other.data_;
  }
  other.data_ = nullptr;
  other.size_ = 0;
  other.mapped_region_ = nullptr;
  other.mapped_size_ = 0;
  other.uses_inline_ = true;
}

void TransientView::reset() noexcept {
  if (data_ == nullptr) {
    return;
  }
  secure_memzero(data_, size_);
#if !defined(_WIN32)
  if (!uses_inline_ && mapped_region_ != nullptr) {
    ::munlock(mapped_region_, mapped_size_);
    ::munmap(mapped_region_, mapped_size_);
  }
#endif
  data_ = nullptr;
  size_ = 0;
  mapped_region_ = nullptr;
  mapped_size_ = 0;
  uses_inline_ = true;
}

StringPool::StringPool(std::vector<std::uint8_t> ciphertext, IndexMap idx, KeyContext key)
    : ciphertext_(std::move(ciphertext)), idx_(std::move(idx)), key_(std::make_shared<KeyContext>(std::move(key))) {}

TransientView StringPool::decrypt(std::uint32_t string_id) const {
  const auto it = idx_.find(string_id);
  if (it == idx_.end()) {
    fail("strings: string id not found", "string_pool_error");
  }
  if (global_plaintext_budget_locked()) {
    fail("strings: global plaintext budget lock forbids decrypt", "plaintext_budget_violation");
  }
  if (it->second.plaintext_budget == vmp::policy::PlaintextBudget::none) {
    fail("strings: plaintext_budget none forbids decrypt", "plaintext_budget_violation");
  }
  const auto end = static_cast<std::size_t>(it->second.offset) + static_cast<std::size_t>(it->second.length);
  if (end > ciphertext_.size()) {
    fail("strings: pool index out of range", "string_pool_error");
  }
  try {
    const auto subkey = key_->derive_subkey("string-pool");
    std::vector<std::uint8_t> record(ciphertext_.begin() + static_cast<std::ptrdiff_t>(it->second.offset),
                                     ciphertext_.begin() + static_cast<std::ptrdiff_t>(end));
    return TransientView(decrypt_string_record(subkey.bytes(), it->second.nonce, record));
  } catch (const std::exception& ex) {
    fail(ex.what(), "string_pool_error");
  }
}

void StringPool::set_audit_dispatcher(vmp::runtime::audit::ReactionDispatcher* dispatcher) noexcept {
  audit_dispatcher_.store(dispatcher, std::memory_order_release);
}

[[noreturn]] void StringPool::fail(const std::string& message, const char* event_type) const {
  if (auto* dispatcher = audit_dispatcher_.load(std::memory_order_acquire); dispatcher != nullptr) {
    dispatcher->dispatch(vmp::runtime::audit::make_event(event_type, message, 0, "strings", "", 0),
                         vmp::runtime::audit::ReactionPolicy::audit_only);
  }
  throw std::runtime_error(message);
}

ScopedCurrentPool::ScopedCurrentPool(StringPool& pool) noexcept : previous_(g_current_pool) { g_current_pool = &pool; }
ScopedCurrentPool::~ScopedCurrentPool() { g_current_pool = previous_; }

StringPool& current_string_pool() {
  if (g_current_pool == nullptr) {
    throw std::runtime_error("strings: no current string pool bound");
  }
  return *g_current_pool;
}

const char* Facade::status() const noexcept { return "strings_ready"; }

}  // namespace vmp::runtime::strings
