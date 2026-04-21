#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace vmp::runtime::strings::obf {
namespace detail {

constexpr std::uint32_t fnv1a_step(std::uint32_t hash, unsigned char ch) noexcept {
  return (hash ^ ch) * 16777619u;
}

constexpr std::uint32_t fnv1a_file_hash(const char* text, std::size_t index = 0, std::uint32_t hash = 2166136261u) noexcept {
  return text[index] == '\0' ? hash : fnv1a_file_hash(text, index + 1u, fnv1a_step(hash, static_cast<unsigned char>(text[index])));
}

template <std::size_t N>
constexpr std::uint8_t file_key(const char (&file)[N]) noexcept {
  return static_cast<std::uint8_t>((fnv1a_file_hash(file) % 251u) + 1u);
}

template <std::size_t N, std::uint8_t Key>
struct Literal {
  std::array<std::uint8_t, N> encoded{};

  constexpr explicit Literal(const char (&text)[N]) noexcept {
    for (std::size_t i = 0; i < N; ++i) {
      encoded[i] = static_cast<std::uint8_t>(static_cast<unsigned char>(text[i]) ^ Key);
    }
  }

  [[nodiscard]] std::array<char, N> decode_stack() const noexcept {
    std::array<char, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
      out[i] = static_cast<char>(encoded[i] ^ Key);
    }
    return out;
  }

  [[nodiscard]] std::string str() const {
    auto decoded = decode_stack();
    return std::string(decoded.data(), N - 1u);
  }
};

template <std::uint8_t Key, std::size_t N>
constexpr auto make_literal(const char (&text)[N]) noexcept {
  return Literal<N, Key>(text);
}

}  // namespace detail

template <typename T>
[[nodiscard]] inline std::string decode(const T& literal) {
  return literal.str();
}

}  // namespace vmp::runtime::strings::obf

#define VMP_OBFSTR(literal) \
  ::vmp::runtime::strings::obf::detail::make_literal< \
      ::vmp::runtime::strings::obf::detail::file_key(__FILE__)>(literal)
