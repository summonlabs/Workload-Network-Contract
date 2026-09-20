// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Inline definitions for the identity templates. Included by identity.hpp.

#ifndef WNC_IDENTITY_INL
#define WNC_IDENTITY_INL

namespace wnc {

namespace detail {

constexpr char kLowerHexDigits[] = "0123456789abcdef";
constexpr char kUpperHexDigits[] = "0123456789ABCDEF";

// Converts one hex digit to its nibble value. Accepts both cases because
// externally supplied identities may arrive in either case; internal storage
// is normalised to lowercase.
constexpr int hex_digit_value(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

template <class Tag>
std::optional<Id<Tag>> parse_id(std::string_view text) noexcept {
  if (text.size() != kSha256HexChars) {
    return std::nullopt;
  }
  std::array<char, kSha256HexChars> chars{};
  for (std::size_t i = 0; i < kSha256HexChars; ++i) {
    const int value = hex_digit_value(text[i]);
    if (value < 0) {
      return std::nullopt;
    }
    chars[i] = kLowerHexDigits[static_cast<std::size_t>(value)];
  }
  return Id<Tag>::from_chars(chars);
}

}  // namespace detail

template <class Tag>
std::optional<Id<Tag>> Id<Tag>::parse(std::string_view text) noexcept {
  return detail::parse_id<Tag>(text);
}

template <class Tag>
Id<Tag> Id<Tag>::from_digest(const Digest& digest) noexcept {
  std::array<char, kSha256HexChars> chars{};
  for (std::size_t i = 0; i < digest.size(); ++i) {
    const auto byte = static_cast<std::size_t>(digest[i]);
    chars[i * 2] = detail::kLowerHexDigits[byte >> 4];
    chars[i * 2 + 1] = detail::kLowerHexDigits[byte & 0x0Fu];
  }
  return Id<Tag>::from_chars(chars);
}

}  // namespace wnc

#endif  // WNC_IDENTITY_INL
