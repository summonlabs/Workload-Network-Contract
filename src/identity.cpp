// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/identity.hpp"

#include <chrono>
#include <cstdio>
#include <random>
#include <stdexcept>

#include "wnc/hash.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace wnc {
namespace {

constexpr char kBase64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int base64url_value(char c) noexcept {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '-') {
    return 62;
  }
  if (c == '_') {
    return 63;
  }
  return -1;
}

}  // namespace

std::string hex_encode(std::span<const std::uint8_t> bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const std::uint8_t byte : bytes) {
    out.push_back(kDigits[byte >> 4]);
    out.push_back(kDigits[byte & 0x0Fu]);
  }
  return out;
}

std::string hex_encode(const Digest& digest) {
  return hex_encode(std::span<const std::uint8_t>(digest.data(), digest.size()));
}

std::optional<Digest> hex_decode_digest(std::string_view text) noexcept {
  if (text.size() != kSha256HexChars) {
    return std::nullopt;
  }
  Digest out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    const char high = text[i * 2];
    const char low = text[i * 2 + 1];
    int high_value = -1;
    int low_value = -1;
    if (high >= '0' && high <= '9') {
      high_value = high - '0';
    } else if (high >= 'a' && high <= 'f') {
      high_value = high - 'a' + 10;
    } else if (high >= 'A' && high <= 'F') {
      high_value = high - 'A' + 10;
    }
    if (low >= '0' && low <= '9') {
      low_value = low - '0';
    } else if (low >= 'a' && low <= 'f') {
      low_value = low - 'a' + 10;
    } else if (low >= 'A' && low <= 'F') {
      low_value = low - 'A' + 10;
    }
    if (high_value < 0 || low_value < 0) {
      return std::nullopt;
    }
    out[i] = static_cast<std::uint8_t>((high_value << 4) | low_value);
  }
  return out;
}

std::string base64url_encode(std::span<const std::uint8_t> bytes) {
  std::string out;
  out.reserve(((bytes.size() + 2) / 3) * 4);
  std::size_t index = 0;
  while (index + 3 <= bytes.size()) {
    const std::uint32_t chunk = (static_cast<std::uint32_t>(bytes[index]) << 16) |
                                (static_cast<std::uint32_t>(bytes[index + 1]) << 8) |
                                static_cast<std::uint32_t>(bytes[index + 2]);
    out.push_back(kBase64UrlAlphabet[(chunk >> 18) & 0x3Fu]);
    out.push_back(kBase64UrlAlphabet[(chunk >> 12) & 0x3Fu]);
    out.push_back(kBase64UrlAlphabet[(chunk >> 6) & 0x3Fu]);
    out.push_back(kBase64UrlAlphabet[chunk & 0x3Fu]);
    index += 3;
  }
  const std::size_t remaining = bytes.size() - index;
  if (remaining == 1) {
    const std::uint32_t chunk = static_cast<std::uint32_t>(bytes[index]) << 16;
    out.push_back(kBase64UrlAlphabet[(chunk >> 18) & 0x3Fu]);
    out.push_back(kBase64UrlAlphabet[(chunk >> 12) & 0x3Fu]);
  } else if (remaining == 2) {
    const std::uint32_t chunk = (static_cast<std::uint32_t>(bytes[index]) << 16) |
                                (static_cast<std::uint32_t>(bytes[index + 1]) << 8);
    out.push_back(kBase64UrlAlphabet[(chunk >> 18) & 0x3Fu]);
    out.push_back(kBase64UrlAlphabet[(chunk >> 12) & 0x3Fu]);
    out.push_back(kBase64UrlAlphabet[(chunk >> 6) & 0x3Fu]);
  }
  return out;
}

std::optional<std::vector<std::uint8_t>> base64url_decode(std::string_view text,
                                                          std::size_t max_bytes) {
  // The decoder accepts both padded and unpadded input but rejects any padding
  // that is not exactly the one or two characters required by the final group.
  std::size_t padding = 0;
  while (!text.empty() && text.back() == '=') {
    text.remove_suffix(1);
    ++padding;
  }
  if (padding > 2 || text.size() % 4 == 1) {
    return std::nullopt;
  }
  const std::size_t estimated = (text.size() / 4) * 3 + 3;
  if (estimated > max_bytes + 3) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> out;
  out.reserve(estimated < max_bytes ? estimated : max_bytes);

  std::uint32_t accumulator = 0;
  int bits = 0;
  for (const char c : text) {
    const int value = base64url_value(c);
    if (value < 0) {
      return std::nullopt;
    }
    accumulator = (accumulator << 6) | static_cast<std::uint32_t>(value);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((accumulator >> bits) & 0xFFu));
      if (out.size() > max_bytes) {
        return std::nullopt;
      }
    }
  }
  // Leftover bits must be zero; otherwise the input is not a canonical encoding.
  if (bits > 0 && (accumulator & ((1u << bits) - 1u)) != 0u) {
    return std::nullopt;
  }
  return out;
}

std::string format_generation(std::uint64_t value) { return "g" + std::to_string(value); }

std::optional<Incarnation> Incarnation::parse(std::string_view text) noexcept {
  const std::optional<std::vector<std::uint8_t>> decoded = base64url_decode(text, kIncarnationBytes);
  if (!decoded.has_value() || decoded->size() != kIncarnationBytes) {
    return std::nullopt;
  }
  Incarnation out;
  for (std::size_t i = 0; i < kIncarnationBytes; ++i) {
    out.bytes[i] = (*decoded)[i];
  }
  if (out.is_zero()) {
    return std::nullopt;
  }
  return out;
}

Incarnation new_incarnation() {
  Incarnation out;
  random_bytes(std::span<std::uint8_t>(out.bytes.data(), out.bytes.size()));
  if (out.is_zero()) {
    out.bytes[0] = 1;
  }
  return out;
}

Incarnation zero_incarnation() noexcept { return Incarnation{}; }

std::uint64_t machine_identity() noexcept {
  // The operating system process identifier. It is a tiebreaker mixed into
  // incarnation identifiers, never an authority by itself.
#if defined(_WIN32)
  return static_cast<std::uint64_t>(GetCurrentProcessId());
#else
  return static_cast<std::uint64_t>(getpid());
#endif
}

void random_bytes(std::span<std::uint8_t> out) {
  if (out.empty()) {
    return;
  }
  std::random_device device;
  std::size_t index = 0;
  while (index < out.size()) {
    const unsigned value = device();
    out[index] = static_cast<std::uint8_t>(value & 0xFFu);
    ++index;
    if (index < out.size()) {
      out[index] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
      ++index;
    }
    if (index < out.size()) {
      out[index] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
      ++index;
    }
    if (index < out.size()) {
      out[index] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
      ++index;
    }
  }
  // Mix in the clock and the process id so a degenerate random_device cannot
  // produce a constant incarnation. This does not replace the entropy source;
  // it only guarantees that repeated calls differ.
  const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  const std::uint64_t stamp = static_cast<std::uint64_t>(now) ^ machine_identity();
  const std::array<std::string_view, 2> parts = {
      std::string_view(reinterpret_cast<const char*>(out.data()), out.size()),
      std::string_view(reinterpret_cast<const char*>(&stamp), sizeof(stamp))};
  const Digest mixed = sha256_parts(std::span<const std::string_view>(parts.data(), parts.size()));
  const std::size_t copy_size = out.size() < mixed.size() ? out.size() : mixed.size();
  for (std::size_t i = 0; i < copy_size; ++i) {
    out[i] = mixed[i];
  }
}

std::string Incarnation::str() const {
  return base64url_encode(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
}

ToolId tool_identity(std::string_view name) noexcept {
  const std::array<std::string_view, 2> parts = {std::string_view("wnc/tool"), name};
  return ToolId::from_digest(sha256_parts(std::span<const std::string_view>(parts.data(), parts.size())));
}

}  // namespace wnc
