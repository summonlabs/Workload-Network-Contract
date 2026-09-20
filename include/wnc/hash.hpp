// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Digest and integrity primitives used for contract identity, journal record
// integrity, and frame integrity. All of these are deterministic functions of
// their input bytes; none of them observe the clock, the environment, or any
// ambient state.

#ifndef WNC_HASH_HPP
#define WNC_HASH_HPP

#include <array>
#include <cstdint>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "wnc/identity.hpp"

namespace wnc {

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

class Sha256 {
 public:
  static constexpr std::size_t kBlockBytes = 64;
  static constexpr std::size_t kDigestBytes = kSha256Bytes;

  Sha256() noexcept;

  void update(std::span<const std::uint8_t> bytes) noexcept;
  void update(std::string_view text) noexcept;

  // Finalises the digest. The instance must not be reused afterwards.
  void finish(std::span<std::uint8_t, kDigestBytes> out) noexcept;

  [[nodiscard]] Digest digest() noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, kBlockBytes> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_bytes_ = 0;
  bool finished_ = false;
};

Digest sha256(std::span<const std::uint8_t> bytes) noexcept;
Digest sha256(std::string_view text) noexcept;

// Length-prefixed concatenation. Every component is preceded by its length as
// a big-endian 32 bit value so that no two distinct component sequences can
// collide by concatenation ambiguity.
Digest sha256_parts(std::span<const std::string_view> parts) noexcept;

// ---------------------------------------------------------------------------
// SHA-512 (FIPS 180-4)
// ---------------------------------------------------------------------------

inline constexpr std::size_t kSha512Bytes = 64;
inline constexpr std::size_t kSha512HexChars = 128;

using Digest512 = std::array<std::uint8_t, kSha512Bytes>;

class Sha512 {
 public:
  static constexpr std::size_t kBlockBytes = 128;

  Sha512() noexcept;

  void update(std::span<const std::uint8_t> bytes) noexcept;
  void update(std::string_view text) noexcept;
  void finish(std::span<std::uint8_t, kSha512Bytes> out) noexcept;
  [[nodiscard]] Digest512 digest() noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint64_t, 8> state_{};
  std::array<std::uint8_t, kBlockBytes> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_bytes_ = 0;
  bool finished_ = false;
};

Digest512 sha512(std::span<const std::uint8_t> bytes) noexcept;
Digest512 sha512(std::string_view text) noexcept;
Digest512 sha512_parts(std::span<const std::string_view> parts) noexcept;

// HMAC-SHA256 (RFC 2104) and a constant time comparison helper.
Digest hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> message) noexcept;
bool constant_time_equal(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) noexcept;

// ---------------------------------------------------------------------------
// CRC-32/ISO-HDLC
// ---------------------------------------------------------------------------

std::uint32_t crc32(std::span<const std::uint8_t> bytes) noexcept;
std::uint32_t crc32(std::string_view text) noexcept;
std::uint32_t crc32_continued(std::uint32_t state, std::span<const std::uint8_t> bytes) noexcept;

// ---------------------------------------------------------------------------
// Domain separated hashing helpers
// ---------------------------------------------------------------------------

// Hashes a domain label followed by the payload. Domains keep distinct object
// classes (contract, evidence, journal record) from colliding even when their
// canonical bytes are identical.
Digest digest_domain(std::string_view domain, std::string_view payload) noexcept;

// Same, with an explicit generation folded into the hashed material.
Digest digest_domain_generation(std::string_view domain, std::string_view payload,
                                std::uint64_t generation) noexcept;

}  // namespace wnc

#endif  // WNC_HASH_HPP
