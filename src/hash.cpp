// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/hash.hpp"

#include <cstring>

namespace wnc {
namespace {

constexpr std::array<std::uint32_t, 64> kSha256RoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned shift) noexcept {
  return (value >> shift) | (value << (32u - shift));
}

constexpr std::uint32_t choose(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
  return (x & y) ^ (~x & z);
}

constexpr std::uint32_t majority(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
  return (x & y) ^ (x & z) ^ (y & z);
}

std::uint32_t read_be32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

void write_be32(std::uint8_t* p, std::uint32_t value) noexcept {
  p[0] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
  p[1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  p[2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  p[3] = static_cast<std::uint8_t>(value & 0xFFu);
}

void write_be64(std::uint8_t* p, std::uint64_t value) noexcept {
  for (unsigned i = 0; i < 8; ++i) {
    p[i] = static_cast<std::uint8_t>((value >> (8u * (7u - i))) & 0xFFu);
  }
}

}  // namespace

Sha256::Sha256() noexcept {
  state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::uint32_t w[64];
  for (std::size_t i = 0; i < 16; ++i) {
    w[i] = read_be32(block + i * 4);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 =
        rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 =
        rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    const std::uint32_t ch = choose(e, f, g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256RoundConstants[i] + w[i];
    const std::uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    const std::uint32_t maj = majority(a, b, c);
    const std::uint32_t temp2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::span<const std::uint8_t> bytes) noexcept {
  if (finished_) {
    return;
  }
  total_bytes_ += static_cast<std::uint64_t>(bytes.size());
  std::size_t offset = 0;
  if (buffered_ > 0) {
    const std::size_t want = kBlockBytes - buffered_;
    const std::size_t take = bytes.size() < want ? bytes.size() : want;
    if (take > 0) {
      std::memcpy(buffer_.data() + buffered_, bytes.data(), take);
      buffered_ += take;
      offset += take;
    }
    if (buffered_ == kBlockBytes) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }
  while (offset + kBlockBytes <= bytes.size()) {
    compress(bytes.data() + offset);
    offset += kBlockBytes;
  }
  if (offset < bytes.size()) {
    const std::size_t remaining = bytes.size() - offset;
    std::memcpy(buffer_.data(), bytes.data() + offset, remaining);
    buffered_ = remaining;
  }
}

void Sha256::update(std::string_view text) noexcept {
  update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                       text.size()));
}

void Sha256::finish(std::span<std::uint8_t, kDigestBytes> out) noexcept {
  if (!finished_) {
    // Capture the message length before padding is fed to update(): padding is
    // not part of the message.
    const std::uint64_t bit_length = total_bytes_ * 8u;
    std::uint8_t padding[kBlockBytes * 2] = {};
    padding[0] = 0x80u;
    const std::size_t pad_len = (buffered_ < 56) ? (56 - buffered_) : (120 - buffered_);
    update(std::span<const std::uint8_t>(padding, pad_len));
    std::uint8_t length_bytes[8];
    write_be64(length_bytes, bit_length);
    update(std::span<const std::uint8_t>(length_bytes, 8));
    finished_ = true;
  }
  for (std::size_t i = 0; i < state_.size(); ++i) {
    write_be32(out.data() + i * 4, state_[i]);
  }
}

Digest Sha256::digest() noexcept {
  Digest out{};
  finish(std::span<std::uint8_t, kDigestBytes>(out.data(), out.size()));
  return out;
}

Digest sha256(std::span<const std::uint8_t> bytes) noexcept {
  Sha256 hasher;
  hasher.update(bytes);
  return hasher.digest();
}

Digest sha256(std::string_view text) noexcept {
  Sha256 hasher;
  hasher.update(text);
  return hasher.digest();
}

Digest sha256_parts(std::span<const std::string_view> parts) noexcept {
  Sha256 hasher;
  for (const std::string_view part : parts) {
    if (part.size() > 0xFFFFFFFFull) {
      // Components larger than 4 GiB cannot be length-prefixed in 32 bits.
      // This boundary never produces them; the branch exists so the encoding
      // stays unambiguous for every possible input.
      const std::array<std::uint8_t, 4> marker = {0xFFu, 0xFFu, 0xFFu, 0xFFu};
      hasher.update(std::span<const std::uint8_t>(marker.data(), marker.size()));
      const Digest part_digest = sha256(part);
      hasher.update(std::span<const std::uint8_t>(part_digest.data(), part_digest.size()));
      continue;
    }
    std::uint8_t length[4];
    write_be32(length, static_cast<std::uint32_t>(part.size()));
    hasher.update(std::span<const std::uint8_t>(length, 4));
    hasher.update(part);
  }
  return hasher.digest();
}

Digest hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> message) noexcept {
  std::array<std::uint8_t, Sha256::kBlockBytes> padded_key{};
  if (key.size() > Sha256::kBlockBytes) {
    const Digest key_digest = sha256(key);
    std::memcpy(padded_key.data(), key_digest.data(), key_digest.size());
  } else if (!key.empty()) {
    std::memcpy(padded_key.data(), key.data(), key.size());
  }

  std::array<std::uint8_t, Sha256::kBlockBytes> inner{};
  std::array<std::uint8_t, Sha256::kBlockBytes> outer{};
  for (std::size_t i = 0; i < Sha256::kBlockBytes; ++i) {
    inner[i] = static_cast<std::uint8_t>(padded_key[i] ^ 0x36u);
    outer[i] = static_cast<std::uint8_t>(padded_key[i] ^ 0x5Cu);
  }

  Sha256 hasher;
  hasher.update(std::span<const std::uint8_t>(inner.data(), inner.size()));
  hasher.update(message);
  const Digest inner_digest = hasher.digest();

  Sha256 outer_hasher;
  outer_hasher.update(std::span<const std::uint8_t>(outer.data(), outer.size()));
  outer_hasher.update(std::span<const std::uint8_t>(inner_digest.data(), inner_digest.size()));
  return outer_hasher.digest();
}

bool constant_time_equal(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) noexcept {
  if (a.size() != b.size()) {
    return false;
  }
  std::uint8_t difference = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    difference = static_cast<std::uint8_t>(difference | (a[i] ^ b[i]));
  }
  return difference == 0;
}

std::uint32_t crc32_continued(std::uint32_t state, std::span<const std::uint8_t> bytes) noexcept {
  static const std::array<std::uint32_t, 256> table = [] {
    std::array<std::uint32_t, 256> built{};
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t value = i;
      for (int bit = 0; bit < 8; ++bit) {
        value = (value & 1u) != 0u ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
      }
      built[i] = value;
    }
    return built;
  }();

  std::uint32_t crc = state;
  for (const std::uint8_t byte : bytes) {
    crc = table[(crc ^ byte) & 0xFFu] ^ (crc >> 8);
  }
  return crc;
}

std::uint32_t crc32(std::span<const std::uint8_t> bytes) noexcept {
  return crc32_continued(0xFFFFFFFFu, bytes) ^ 0xFFFFFFFFu;
}

uint32_t crc32(std::string_view text) noexcept {
  return crc32(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                             text.size()));
}

Digest digest_domain(std::string_view domain, std::string_view payload) noexcept {
  const std::array<std::string_view, 3> parts = {std::string_view("wnc/v1"), domain, payload};
  return sha256_parts(std::span<const std::string_view>(parts.data(), parts.size()));
}

Digest digest_domain_generation(std::string_view domain, std::string_view payload,
                                std::uint64_t generation) noexcept {
  std::uint8_t generation_bytes[8];
  write_be64(generation_bytes, generation);
  const std::string_view generation_view(reinterpret_cast<const char*>(generation_bytes),
                                         sizeof(generation_bytes));
  const std::array<std::string_view, 4> parts = {std::string_view("wnc/v1"), domain, payload,
                                                 generation_view};
  return sha256_parts(std::span<const std::string_view>(parts.data(), parts.size()));
}

}  // namespace wnc
