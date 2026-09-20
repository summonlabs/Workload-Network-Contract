// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// SHA-512 as required by Ed25519 (RFC 8032). Kept separate from SHA-256 so the
// 64 bit path is only linked where signatures are actually used.

#include <cstring>

#include "wnc/hash.hpp"

namespace wnc {
namespace {

constexpr std::array<std::uint64_t, 80> kSha512RoundConstants = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};

constexpr std::uint64_t rotate_right64(std::uint64_t value, unsigned shift) noexcept {
  return (value >> shift) | (value << (64u - shift));
}

std::uint64_t read_be64(const std::uint8_t* p) noexcept {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i) {
    value = (value << 8) | static_cast<std::uint64_t>(p[i]);
  }
  return value;
}

void write_be64_bytes(std::uint8_t* p, std::uint64_t value) noexcept {
  for (unsigned i = 0; i < 8; ++i) {
    p[i] = static_cast<std::uint8_t>((value >> (8u * (7u - i))) & 0xFFu);
  }
}

}  // namespace

Sha512::Sha512() noexcept {
  state_ = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
            0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
            0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
}

void Sha512::compress(const std::uint8_t* block) noexcept {
  std::uint64_t w[80];
  for (std::size_t i = 0; i < 16; ++i) {
    w[i] = read_be64(block + i * 8);
  }
  for (std::size_t i = 16; i < 80; ++i) {
    const std::uint64_t s0 = rotate_right64(w[i - 15], 1) ^ rotate_right64(w[i - 15], 8) ^ (w[i - 15] >> 7);
    const std::uint64_t s1 = rotate_right64(w[i - 2], 19) ^ rotate_right64(w[i - 2], 61) ^ (w[i - 2] >> 6);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint64_t a = state_[0];
  std::uint64_t b = state_[1];
  std::uint64_t c = state_[2];
  std::uint64_t d = state_[3];
  std::uint64_t e = state_[4];
  std::uint64_t f = state_[5];
  std::uint64_t g = state_[6];
  std::uint64_t h = state_[7];

  for (std::size_t i = 0; i < 80; ++i) {
    const std::uint64_t s1 = rotate_right64(e, 14) ^ rotate_right64(e, 18) ^ rotate_right64(e, 41);
    const std::uint64_t ch = (e & f) ^ (~e & g);
    const std::uint64_t temp1 = h + s1 + ch + kSha512RoundConstants[i] + w[i];
    const std::uint64_t s0 = rotate_right64(a, 28) ^ rotate_right64(a, 34) ^ rotate_right64(a, 39);
    const std::uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint64_t temp2 = s0 + maj;
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

void Sha512::update(std::span<const std::uint8_t> bytes) noexcept {
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

void Sha512::update(std::string_view text) noexcept {
  update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                       text.size()));
}

void Sha512::finish(std::span<std::uint8_t, kSha512Bytes> out) noexcept {
  if (!finished_) {
    const std::uint64_t bit_length = total_bytes_ * 8u;
    std::uint8_t padding[kBlockBytes * 2] = {};
    padding[0] = 0x80u;
    const std::size_t pad_len = (buffered_ < 112) ? (112 - buffered_) : (240 - buffered_);
    update(std::span<const std::uint8_t>(padding, pad_len));
    std::uint8_t length_bytes[16] = {};
    write_be64_bytes(length_bytes + 8, bit_length);
    update(std::span<const std::uint8_t>(length_bytes, sizeof(length_bytes)));
    finished_ = true;
  }
  for (std::size_t i = 0; i < state_.size(); ++i) {
    write_be64_bytes(out.data() + i * 8, state_[i]);
  }
}

Digest512 Sha512::digest() noexcept {
  Digest512 out{};
  finish(std::span<std::uint8_t, kSha512Bytes>(out.data(), out.size()));
  return out;
}

Digest512 sha512(std::span<const std::uint8_t> bytes) noexcept {
  Sha512 hasher;
  hasher.update(bytes);
  return hasher.digest();
}

Digest512 sha512(std::string_view text) noexcept {
  Sha512 hasher;
  hasher.update(text);
  return hasher.digest();
}

Digest512 sha512_parts(std::span<const std::string_view> parts) noexcept {
  Sha512 hasher;
  for (const std::string_view part : parts) {
    std::uint8_t length[4];
    const auto size = static_cast<std::uint32_t>(part.size() & 0xFFFFFFFFu);
    length[0] = static_cast<std::uint8_t>((size >> 24) & 0xFFu);
    length[1] = static_cast<std::uint8_t>((size >> 16) & 0xFFu);
    length[2] = static_cast<std::uint8_t>((size >> 8) & 0xFFu);
    length[3] = static_cast<std::uint8_t>(size & 0xFFu);
    hasher.update(std::span<const std::uint8_t>(length, 4));
    hasher.update(part);
  }
  return hasher.digest();
}

}  // namespace wnc
