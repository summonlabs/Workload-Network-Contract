// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Ed25519 (RFC 8032 sections 5.1 and 5.2) over edwards25519 with SHA-512.
//
// Representation
// --------------
//   * A field element modulo p = 2^255 - 19 is eight little-endian 32 bit
//     limbs holding the canonical representative, a value in [0, p). Eight
//     limbs (256 bits) is the smallest 32 bit limb count that can hold such a
//     value; every operation below returns a canonical representative, so
//     equality is limb equality and each value has exactly one encoding.
//   * Multiplication is a schoolbook product into sixteen 32 bit limbs, then
//     every limb at or above 2^256 (index 8 and up) is folded back in with
//     2^256 = 38 (mod p), then at most two conditional subtractions of p
//     finish the reduction. The carry positions are spelled out where they
//     occur.
//   * Inversion is a^(p-2). It reuses the square root exponent
//     (p-5)/8 = 2^252 - 3 and finishes with three squarings and one
//     multiplication, because 8 * (2^252 - 3) + 3 = 2^255 - 21 = p - 2.
//   * Scalars are eight little-endian 32 bit limbs modulo the group order L,
//     produced from 512 bit material by binary long division.
//   * Points use extended twisted Edwards coordinates (X : Y : Z : T) and
//     scalar multiplication is a left-to-right four bit window.
//
// The implementation is deliberately not constant time: it serves offline
// signing and verification of contract envelopes and never sits inside an
// attacker-observable timing oracle. It is free of undefined behaviour: no
// signed overflow, no shift at or beyond the width of a type, no access
// outside a live object, and every narrowing conversion is explicit.

#include "wnc/ed25519.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "wnc/hash.hpp"

namespace wnc {
namespace {

// ---------------------------------------------------------------------------
// Field arithmetic modulo p = 2^255 - 19
// ---------------------------------------------------------------------------

using Fe = std::array<std::uint32_t, 8>;

// p as eight little-endian 32 bit limbs.
constexpr Fe kP = {0xFFFFFFEDu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                   0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x7FFFFFFFu};
constexpr Fe kOne = {1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u};
constexpr Fe kZero = {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u};

// d = -121665 / 121666 (mod p), the constant of -x^2 + y^2 = 1 + d x^2 y^2.
constexpr Fe kD = {0x135978A3u, 0x75EB4DCAu, 0x4141D8ABu, 0x00700A4Du,
                   0x7779E898u, 0x8CC74079u, 0x2B6FFE73u, 0x52036CEEu};
// 2 * d (mod p), the constant of the extended addition formula.
constexpr Fe kD2 = {0x26B2F159u, 0xEBD69B94u, 0x8283B156u, 0x00E0149Au,
                    0xEEF3D130u, 0x198E80F2u, 0x56DFFCE7u, 0x2406D9DCu};
// sqrt(-1) (mod p), used when the square root candidate is off by that factor.
constexpr Fe kSqrtM1 = {0x4A0EA0B0u, 0xC4EE1B27u, 0xAD2FE478u, 0x2F431806u,
                        0x3DFBD7A7u, 0x2B4D0099u, 0x4FC1DF0Bu, 0x2B832480u};

// Subtracts p from a when a >= p and leaves a unchanged otherwise. The
// subtraction always runs and the outcome is selected with a mask, so no
// branch depends on the value.
void fe_conditional_subtract_p(Fe& a) noexcept {
  Fe reduced{};
  std::uint64_t borrow = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    // A negative difference wraps, and then bits 32..63 are all ones, so the
    // borrow out of limb i is bit 32 of the 64 bit difference.
    const std::uint64_t difference =
        static_cast<std::uint64_t>(a[i]) - static_cast<std::uint64_t>(kP[i]) - borrow;
    reduced[i] = static_cast<std::uint32_t>(difference);
    borrow = (difference >> 32) & 1u;
  }
  // borrow == 0 means a >= p, so take the difference; borrow == 1 keeps a.
  const std::uint32_t take_mask =
      static_cast<std::uint32_t>(0u) - (1u - static_cast<std::uint32_t>(borrow));
  const std::uint32_t keep_mask = ~take_mask;
  for (std::size_t i = 0; i < 8; ++i) {
    a[i] = (a[i] & keep_mask) | (reduced[i] & take_mask);
  }
}

// True when the limbs hold a value below p. Values produced by fe_mul and
// friends always do; the check exists for material that arrives as bytes.
bool fe_below_p(const Fe& a) noexcept {
  std::uint64_t borrow = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    const std::uint64_t difference =
        static_cast<std::uint64_t>(a[i]) - static_cast<std::uint64_t>(kP[i]) - borrow;
    borrow = (difference >> 32) & 1u;
  }
  return borrow != 0;
}

Fe fe_add(const Fe& a, const Fe& b) noexcept {
  Fe out{};
  std::uint64_t carry = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    const std::uint64_t sum =
        static_cast<std::uint64_t>(a[i]) + static_cast<std::uint64_t>(b[i]) + carry;
    out[i] = static_cast<std::uint32_t>(sum);
    carry = sum >> 32;
  }
  // a + b < 2p = 2^256 - 38, so the carry out of limb 7 is zero and one
  // conditional subtraction is enough to land below p.
  fe_conditional_subtract_p(out);
  return out;
}

Fe fe_sub(const Fe& a, const Fe& b) noexcept {
  Fe out{};
  std::uint64_t borrow = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    const std::uint64_t difference =
        static_cast<std::uint64_t>(a[i]) - static_cast<std::uint64_t>(b[i]) - borrow;
    out[i] = static_cast<std::uint32_t>(difference);
    borrow = (difference >> 32) & 1u;
  }
  if (borrow != 0) {
    // a < b: out currently holds a - b + 2^256. Adding p wraps modulo 2^256 and
    // the carry out cancels the borrowed 2^256, leaving a - b + p in (0, p).
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < 8; ++i) {
      const std::uint64_t sum =
          static_cast<std::uint64_t>(out[i]) + static_cast<std::uint64_t>(kP[i]) + carry;
      out[i] = static_cast<std::uint32_t>(sum);
      carry = sum >> 32;
    }
  }
  return out;
}

Fe fe_neg(const Fe& a) noexcept { return fe_sub(kZero, a); }

// a * b (mod p).
//
// Carry bookkeeping, limb by limb:
//   * The schoolbook step multiplies limbs of two canonical values. Each inner
//     step adds one product and two 32 bit values into a 64 bit accumulator,
//     bounded by (2^32-1)^2 + (2^32-1) + (2^32-1) = 2^64 - 1, so the 64 bit sum
//     cannot overflow. t[0..15] are written masked and t[i+8] receives a carry
//     below 2^32 while it is still zero, so all sixteen limbs end up below
//     2^32 and the product is exact.
//   * Limb i + 8 has weight 2^(32(i+8)) = 2^(32i) * 2^256, and 2^256 = 38
//     (mod p), so 38 * t[i+8] is added at limb i. Each accumulator is then
//     below 2^32 + 38 * (2^32 - 1) < 2^39, and the folded value is below
//     39 * 2^256, so the carry out of bit 256 is at most 38.
//   * Folding that carry adds 38 * 38 = 1444 at limb 0, so the value is then
//     below 2^256 + 1444 and its carry out is 0 or 1. A carry of one means the
//     low 256 bits were below 1444, so adding 38 once more stays below 2^32 in
//     limb 0: no further renormalisation is needed.
//   * What remains is below 2^256 < 2p + 38, so two conditional subtractions
//     of p produce the canonical representative.
Fe fe_mul(const Fe& a, const Fe& b) noexcept {
  std::uint64_t t[16] = {};
  for (std::size_t i = 0; i < 8; ++i) {
    std::uint64_t carry = 0;
    for (std::size_t j = 0; j < 8; ++j) {
      const std::uint64_t current =
          t[i + j] + static_cast<std::uint64_t>(a[i]) * static_cast<std::uint64_t>(b[j]) + carry;
      t[i + j] = current & 0xFFFFFFFFu;
      carry = current >> 32;
    }
    t[i + 8] = carry;  // still zero here: the inner loop wrote at most t[i+7]
  }

  std::uint64_t w[8];
  for (std::size_t i = 0; i < 8; ++i) {
    w[i] = t[i] + 38u * t[i + 8];
  }
  std::uint64_t carry = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    const std::uint64_t sum = w[i] + carry;
    w[i] = sum & 0xFFFFFFFFu;
    carry = sum >> 32;
  }

  w[0] += 38u * carry;
  carry = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    const std::uint64_t sum = w[i] + carry;
    w[i] = sum & 0xFFFFFFFFu;
    carry = sum >> 32;
  }

  w[0] += 38u * carry;

  Fe out{};
  for (std::size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint32_t>(w[i] & 0xFFFFFFFFu);
  }
  fe_conditional_subtract_p(out);
  fe_conditional_subtract_p(out);
  return out;
}

Fe fe_sqr(const Fe& a) noexcept { return fe_mul(a, a); }

// value^(2^count) by repeated squaring.
Fe fe_square_times(Fe value, std::size_t count) noexcept {
  while (count > 0) {
    value = fe_sqr(value);
    --count;
  }
  return value;
}

// a^((p-5)/8) = a^(2^252 - 3), the square root candidate exponent of
// decompression. The chain builds a^(2^k - 1) for growing k and combines them:
//   a^(2^2 - 1) = (a^(2^1-1))^2      * a^(2^1-1)
//   a^(2^4 - 1) = (a^(2^2-1))^2      * a^(2^2-1)
//   ... and likewise to a^(2^8-1), a^(2^16-1), a^(2^32-1)
//   a^(2^18 - 1) = (a^(2^16-1))^2^2  * a^(2^2-1)
//   a^(2^50 - 1) = (a^(2^32-1))^2^18 * a^(2^18-1)
//   a^(2^100- 1) = (a^(2^50-1))^2^50 * a^(2^50-1)
//   a^(2^200- 1) = (a^(2^100-1))^2^100 * a^(2^100-1)
//   a^(2^250- 1) = (a^(2^200-1))^2^50 * a^(2^50-1)
//   a^(2^252- 3) = (a^(2^250-1))^2^2  * a
Fe fe_pow_p58(const Fe& a) noexcept {
  const Fe q2 = fe_mul(fe_square_times(a, 1), a);            // a^(2^2 - 1)
  const Fe q4 = fe_mul(fe_square_times(q2, 2), q2);          // a^(2^4 - 1)
  const Fe q8 = fe_mul(fe_square_times(q4, 4), q4);          // a^(2^8 - 1)
  const Fe q16 = fe_mul(fe_square_times(q8, 8), q8);         // a^(2^16 - 1)
  const Fe q32 = fe_mul(fe_square_times(q16, 16), q16);      // a^(2^32 - 1)
  const Fe q18 = fe_mul(fe_square_times(q16, 2), q2);        // a^(2^18 - 1)
  const Fe q50 = fe_mul(fe_square_times(q32, 18), q18);      // a^(2^50 - 1)
  const Fe q100 = fe_mul(fe_square_times(q50, 50), q50);     // a^(2^100 - 1)
  const Fe q200 = fe_mul(fe_square_times(q100, 100), q100);  // a^(2^200 - 1)
  const Fe q250 = fe_mul(fe_square_times(q200, 50), q50);    // a^(2^250 - 1)
  return fe_mul(fe_square_times(q250, 2), a);                // a^(2^252 - 3)
}

// a^(p-2) = a^(2^255 - 21). Since 8 * (2^252 - 3) + 3 = 2^255 - 21, the
// inverse is the square root exponent raised to the eighth power, times a^3.
Fe fe_invert(const Fe& a) noexcept {
  const Fe z = fe_pow_p58(a);
  const Fe z8 = fe_square_times(z, 3);
  const Fe a3 = fe_mul(fe_sqr(a), a);
  return fe_mul(z8, a3);
}

bool fe_is_zero(const Fe& a) noexcept {
  std::uint32_t acc = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    acc |= a[i];
  }
  return acc == 0u;
}

bool fe_equal(const Fe& a, const Fe& b) noexcept {
  std::uint32_t acc = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    acc |= a[i] ^ b[i];
  }
  return acc == 0u;
}

// Reads a little-endian 32 byte value without reducing it: callers that need a
// canonical element check fe_below_p first.
Fe fe_from_bytes(const std::uint8_t* bytes) noexcept {
  Fe out{};
  for (std::size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint32_t>(bytes[i * 4]) |
             (static_cast<std::uint32_t>(bytes[i * 4 + 1]) << 8) |
             (static_cast<std::uint32_t>(bytes[i * 4 + 2]) << 16) |
             (static_cast<std::uint32_t>(bytes[i * 4 + 3]) << 24);
  }
  return out;
}

void fe_to_bytes(const Fe& a, std::uint8_t* out) noexcept {
  for (std::size_t i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<std::uint8_t>(a[i] & 0xFFu);
    out[i * 4 + 1] = static_cast<std::uint8_t>((a[i] >> 8) & 0xFFu);
    out[i * 4 + 2] = static_cast<std::uint8_t>((a[i] >> 16) & 0xFFu);
    out[i * 4 + 3] = static_cast<std::uint8_t>((a[i] >> 24) & 0xFFu);
  }
}

// ---------------------------------------------------------------------------
// Scalar arithmetic modulo the group order L
// ---------------------------------------------------------------------------

using Scalar = std::array<std::uint32_t, 8>;

// L = 2^252 + 27742317777372353535851937790883648493.
constexpr Scalar kL = {0x5CF5D3EDu, 0x5812631Au, 0xA2F79CD6u, 0x14DEF9DEu,
                       0x00000000u, 0x00000000u, 0x00000000u, 0x10000000u};

int scalar_compare(const Scalar& a, const Scalar& b) noexcept {
  for (std::size_t i = 8; i > 0; --i) {
    if (a[i - 1] != b[i - 1]) {
      return a[i - 1] < b[i - 1] ? -1 : 1;
    }
  }
  return 0;
}

void scalar_sub(const Scalar& a, const Scalar& b, Scalar& out) noexcept {
  std::uint64_t borrow = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    const std::uint64_t difference =
        static_cast<std::uint64_t>(a[i]) - static_cast<std::uint64_t>(b[i]) - borrow;
    out[i] = static_cast<std::uint32_t>(difference);
    borrow = (difference >> 32) & 1u;
  }
}

void scalar_from_bytes(const std::uint8_t* bytes, Scalar& out) noexcept {
  for (std::size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint32_t>(bytes[i * 4]) |
             (static_cast<std::uint32_t>(bytes[i * 4 + 1]) << 8) |
             (static_cast<std::uint32_t>(bytes[i * 4 + 2]) << 16) |
             (static_cast<std::uint32_t>(bytes[i * 4 + 3]) << 24);
  }
}

void scalar_to_bytes(const Scalar& value, std::uint8_t* out) noexcept {
  for (std::size_t i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<std::uint8_t>(value[i] & 0xFFu);
    out[i * 4 + 1] = static_cast<std::uint8_t>((value[i] >> 8) & 0xFFu);
    out[i * 4 + 2] = static_cast<std::uint8_t>((value[i] >> 16) & 0xFFu);
    out[i * 4 + 3] = static_cast<std::uint8_t>((value[i] >> 24) & 0xFFu);
  }
}

// Reduces a 512 bit little-endian value modulo L by binary long division, most
// significant bit first. The running remainder stays below L < 2^253, so it
// never overflows eight limbs and the shifted-out bit is always zero.
Scalar scalar_reduce(const std::array<std::uint32_t, 16>& wide) noexcept {
  Scalar remainder{};
  for (std::size_t bit = 512; bit > 0; --bit) {
    const std::size_t index = bit - 1;
    std::uint32_t carry = (wide[index / 32] >> (index % 32)) & 1u;
    for (std::size_t i = 0; i < 8; ++i) {
      const std::uint64_t shifted = (static_cast<std::uint64_t>(remainder[i]) << 1) | carry;
      remainder[i] = static_cast<std::uint32_t>(shifted);
      carry = static_cast<std::uint32_t>(shifted >> 32);
    }
    if (scalar_compare(remainder, kL) >= 0) {
      Scalar reduced{};
      scalar_sub(remainder, kL, reduced);
      remainder = reduced;
    }
  }
  return remainder;
}

Scalar scalar_from_wide_hash(const Digest512& hash) noexcept {
  std::array<std::uint32_t, 16> wide{};
  for (std::size_t i = 0; i < 16; ++i) {
    wide[i] = static_cast<std::uint32_t>(hash[i * 4]) |
              (static_cast<std::uint32_t>(hash[i * 4 + 1]) << 8) |
              (static_cast<std::uint32_t>(hash[i * 4 + 2]) << 16) |
              (static_cast<std::uint32_t>(hash[i * 4 + 3]) << 24);
  }
  return scalar_reduce(wide);
}

// a * b (mod L), 8x8 schoolbook into sixteen limbs with the same accumulator
// bound as the field product: one product, one limb and one carry sum to at
// most 2^64 - 1. Limb i+8 is still zero when its carry is stored.
Scalar scalar_mul(const Scalar& a, const Scalar& b) noexcept {
  std::array<std::uint32_t, 16> wide{};
  for (std::size_t i = 0; i < 8; ++i) {
    std::uint64_t carry = 0;
    for (std::size_t j = 0; j < 8; ++j) {
      const std::uint64_t current =
          static_cast<std::uint64_t>(wide[i + j]) +
          static_cast<std::uint64_t>(a[j]) * static_cast<std::uint64_t>(b[i]) + carry;
      wide[i + j] = static_cast<std::uint32_t>(current & 0xFFFFFFFFu);
      carry = current >> 32;
    }
    wide[i + 8] = static_cast<std::uint32_t>(carry);
  }
  return scalar_reduce(wide);
}

Scalar scalar_add(const Scalar& a, const Scalar& b) noexcept {
  Scalar sum{};
  std::uint64_t carry = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    const std::uint64_t total =
        static_cast<std::uint64_t>(a[i]) + static_cast<std::uint64_t>(b[i]) + carry;
    sum[i] = static_cast<std::uint32_t>(total);
    carry = total >> 32;
  }
  // a + b < 2L, so at most one subtraction of L is needed.
  if (scalar_compare(sum, kL) >= 0) {
    Scalar reduced{};
    scalar_sub(sum, kL, reduced);
    sum = reduced;
  }
  return sum;
}

// ---------------------------------------------------------------------------
// Group arithmetic on edwards25519: -x^2 + y^2 = 1 + d x^2 y^2
// ---------------------------------------------------------------------------

struct Point {
  Fe x{};
  Fe y{};
  Fe z{};
  Fe t{};
};

Point point_identity() noexcept {
  Point out{};
  out.x = kZero;
  out.y = kOne;
  out.z = kOne;
  out.t = kZero;
  return out;
}

// Extended coordinates, a = -1, from the complete addition law (add-2008-hwcd-3).
Point point_add(const Point& p, const Point& q) noexcept {
  const Fe a = fe_mul(fe_sub(p.y, p.x), fe_sub(q.y, q.x));
  const Fe b = fe_mul(fe_add(p.y, p.x), fe_add(q.y, q.x));
  const Fe c = fe_mul(fe_mul(p.t, q.t), kD2);
  const Fe d = fe_mul(fe_add(p.z, p.z), q.z);
  const Fe e = fe_sub(b, a);
  const Fe f = fe_sub(d, c);
  const Fe g = fe_add(d, c);
  const Fe h = fe_add(b, a);
  Point out{};
  out.x = fe_mul(e, f);
  out.y = fe_mul(g, h);
  out.z = fe_mul(f, g);
  out.t = fe_mul(e, h);
  return out;
}

// Extended coordinates, a = -1 (dbl-2008-hwcd).
Point point_double(const Point& p) noexcept {
  const Fe a = fe_sqr(p.x);
  const Fe b = fe_sqr(p.y);
  const Fe c = fe_add(fe_sqr(p.z), fe_sqr(p.z));
  const Fe d = fe_neg(a);
  const Fe e = fe_sub(fe_sub(fe_sqr(fe_add(p.x, p.y)), a), b);
  const Fe g = fe_add(d, b);
  const Fe f = fe_sub(g, c);
  const Fe h = fe_sub(d, b);
  Point out{};
  out.x = fe_mul(e, f);
  out.y = fe_mul(g, h);
  out.z = fe_mul(f, g);
  out.t = fe_mul(e, h);
  return out;
}

bool point_is_identity(const Point& p) noexcept {
  // (X : Y : Z) is the identity (0 : 1 : 1) exactly when X == 0 and Y == Z.
  return fe_is_zero(p.x) && fe_equal(p.y, p.z);
}

// x1 * z2 == x2 * z1 and y1 * z2 == y2 * z1, which needs no inversion.
bool point_equal(const Point& p, const Point& q) noexcept {
  return fe_equal(fe_mul(p.x, q.z), fe_mul(q.x, p.z)) &&
         fe_equal(fe_mul(p.y, q.z), fe_mul(q.y, p.z));
}

void point_to_bytes(const Point& p, std::uint8_t* out) noexcept {
  const Fe z_inverse = fe_invert(p.z);
  const Fe x = fe_mul(p.x, z_inverse);
  const Fe y = fe_mul(p.y, z_inverse);
  fe_to_bytes(y, out);
  out[31] = static_cast<std::uint8_t>(out[31] |
                                      static_cast<std::uint8_t>((x[0] & 1u) << 7));
}

// Decodes a compressed point, rejecting a non-canonical y (y >= p), a y for
// which the curve equation has no solution x, and the encoding of x == 0 with
// the sign bit set.
bool point_from_bytes(const std::uint8_t* in, Point& out) noexcept {
  std::uint8_t y_bytes[32];
  std::memcpy(y_bytes, in, 32);
  const std::uint32_t sign = static_cast<std::uint32_t>(y_bytes[31] >> 7);
  y_bytes[31] = static_cast<std::uint8_t>(y_bytes[31] & 0x7Fu);

  const Fe y = fe_from_bytes(y_bytes);
  if (!fe_below_p(y)) {
    return false;
  }

  // Recover x from x^2 = (y^2 - 1) / (d y^2 + 1) with the candidate
  // x = u * v^3 * (u * v^7)^((p-5)/8) for u = y^2 - 1 and v = d y^2 + 1.
  const Fe y2 = fe_sqr(y);
  const Fe u = fe_sub(y2, kOne);
  const Fe v = fe_add(fe_mul(kD, y2), kOne);
  const Fe v3 = fe_mul(fe_sqr(v), v);
  const Fe v7 = fe_mul(fe_sqr(v3), v);
  Fe x = fe_mul(fe_pow_p58(fe_mul(u, v7)), fe_mul(u, v3));

  const Fe vx2 = fe_mul(v, fe_sqr(x));
  if (!fe_equal(vx2, u)) {
    if (!fe_equal(vx2, fe_neg(u))) {
      return false;  // no square root: not a point on the curve
    }
    x = fe_mul(x, kSqrtM1);
  }

  if (fe_is_zero(x) && sign != 0u) {
    return false;  // (x = 0, sign = 1) is not a valid encoding
  }
  if ((x[0] & 1u) != sign) {
    x = fe_neg(x);
  }

  out.x = x;
  out.y = y;
  out.z = kOne;
  out.t = fe_mul(x, y);
  return true;
}

// The fifteen multiples of a point plus the identity, for the four bit window.
std::array<Point, 16> point_small_multiples(const Point& base) noexcept {
  std::array<Point, 16> table{};
  table[0] = point_identity();
  table[1] = base;
  for (std::size_t i = 2; i < table.size(); ++i) {
    table[i] = (i % 2 == 0) ? point_double(table[i / 2]) : point_add(table[i - 1], base);
  }
  return table;
}

// Left-to-right four bit window: 256 doublings and at most 64 additions, with
// the sixteen entry table built once by the caller.
Point point_window_mul(const Scalar& scalar, const std::array<Point, 16>& table) noexcept {
  std::uint8_t bytes[32];
  scalar_to_bytes(scalar, bytes);

  Point result = point_identity();
  for (std::size_t window = 64; window-- > 0;) {
    if (window != 63) {
      result = point_double(point_double(point_double(point_double(result))));
    }
    const std::uint8_t packed = bytes[window / 2];
    const std::uint32_t digit = static_cast<std::uint32_t>(
        (window % 2 == 0) ? (packed & 0x0Fu) : static_cast<std::uint8_t>(packed >> 4));
    if (digit != 0u) {
      result = point_add(result, table[digit]);
    }
  }
  return result;
}

constexpr std::array<std::uint8_t, 32> kBasePointBytes = {
    0x58u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u,
    0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u,
    0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u};

// Decompression costs an exponentiation, so the base point is decoded once.
const Point& base_point() noexcept {
  static const Point cached = [] {
    Point out{};
    if (!point_from_bytes(kBasePointBytes.data(), out)) {
      return point_identity();
    }
    return out;
  }();
  return cached;
}

const std::array<Point, 16>& base_multiples() noexcept {
  static const std::array<Point, 16> table = point_small_multiples(base_point());
  return table;
}

Point point_scalar_mul_base(const Scalar& scalar) noexcept {
  return point_window_mul(scalar, base_multiples());
}

Point point_scalar_mul(const Scalar& scalar, const Point& base) noexcept {
  const std::array<Point, 16> table = point_small_multiples(base);
  return point_window_mul(scalar, table);
}

// ---------------------------------------------------------------------------
// SHA-512 over concatenated byte ranges
// ---------------------------------------------------------------------------
//
// Ed25519 hashes raw concatenations (prefix || message and R || A || message).
// The library's sha512_parts helper prefixes every component with its length,
// which is a different function, so the parts are streamed into one hasher
// instead. Zero length ranges are skipped so no span is built from a null
// pointer.

void sha512_update_span(Sha512& hasher, const std::uint8_t* bytes, std::size_t size) noexcept {
  if (size != 0) {
    hasher.update(std::span<const std::uint8_t>(bytes, size));
  }
}

Digest512 sha512_of_two(const std::uint8_t* first, std::size_t first_size,
                        const std::uint8_t* second, std::size_t second_size) noexcept {
  Sha512 hasher;
  sha512_update_span(hasher, first, first_size);
  sha512_update_span(hasher, second, second_size);
  return hasher.digest();
}

Digest512 sha512_of_three(const std::uint8_t* first, std::size_t first_size,
                          const std::uint8_t* second, std::size_t second_size,
                          const std::uint8_t* third, std::size_t third_size) noexcept {
  Sha512 hasher;
  sha512_update_span(hasher, first, first_size);
  sha512_update_span(hasher, second, second_size);
  sha512_update_span(hasher, third, third_size);
  return hasher.digest();
}

// ---------------------------------------------------------------------------
// Key expansion and the two equations of RFC 8032
// ---------------------------------------------------------------------------

struct ExpandedKey {
  Scalar scalar{};
  std::array<std::uint8_t, 32> prefix{};
  std::array<std::uint8_t, 32> public_key{};
};

ExpandedKey expand_key(const Ed25519Seed& seed) noexcept {
  ExpandedKey out{};
  const Digest512 expanded = sha512(std::span<const std::uint8_t>(seed.data(), seed.size()));

  std::uint8_t clamped[32];
  std::memcpy(clamped, expanded.data(), 32);
  clamped[0] = static_cast<std::uint8_t>(clamped[0] & 248u);
  clamped[31] = static_cast<std::uint8_t>(clamped[31] & 63u);
  clamped[31] = static_cast<std::uint8_t>(clamped[31] | 64u);
  scalar_from_bytes(clamped, out.scalar);
  std::memcpy(out.prefix.data(), expanded.data() + 32, out.prefix.size());

  const Point public_point = point_scalar_mul_base(out.scalar);
  point_to_bytes(public_point, out.public_key.data());
  return out;
}

}  // namespace

Ed25519PublicKey ed25519_public_key(const Ed25519Seed& seed) noexcept {
  const ExpandedKey key = expand_key(seed);
  Ed25519PublicKey out{};
  std::memcpy(out.data(), key.public_key.data(), out.size());
  return out;
}

Ed25519Signature ed25519_sign(const Ed25519Seed& seed, std::span<const std::uint8_t> message) noexcept {
  const ExpandedKey key = expand_key(seed);

  // r = SHA-512(prefix || message) mod L, then R = [r]B.
  const Digest512 nonce_hash = sha512_of_two(key.prefix.data(), key.prefix.size(), message.data(),
                                             message.size());
  const Scalar nonce = scalar_from_wide_hash(nonce_hash);

  std::array<std::uint8_t, 32> nonce_bytes{};
  const Point nonce_point = point_scalar_mul_base(nonce);
  point_to_bytes(nonce_point, nonce_bytes.data());

  // k = SHA-512(R || A || message) mod L, then S = r + k * a (mod L).
  const Digest512 challenge_hash =
      sha512_of_three(nonce_bytes.data(), nonce_bytes.size(), key.public_key.data(),
                      key.public_key.size(), message.data(), message.size());
  const Scalar challenge = scalar_from_wide_hash(challenge_hash);
  const Scalar s = scalar_add(scalar_mul(challenge, key.scalar), nonce);

  Ed25519Signature out{};
  std::memcpy(out.data(), nonce_bytes.data(), nonce_bytes.size());
  scalar_to_bytes(s, out.data() + 32);
  return out;
}

bool ed25519_verify(const Ed25519PublicKey& public_key, std::span<const std::uint8_t> message,
                    const Ed25519Signature& signature) noexcept {
  Point a{};
  Point r{};
  if (!point_from_bytes(public_key.data(), a)) {
    return false;
  }
  if (!point_from_bytes(signature.data(), r)) {
    return false;
  }
  Scalar s{};
  scalar_from_bytes(signature.data() + 32, s);
  if (scalar_compare(s, kL) >= 0) {
    return false;  // S is not a canonical scalar
  }

  const Digest512 challenge_hash =
      sha512_of_three(signature.data(), 32, public_key.data(), public_key.size(), message.data(),
                      message.size());
  const Scalar challenge = scalar_from_wide_hash(challenge_hash);

  // [S]B == R + [k]A
  const Point left = point_scalar_mul_base(s);
  const Point right = point_add(r, point_scalar_mul(challenge, a));
  return point_equal(left, right);
}

bool ed25519_verify_strict(const Ed25519PublicKey& public_key, std::span<const std::uint8_t> message,
                           const Ed25519Signature& signature) noexcept {
  // A public key of small order admits signatures that verify for messages the
  // signer never saw, so it is refused before any mathematical check.
  Point a{};
  if (!point_from_bytes(public_key.data(), a)) {
    return false;
  }
  const Point eight_a = point_double(point_double(point_double(a)));
  if (point_is_identity(eight_a)) {
    return false;
  }
  return ed25519_verify(public_key, message, signature);
}

}  // namespace wnc
