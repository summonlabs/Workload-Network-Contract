// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Self-contained Ed25519 (RFC 8032) with strict verification. The
// implementation uses 32 bit limbs and is not constant time; it is used for
// offline signing and verification of contract envelopes, not inside an
// attacker-observable timing oracle. Signing and verification are deterministic.

#ifndef WNC_ED25519_HPP
#define WNC_ED25519_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace wnc {

inline constexpr std::size_t kEd25519SeedBytes = 32;
inline constexpr std::size_t kEd25519PublicKeyBytes = 32;
inline constexpr std::size_t kEd25519SignatureBytes = 64;

using Ed25519Seed = std::array<std::uint8_t, kEd25519SeedBytes>;
using Ed25519PublicKey = std::array<std::uint8_t, kEd25519PublicKeyBytes>;
using Ed25519Signature = std::array<std::uint8_t, kEd25519SignatureBytes>;

// Derives the public key for a seed. Deterministic.
Ed25519PublicKey ed25519_public_key(const Ed25519Seed& seed) noexcept;

// Signs a message with a seed. Deterministic per RFC 8032.
Ed25519Signature ed25519_sign(const Ed25519Seed& seed, std::span<const std::uint8_t> message) noexcept;

bool ed25519_verify(const Ed25519PublicKey& public_key, std::span<const std::uint8_t> message,
                    const Ed25519Signature& signature) noexcept;

// Rejects non-canonical point encodings, non-canonical scalars, and small order
// public keys, in addition to the mathematical check. Verification through this
// entry point is the only form this boundary accepts.
bool ed25519_verify_strict(const Ed25519PublicKey& public_key, std::span<const std::uint8_t> message,
                           const Ed25519Signature& signature) noexcept;

}  // namespace wnc

#endif  // WNC_ED25519_HPP
