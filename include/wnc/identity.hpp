// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Strongly typed, fixed-width identities and monotonic generation counters.
// A matching identifier is never by itself evidence of a current generation:
// identity and generation are separate values everywhere in this boundary.

#ifndef WNC_IDENTITY_HPP
#define WNC_IDENTITY_HPP

#include <array>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "wnc/config.hpp"

namespace wnc {

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

inline constexpr std::size_t kSha256Bytes = 32;
inline constexpr std::size_t kSha256HexChars = 64;
inline constexpr std::size_t kSignatureBytes = 64;
inline constexpr std::size_t kPublicKeyBytes = 32;
inline constexpr std::size_t kPublicKeyHexChars = 64;
inline constexpr std::size_t kSignatureBase64Chars = 86;

using Digest = std::array<std::uint8_t, kSha256Bytes>;

// ---------------------------------------------------------------------------
// Tag traits
// ---------------------------------------------------------------------------

struct WorkloadTag {};
struct ContractTag {};
struct RequirementTag {};
struct ScopeTag {};
struct PublisherTag {};
struct CoordinatorTag {};
struct ToolTag {};
struct EvidenceTag {};
struct PolicyTag {};
struct SnapshotTag {};
struct ReceiptTag {};

// An identity is a 64 character lowercase hex SHA-256 digest with a type tag.
// The zero identity is the canonical "no identity" value; it is never a valid
// identity for a registered object.
template <class Tag>
class Id {
 public:
  static constexpr std::size_t kChars = kSha256HexChars;

  // The zero identity is 64 '0' characters, so that an identity that was never
  // derived from bytes is recognisable as the absence of an identity.
  constexpr Id() noexcept : chars_{} {
    for (std::size_t i = 0; i < kSha256HexChars; ++i) {
      chars_[i] = '0';
    }
  }

  static std::optional<Id> parse(std::string_view text) noexcept;

  static Id from_digest(const Digest& digest) noexcept;

  [[nodiscard]] constexpr bool is_zero() const noexcept {
    for (char c : chars_) {
      if (c != '0') {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] constexpr std::string_view view() const noexcept {
    return std::string_view(chars_.data(), chars_.size());
  }

  [[nodiscard]] std::string str() const { return std::string(view()); }

  // Builds an identity from an already normalised lowercase hexadecimal array.
  // It is public so that the inline parse helper can use it, and it is only
  // reachable with exactly 64 validated lowercase hexadecimal digits.
  static constexpr Id from_chars(const std::array<char, kSha256HexChars>& chars) noexcept {
    return Id(chars);
  }

  friend constexpr bool operator==(const Id& a, const Id& b) noexcept { return a.chars_ == b.chars_; }
  friend constexpr bool operator!=(const Id& a, const Id& b) noexcept { return !(a == b); }
  friend constexpr bool operator<(const Id& a, const Id& b) noexcept { return a.chars_ < b.chars_; }

 private:
  // Identities are only produced by parse, from_digest, or the zero default.
  // The character array stays an internal detail so that no caller can invent
  // an identity that was never derived from bytes.
  constexpr explicit Id(const std::array<char, kSha256HexChars>& chars) noexcept : chars_(chars) {}

  std::array<char, kSha256HexChars> chars_{};
};

using WorkloadId = Id<WorkloadTag>;
using ContractId = Id<ContractTag>;
using RequirementId = Id<RequirementTag>;
using ScopeId = Id<ScopeTag>;
using PublisherId = Id<PublisherTag>;
using CoordinatorId = Id<CoordinatorTag>;
using ToolId = Id<ToolTag>;
using EvidenceId = Id<EvidenceTag>;
using PolicyId = Id<PolicyTag>;
using SnapshotId = Id<SnapshotTag>;
using ReceiptId = Id<ReceiptTag>;

// ---------------------------------------------------------------------------
// Generations
// ---------------------------------------------------------------------------

struct Generation {
  std::uint64_t value = 0;

  [[nodiscard]] constexpr bool is_zero() const noexcept { return value == 0; }

  friend constexpr bool operator==(const Generation&, const Generation&) noexcept = default;
  friend constexpr bool operator<(const Generation& a, const Generation& b) noexcept {
    return a.value < b.value;
  }
};

struct WorkloadGenerationTag {};
struct ContractGenerationTag {};
struct RequirementGenerationTag {};
struct PolicyGenerationTag {};
struct EvidenceGenerationTag {};
struct SatisfactionGenerationTag {};

// A generation counter. Generations start at one; zero means "no generation"
// and is never a current generation.
template <class Tag>
struct Gen {
  std::uint64_t value = 0;

  [[nodiscard]] constexpr bool is_zero() const noexcept { return value == 0; }

  // Strictly advances only when the successor is greater than the current
  // generation. This is the only way a generation may change in place.
  constexpr bool advance_to(const Gen& successor) noexcept {
    if (successor.value > value) {
      value = successor.value;
      return true;
    }
    return false;
  }

  friend constexpr bool operator==(const Gen&, const Gen&) noexcept = default;
  friend constexpr bool operator<(const Gen& a, const Gen& b) noexcept { return a.value < b.value; }
};

using WorkloadGeneration = Gen<WorkloadGenerationTag>;
using ContractGeneration = Gen<ContractGenerationTag>;
using RequirementGeneration = Gen<RequirementGenerationTag>;
using PolicyGeneration = Gen<PolicyGenerationTag>;
using EvidenceGeneration = Gen<EvidenceGenerationTag>;
using SatisfactionGeneration = Gen<SatisfactionGenerationTag>;

// ---------------------------------------------------------------------------
// Incarnations and epochs
// ---------------------------------------------------------------------------

inline constexpr std::size_t kIncarnationBytes = 16;

// A process incarnation: a fresh random value for every boot of a coordinator.
// An incarnation is never reused, so an incarnation observed in durable state
// always belongs to an earlier boot.
struct Incarnation {
  std::array<std::uint8_t, kIncarnationBytes> bytes{};

  [[nodiscard]] bool is_zero() const noexcept {
    for (const std::uint8_t byte : bytes) {
      if (byte != 0) {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] std::string str() const;

  static std::optional<Incarnation> parse(std::string_view text) noexcept;

  friend bool operator==(const Incarnation& a, const Incarnation& b) noexcept {
    return a.bytes == b.bytes;
  }
  friend bool operator!=(const Incarnation& a, const Incarnation& b) noexcept { return !(a == b); }
};

// A per-process incarnation for a non-coordinator process. Producers carry one
// so that replay from an earlier boot can be refused.
Incarnation new_incarnation();
Incarnation zero_incarnation() noexcept;

// A monotonic boot epoch. Epochs strictly increase across boots of the same
// state directory; a request that names an older epoch is refused.
struct Epoch {
  std::uint64_t value = 0;
  friend constexpr bool operator==(const Epoch&, const Epoch&) noexcept = default;
  friend constexpr bool operator<(const Epoch& a, const Epoch& b) noexcept {
    return a.value < b.value;
  }
};

inline constexpr std::uint64_t kNoEpoch = 0;

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

inline constexpr std::uint64_t kFnvOffsetBasis = 1469598103934665603ull;
inline constexpr std::uint64_t kFnvPrime = 1099511628211ull;

// Stable non-cryptographic identifier for compile-time constant tools.
constexpr std::uint64_t fnv1a64(std::string_view text) noexcept {
  std::uint64_t hash = kFnvOffsetBasis;
  for (char c : text) {
    hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(c));
    hash *= kFnvPrime;
  }
  return hash;
}

// Deterministic machine-local coordinator identity for a tool with a known
// name. Machine identity is not required to be secret; it is bound into the
// ledger so authority from another installation is rejected.
ToolId tool_identity(std::string_view name) noexcept;

// Platform stable machine identity, mixed into coordinator identities.
std::uint64_t machine_identity() noexcept;

// Cryptographically seeded random bytes. Throws std::runtime_error when the
// platform source of entropy is unavailable; a caller must never substitute
// predictable bytes for an incarnation, epoch, or key.
void random_bytes(std::span<std::uint8_t> out);

std::string hex_encode(std::span<const std::uint8_t> bytes);
std::string hex_encode(const Digest& digest);
std::optional<Digest> hex_decode_digest(std::string_view text) noexcept;

std::string base64url_encode(std::span<const std::uint8_t> bytes);
std::optional<std::vector<std::uint8_t>> base64url_decode(std::string_view text,
                                                          std::size_t max_bytes);

// Formats a generation for diagnostics: "g<value>" or "g0" when unset.
std::string format_generation(std::uint64_t value);

}  // namespace wnc

#include "wnc/identity.inl"

#endif  // WNC_IDENTITY_HPP
