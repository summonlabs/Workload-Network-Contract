// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Publisher identity binding and signature verification.
//
// A contract submission carries a signer identity. The identity is never read
// from a provenance field that the submitter controls: it is derived from the
// verified signature over the exact canonical bytes of the submission, using a
// key that the coordinator already trusts for that publisher. A submission that
// names a publisher whose key did not sign it is rejected with
// kPublisherMismatch, and a key that is not in the trust set is rejected with
// kPublisherNotTrusted.

#ifndef WNC_SIGNATURE_HPP
#define WNC_SIGNATURE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "wnc/ed25519.hpp"
#include "wnc/error.hpp"
#include "wnc/identity.hpp"

namespace wnc {

enum class SignatureAlgorithm : std::uint8_t {
  kNone = 0,
  kEd25519 = 1,
  kHmacSha256 = 2,  // shared secret deployments only; never a public key scheme
};

std::string_view signature_algorithm_token(SignatureAlgorithm algorithm) noexcept;
std::optional<SignatureAlgorithm> parse_signature_algorithm(std::string_view token) noexcept;

// Stable key identifier for an issuer: the digest of its algorithm token and
// key bytes. Two issuers with the same key material share a key id.
std::string issuer_key_id(SignatureAlgorithm algorithm, std::span<const std::uint8_t> key_bytes);

struct Issuer {
  PublisherId publisher{};
  SignatureAlgorithm algorithm = SignatureAlgorithm::kNone;
  std::string key_id;
  Ed25519PublicKey ed25519_public_key{};
  std::vector<std::uint8_t> hmac_key;
};

// The set of issuers a coordinator trusts. Its digest is bound into durable
// state: a ledger written under one trust set is not served under another,
// because that would silently change which publisher identities are current.
class TrustSet {
 public:
  void add_ed25519(PublisherId publisher, const Ed25519PublicKey& key);
  void add_hmac(PublisherId publisher, std::span<const std::uint8_t> key);

  [[nodiscard]] const std::vector<Issuer>& issuers() const noexcept { return issuers_; }
  [[nodiscard]] bool empty() const noexcept { return issuers_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return issuers_.size(); }

  // Finds the issuer record for a publisher. Returns nullptr when the publisher
  // is not trusted at all.
  [[nodiscard]] const Issuer* find(PublisherId publisher) const noexcept;

  // Finds the issuer record matching both publisher and key id.
  [[nodiscard]] const Issuer* find_key(PublisherId publisher, std::string_view key_id) const noexcept;

  // Deterministic digest over the sorted trust records.
  [[nodiscard]] Digest digest() const noexcept;

  void clear() noexcept { issuers_.clear(); }

 private:
  void sort_records();
  std::vector<Issuer> issuers_;
};

// ---------------------------------------------------------------------------
// Local signing material
// ---------------------------------------------------------------------------

// An Ed25519 key pair derived from a 32 byte seed. Seeds are never generated
// implicitly; a caller must supply one, usually loaded from a key file.
struct LocalSigner {
  Ed25519Seed seed{};
  Ed25519PublicKey public_key{};
  PublisherId publisher{};

  [[nodiscard]] std::string key_id() const;
  [[nodiscard]] Issuer issuer() const;
};

// Derives the publisher identity from the public key. The publisher identity is
// a function of the key material only, so it cannot be claimed by a party that
// does not hold the private key.
PublisherId publisher_identity(SignatureAlgorithm algorithm, std::span<const std::uint8_t> key_bytes) noexcept;

LocalSigner local_signer_from_seed(const Ed25519Seed& seed);

struct SignatureBytes {
  SignatureAlgorithm algorithm = SignatureAlgorithm::kNone;
  std::string key_id;
  std::vector<std::uint8_t> bytes;
};

// Binds a signature to the exact bytes it covers. The covered material is
// domain separated so that a signature over one object class can never be
// replayed as a signature over another.
Digest signature_subject(std::string_view domain, std::string_view canonical_bytes) noexcept;

SignatureBytes sign_with_local_signer(const LocalSigner& signer, std::string_view domain,
                                      std::string_view canonical_bytes);

struct VerifyOutcome {
  bool ok = false;
  Code code = Code::kOk;
  std::string message;
  PublisherId publisher{};
  std::string key_id;
};

// Verifies a signature against the trust set and returns the verified publisher
// identity. The publisher is taken from the trust record that matched the key,
// never from the envelope alone.
VerifyOutcome verify_signature(const TrustSet& trust, PublisherId claimed_publisher,
                               std::string_view domain, std::string_view canonical_bytes,
                               const SignatureBytes& signature);

}  // namespace wnc

#endif  // WNC_SIGNATURE_HPP
