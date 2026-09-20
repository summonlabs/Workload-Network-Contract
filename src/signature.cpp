// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/signature.hpp"

#include <algorithm>
#include <array>

#include "wnc/hash.hpp"

namespace wnc {
namespace {

constexpr std::string_view kEd25519Token = "ED25519";
constexpr std::string_view kHmacToken = "HMAC-SHA256";
constexpr std::string_view kNoneToken = "NONE";

// Binds a claim to the publisher identity and the key that must have signed it.
// Length prefixes keep distinct claims from colliding by concatenation.
Digest bind_claim(PublisherId publisher, std::string_view key_id, std::string_view subject_hex) noexcept {
  const std::array<std::string_view, 4> parts = {std::string_view("wnc/v1/bind"), publisher.view(),
                                                 key_id, subject_hex};
  return sha256_parts(std::span<const std::string_view>(parts.data(), parts.size()));
}

std::string digest_hex(const Digest& digest) { return hex_encode(digest); }

}  // namespace

std::string_view signature_algorithm_token(SignatureAlgorithm algorithm) noexcept {
  switch (algorithm) {
    case SignatureAlgorithm::kEd25519:
      return kEd25519Token;
    case SignatureAlgorithm::kHmacSha256:
      return kHmacToken;
    case SignatureAlgorithm::kNone:
      return kNoneToken;
  }
  return kNoneToken;
}

std::optional<SignatureAlgorithm> parse_signature_algorithm(std::string_view token) noexcept {
  if (token == kEd25519Token) {
    return SignatureAlgorithm::kEd25519;
  }
  if (token == kHmacToken) {
    return SignatureAlgorithm::kHmacSha256;
  }
  if (token == kNoneToken) {
    return SignatureAlgorithm::kNone;
  }
  return std::nullopt;
}

std::string issuer_key_id(SignatureAlgorithm algorithm, std::span<const std::uint8_t> key_bytes) {
  const std::array<std::string_view, 3> parts = {
      std::string_view("wnc/v1/key"), signature_algorithm_token(algorithm),
      std::string_view(reinterpret_cast<const char*>(key_bytes.data()), key_bytes.size())};
  return digest_hex(sha256_parts(std::span<const std::string_view>(parts.data(), parts.size())));
}

PublisherId publisher_identity(SignatureAlgorithm algorithm,
                               std::span<const std::uint8_t> key_bytes) noexcept {
  const std::array<std::string_view, 3> parts = {
      std::string_view("wnc/v1/publisher"), signature_algorithm_token(algorithm),
      std::string_view(reinterpret_cast<const char*>(key_bytes.data()), key_bytes.size())};
  return PublisherId::from_digest(sha256_parts(std::span<const std::string_view>(parts.data(), parts.size())));
}

void TrustSet::add_ed25519(PublisherId publisher, const Ed25519PublicKey& key) {
  Issuer issuer;
  issuer.publisher = publisher;
  issuer.algorithm = SignatureAlgorithm::kEd25519;
  issuer.key_id = issuer_key_id(SignatureAlgorithm::kEd25519, std::span<const std::uint8_t>(key.data(), key.size()));
  issuer.ed25519_public_key = key;
  issuers_.push_back(std::move(issuer));
  sort_records();
}

void TrustSet::add_hmac(PublisherId publisher, std::span<const std::uint8_t> key) {
  Issuer issuer;
  issuer.publisher = publisher;
  issuer.algorithm = SignatureAlgorithm::kHmacSha256;
  issuer.key_id = issuer_key_id(SignatureAlgorithm::kHmacSha256, key);
  issuer.hmac_key.assign(key.begin(), key.end());
  issuers_.push_back(std::move(issuer));
  sort_records();
}

void TrustSet::sort_records() {
  std::sort(issuers_.begin(), issuers_.end(), [](const Issuer& a, const Issuer& b) {
    if (a.publisher != b.publisher) {
      return a.publisher < b.publisher;
    }
    return a.key_id < b.key_id;
  });
  issuers_.erase(std::unique(issuers_.begin(), issuers_.end(),
                             [](const Issuer& a, const Issuer& b) {
                               return a.publisher == b.publisher && a.key_id == b.key_id;
                             }),
                 issuers_.end());
}

const Issuer* TrustSet::find(PublisherId publisher) const noexcept {
  for (const Issuer& issuer : issuers_) {
    if (issuer.publisher == publisher) {
      return &issuer;
    }
  }
  return nullptr;
}

const Issuer* TrustSet::find_key(PublisherId publisher, std::string_view key_id) const noexcept {
  for (const Issuer& issuer : issuers_) {
    if (issuer.publisher == publisher && issuer.key_id == key_id) {
      return &issuer;
    }
  }
  return nullptr;
}

Digest TrustSet::digest() const noexcept {
  std::vector<std::string_view> parts;
  parts.reserve(issuers_.size() * 3 + 1);
  parts.push_back(std::string_view("wnc/v1/trust"));
  for (const Issuer& issuer : issuers_) {
    parts.push_back(issuer.publisher.view());
    parts.push_back(signature_algorithm_token(issuer.algorithm));
    parts.push_back(issuer.key_id);
  }
  return sha256_parts(std::span<const std::string_view>(parts.data(), parts.size()));
}

std::string LocalSigner::key_id() const {
  return issuer_key_id(SignatureAlgorithm::kEd25519,
                       std::span<const std::uint8_t>(public_key.data(), public_key.size()));
}

Issuer LocalSigner::issuer() const {
  Issuer out;
  out.publisher = publisher;
  out.algorithm = SignatureAlgorithm::kEd25519;
  out.key_id = key_id();
  out.ed25519_public_key = public_key;
  return out;
}

LocalSigner local_signer_from_seed(const Ed25519Seed& seed) {
  LocalSigner signer;
  signer.seed = seed;
  signer.public_key = ed25519_public_key(seed);
  signer.publisher = publisher_identity(
      SignatureAlgorithm::kEd25519, std::span<const std::uint8_t>(signer.public_key.data(),
                                                                 signer.public_key.size()));
  return signer;
}

Digest signature_subject(std::string_view domain, std::string_view canonical_bytes) noexcept {
  return digest_domain(domain, canonical_bytes);
}

SignatureBytes sign_with_local_signer(const LocalSigner& signer, std::string_view domain,
                                      std::string_view canonical_bytes) {
  const Digest subject = signature_subject(domain, canonical_bytes);
  const Digest bound = bind_claim(signer.publisher, signer.key_id(), digest_hex(subject));

  SignatureBytes out;
  out.algorithm = SignatureAlgorithm::kEd25519;
  out.key_id = signer.key_id();
  const Ed25519Signature signature = ed25519_sign(
      signer.seed, std::span<const std::uint8_t>(bound.data(), bound.size()));
  out.bytes.assign(signature.begin(), signature.end());
  return out;
}

VerifyOutcome verify_signature(const TrustSet& trust, PublisherId claimed_publisher,
                               std::string_view domain, std::string_view canonical_bytes,
                               const SignatureBytes& signature) {
  VerifyOutcome outcome;
  outcome.publisher = claimed_publisher;
  outcome.key_id = signature.key_id;

  if (claimed_publisher.is_zero()) {
    outcome.code = Code::kZeroIdentity;
    outcome.message = "submission carries the zero publisher identity";
    return outcome;
  }
  if (signature.algorithm == SignatureAlgorithm::kNone || signature.bytes.empty()) {
    outcome.code = Code::kSignatureMissing;
    outcome.message = "submission carries no signature";
    return outcome;
  }
  if (signature.key_id.size() != kSha256HexChars) {
    outcome.code = Code::kSignatureInvalid;
    outcome.message = "signature key identifier is not a 64 character digest";
    return outcome;
  }

  const Issuer* issuer = trust.find_key(claimed_publisher, signature.key_id);
  if (issuer == nullptr) {
    if (trust.find(claimed_publisher) == nullptr) {
      outcome.code = Code::kPublisherNotTrusted;
      outcome.message = "publisher is not present in the trust set";
    } else {
      outcome.code = Code::kPublisherMismatch;
      outcome.message = "trust set holds no key with that identifier for the publisher";
    }
    return outcome;
  }

  const Digest subject = signature_subject(domain, canonical_bytes);
  const Digest bound = bind_claim(claimed_publisher, signature.key_id, digest_hex(subject));

  if (issuer->algorithm == SignatureAlgorithm::kEd25519) {
    if (signature.bytes.size() != kEd25519SignatureBytes) {
      outcome.code = Code::kSignatureInvalid;
      outcome.message = "ed25519 signature must be 64 bytes";
      return outcome;
    }
    Ed25519Signature raw{};
    std::copy(signature.bytes.begin(), signature.bytes.end(), raw.begin());
    if (!ed25519_verify_strict(issuer->ed25519_public_key,
                               std::span<const std::uint8_t>(bound.data(), bound.size()), raw)) {
      outcome.code = Code::kSignatureInvalid;
      outcome.message = "ed25519 signature does not verify for the submitted bytes";
      return outcome;
    }
  } else if (issuer->algorithm == SignatureAlgorithm::kHmacSha256) {
    const Digest mac = hmac_sha256(
        std::span<const std::uint8_t>(issuer->hmac_key.data(), issuer->hmac_key.size()),
        std::span<const std::uint8_t>(bound.data(), bound.size()));
    if (!constant_time_equal(std::span<const std::uint8_t>(mac.data(), mac.size()),
                             std::span<const std::uint8_t>(signature.bytes.data(),
                                                           signature.bytes.size()))) {
      outcome.code = Code::kSignatureInvalid;
      outcome.message = "hmac does not verify for the submitted bytes";
      return outcome;
    }
  } else {
    outcome.code = Code::kSignatureInvalid;
    outcome.message = "signature algorithm is not verifiable";
    return outcome;
  }

  outcome.ok = true;
  outcome.publisher = issuer->publisher;
  outcome.key_id = issuer->key_id;
  return outcome;
}

}  // namespace wnc
