// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Ed25519 and signature binding proof surface.

#include "wnc_test.hpp"

#include <array>
#include <string>
#include <vector>

#include "wnc/ed25519.hpp"
#include "wnc/hash.hpp"
#include "wnc/signature.hpp"

using namespace wnc;

namespace {

std::vector<std::uint8_t> unhex(std::string_view text) {
  WNC_CHECK_EQ(text.size() % 2, std::size_t(0));
  std::vector<std::uint8_t> out;
  out.reserve(text.size() / 2);
  const auto value_of = [](char c) -> int {
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
  };
  for (std::size_t i = 0; i < text.size(); i += 2) {
    const int high = value_of(text[i]);
    const int low = value_of(text[i + 1]);
    WNC_CHECK(high >= 0 && low >= 0);
    out.push_back(static_cast<std::uint8_t>((high << 4) | low));
  }
  return out;
}

// RFC 8032 section 7.1 test vector 1.
constexpr std::string_view kVector1Secret = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
constexpr std::string_view kVector1Public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
constexpr std::string_view kVector1Message = "";
constexpr std::string_view kVector1Signature =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

// RFC 8032 section 7.1 test vector 2 (one byte message).
constexpr std::string_view kVector2Secret = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
constexpr std::string_view kVector2Public = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
constexpr std::string_view kVector2Message = "72";
constexpr std::string_view kVector2Signature =
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

// RFC 8032 section 7.1 test vector 3 (two byte message).
constexpr std::string_view kVector3Secret = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
constexpr std::string_view kVector3Public = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
constexpr std::string_view kVector3Message = "af82";
constexpr std::string_view kVector3Signature =
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

std::string to_hex(std::span<const std::uint8_t> bytes) { return hex_encode(bytes); }

}  // namespace

WNC_TEST(crypto, ed25519_rfc8032_vectors) {
  struct Vector {
    std::string_view secret;
    std::string_view public_key;
    std::string_view message;
    std::string_view signature;
  };
  const Vector vectors[] = {
      {kVector1Secret, kVector1Public, kVector1Message, kVector1Signature},
      {kVector2Secret, kVector2Public, kVector2Message, kVector2Signature},
      {kVector3Secret, kVector3Public, kVector3Message, kVector3Signature},
  };

  for (const Vector& vector : vectors) {
    const std::vector<std::uint8_t> seed_bytes = unhex(vector.secret);
    const std::vector<std::uint8_t> expected_public = unhex(vector.public_key);
    const std::vector<std::uint8_t> message = unhex(vector.message);
    const std::vector<std::uint8_t> expected_signature = unhex(vector.signature);

    Ed25519Seed seed{};
    std::copy(seed_bytes.begin(), seed_bytes.end(), seed.begin());
    const Ed25519PublicKey public_key = ed25519_public_key(seed);
    WNC_CHECK_EQ(to_hex(std::span<const std::uint8_t>(public_key.data(), public_key.size())),
                 to_hex(std::span<const std::uint8_t>(expected_public.data(), expected_public.size())));

    const Ed25519Signature signature = ed25519_sign(
        seed, std::span<const std::uint8_t>(message.data(), message.size()));
    WNC_CHECK_EQ(to_hex(std::span<const std::uint8_t>(signature.data(), signature.size())),
                 to_hex(std::span<const std::uint8_t>(expected_signature.data(),
                                                      expected_signature.size())));

    WNC_CHECK(ed25519_verify(public_key, std::span<const std::uint8_t>(message.data(), message.size()),
                             signature));
    WNC_CHECK(ed25519_verify_strict(
        public_key, std::span<const std::uint8_t>(message.data(), message.size()), signature));

    // A single flipped message bit must fail.
    if (!message.empty()) {
      std::vector<std::uint8_t> tampered = message;
      tampered[0] = static_cast<std::uint8_t>(tampered[0] ^ 0x01u);
      WNC_CHECK(!ed25519_verify(
          public_key, std::span<const std::uint8_t>(tampered.data(), tampered.size()), signature));
    }
    // A single flipped signature bit must fail.
    Ed25519Signature tampered_signature = signature;
    tampered_signature[0] = static_cast<std::uint8_t>(tampered_signature[0] ^ 0x80u);
    WNC_CHECK(!ed25519_verify(public_key, std::span<const std::uint8_t>(message.data(), message.size()),
                              tampered_signature));
  }
}

WNC_TEST(crypto, ed25519_rejects_non_canonical_material) {
  const std::vector<std::uint8_t> seed_bytes = unhex(kVector2Secret);
  Ed25519Seed seed{};
  std::copy(seed_bytes.begin(), seed_bytes.end(), seed.begin());
  const Ed25519PublicKey public_key = ed25519_public_key(seed);
  const std::vector<std::uint8_t> message = unhex(kVector2Message);
  const Ed25519Signature signature = ed25519_sign(
      seed, std::span<const std::uint8_t>(message.data(), message.size()));

  // S above L is not a canonical scalar.
  Ed25519Signature oversized = signature;
  for (std::size_t i = 32; i < 64; ++i) {
    oversized[i] = 0xFFu;
  }
  WNC_CHECK(!ed25519_verify(public_key, std::span<const std::uint8_t>(message.data(), message.size()),
                            oversized));

  // An all zero signing scalar is structurally valid but cannot be produced by
  // a real signature; it must fail verification.
  Ed25519Signature zeroed = signature;
  for (std::size_t i = 32; i < 64; ++i) {
    zeroed[i] = 0;
  }
  WNC_CHECK(!ed25519_verify(public_key, std::span<const std::uint8_t>(message.data(), message.size()),
                            zeroed));
}

WNC_TEST(crypto, ed25519_signing_is_deterministic) {
  const std::vector<std::uint8_t> seed_bytes = unhex(kVector3Secret);
  Ed25519Seed seed{};
  std::copy(seed_bytes.begin(), seed_bytes.end(), seed.begin());
  const std::string message = "deterministic";
  const Ed25519Signature first = ed25519_sign(
      seed, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(message.data()),
                                          message.size()));
  const Ed25519Signature second = ed25519_sign(
      seed, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(message.data()),
                                          message.size()));
  WNC_CHECK_EQ(to_hex(std::span<const std::uint8_t>(first.data(), first.size())),
               to_hex(std::span<const std::uint8_t>(second.data(), second.size())));
}

WNC_TEST(crypto, trust_set_and_signature_binding) {
  const std::vector<std::uint8_t> seed_bytes = unhex(kVector1Secret);
  Ed25519Seed seed{};
  std::copy(seed_bytes.begin(), seed_bytes.end(), seed.begin());
  const LocalSigner signer = local_signer_from_seed(seed);

  TrustSet trust;
  trust.add_ed25519(signer.publisher, signer.public_key);
  WNC_CHECK_EQ(trust.size(), std::size_t(1));

  const std::string canonical = "{\"a\":1}";
  const SignatureBytes signature = sign_with_local_signer(signer, "wnc/v1/contract", canonical);
  const VerifyOutcome verified = verify_signature(trust, signer.publisher, "wnc/v1/contract",
                                                  canonical, signature);
  WNC_CHECK_MSG(verified.ok, verified.message);
  WNC_CHECK_EQ(verified.publisher.view(), signer.publisher.view());

  // A different domain must not verify: signatures are domain separated.
  const VerifyOutcome wrong_domain =
      verify_signature(trust, signer.publisher, "wnc/v1/evidence", canonical, signature);
  WNC_CHECK(!wrong_domain.ok);
  WNC_CHECK_EQ(wrong_domain.code, Code::kSignatureInvalid);

  // Different bytes must not verify.
  const VerifyOutcome wrong_bytes =
      verify_signature(trust, signer.publisher, "wnc/v1/contract", "{\"a\":2}", signature);
  WNC_CHECK(!wrong_bytes.ok);
  WNC_CHECK_EQ(wrong_bytes.code, Code::kSignatureInvalid);

  // An untrusted publisher is refused before any cryptographic work.
  const LocalSigner other = local_signer_from_seed(Ed25519Seed{7});
  const VerifyOutcome untrusted =
      verify_signature(trust, other.publisher, "wnc/v1/contract", canonical, signature);
  WNC_CHECK(!untrusted.ok);
  WNC_CHECK_EQ(untrusted.code, Code::kPublisherNotTrusted);

  // Claiming another publisher's identity does not transfer authority.
  const SignatureBytes other_signature = sign_with_local_signer(other, "wnc/v1/contract", canonical);
  const VerifyOutcome mismatch = verify_signature(trust, signer.publisher, "wnc/v1/contract",
                                                  canonical, other_signature);
  WNC_CHECK(!mismatch.ok);
  WNC_CHECK(mismatch.code == Code::kPublisherMismatch || mismatch.code == Code::kPublisherNotTrusted);
}

WNC_TEST(crypto, hmac_signature_binding) {
  const std::array<std::uint8_t, 16> key = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  const PublisherId publisher = publisher_identity(
      SignatureAlgorithm::kHmacSha256, std::span<const std::uint8_t>(key.data(), key.size()));
  TrustSet trust;
  trust.add_hmac(publisher, std::span<const std::uint8_t>(key.data(), key.size()));

  const std::string canonical = "{\"hmac\":true}";
  // The key identifier has to own its bytes: a view into the temporary the
  // function returns would dangle by the time it is hashed.
  const std::string key_id = issuer_key_id(SignatureAlgorithm::kHmacSha256,
                                           std::span<const std::uint8_t>(key.data(), key.size()));
  const std::string subject = hex_encode(signature_subject("wnc/v1/contract", canonical));
  const std::array<std::string_view, 4> parts = {std::string_view("wnc/v1/bind"), publisher.view(),
                                                 key_id, subject};
  const Digest bound = sha256_parts(std::span<const std::string_view>(parts.data(), parts.size()));
  const Digest mac = hmac_sha256(std::span<const std::uint8_t>(key.data(), key.size()),
                                 std::span<const std::uint8_t>(bound.data(), bound.size()));

  SignatureBytes signature;
  signature.algorithm = SignatureAlgorithm::kHmacSha256;
  signature.key_id = key_id;
  signature.bytes.assign(mac.begin(), mac.end());

  const VerifyOutcome verified =
      verify_signature(trust, publisher, "wnc/v1/contract", canonical, signature);
  WNC_CHECK_MSG(verified.ok, verified.message);

  signature.bytes[0] = static_cast<std::uint8_t>(signature.bytes[0] ^ 0xFFu);
  const VerifyOutcome tampered =
      verify_signature(trust, publisher, "wnc/v1/contract", canonical, signature);
  WNC_CHECK(!tampered.ok);
  WNC_CHECK_EQ(tampered.code, Code::kSignatureInvalid);
}

WNC_TEST(crypto, trust_set_digest_is_order_independent) {
  const std::vector<std::uint8_t> first_seed_bytes = unhex(kVector1Secret);
  const std::vector<std::uint8_t> second_seed_bytes = unhex(kVector2Secret);
  Ed25519Seed first_seed{};
  Ed25519Seed second_seed{};
  std::copy(first_seed_bytes.begin(), first_seed_bytes.end(), first_seed.begin());
  std::copy(second_seed_bytes.begin(), second_seed_bytes.end(), second_seed.begin());
  const LocalSigner first = local_signer_from_seed(first_seed);
  const LocalSigner second = local_signer_from_seed(second_seed);

  TrustSet forward;
  forward.add_ed25519(first.publisher, first.public_key);
  forward.add_ed25519(second.publisher, second.public_key);

  TrustSet backward;
  backward.add_ed25519(second.publisher, second.public_key);
  backward.add_ed25519(first.publisher, first.public_key);

  WNC_CHECK_EQ(hex_encode(forward.digest()), hex_encode(backward.digest()));
}
