// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc_test.hpp"

#include <array>
#include <cstdio>
#include <string>

#include "wnc/config.hpp"
#include "wnc/error.hpp"
#include "wnc/hash.hpp"
#include "wnc/identity.hpp"

using namespace wnc;

WNC_TEST(core, sha256_known_answers) {
  WNC_CHECK_EQ(hex_encode(sha256(std::string_view(""))),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  WNC_CHECK_EQ(hex_encode(sha256(std::string_view("abc"))),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  WNC_CHECK_EQ(hex_encode(sha256(std::string_view(
                   "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
               std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

WNC_TEST(core, sha512_known_answers) {
  const Digest512 empty = sha512(std::string_view(""));
  WNC_CHECK_EQ(hex_encode(std::span<const std::uint8_t>(empty.data(), empty.size())),
               std::string("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                           "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));
  const Digest512 abc = sha512(std::string_view("abc"));
  WNC_CHECK_EQ(hex_encode(std::span<const std::uint8_t>(abc.data(), abc.size())),
               std::string("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                           "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
}

WNC_TEST(core, sha256_multi_block_boundaries) {
  // 55, 56, 63, 64, and 65 byte messages exercise every padding path.
  for (const std::size_t size : {std::size_t(55), std::size_t(56), std::size_t(63),
                                 std::size_t(64), std::size_t(65), std::size_t(1000)}) {
    const std::string message(size, 'a');
    Sha256 streaming;
    for (const char c : message) {
      streaming.update(std::string_view(&c, 1));
    }
    const Digest streamed = streaming.digest();
    const Digest single = sha256(std::string_view(message));
    WNC_CHECK_EQ(hex_encode(streamed), hex_encode(single));
  }
}

WNC_TEST(core, crc32_known_answers) {
  WNC_CHECK_EQ(crc32(std::string_view("123456789")), 0xCBF43926u);
  WNC_CHECK_EQ(crc32(std::string_view("")), 0u);
}

WNC_TEST(core, identity_round_trip) {
  const Digest digest = sha256(std::string_view("identity"));
  const WorkloadId id = WorkloadId::from_digest(digest);
  WNC_CHECK_EQ(id.view().size(), kSha256HexChars);
  const std::optional<WorkloadId> parsed = WorkloadId::parse(id.view());
  WNC_CHECK(parsed.has_value());
  WNC_CHECK_EQ(parsed->view(), id.view());
  WNC_CHECK(!id.is_zero());
  WNC_CHECK(WorkloadId{}.is_zero());

  // Uppercase input is normalised rather than rejected, but a wrong length or a
  // non hex character is refused.
  std::string upper(id.view());
  for (char& c : upper) {
    if (c >= 'a' && c <= 'f') {
      c = static_cast<char>(c - 'a' + 'A');
    }
  }
  const std::optional<WorkloadId> parsed_upper = WorkloadId::parse(upper);
  WNC_CHECK(parsed_upper.has_value());
  WNC_CHECK_EQ(parsed_upper->view(), id.view());
  WNC_CHECK(!WorkloadId::parse("abc").has_value());
  WNC_CHECK(!WorkloadId::parse(std::string(64, 'z')).has_value());
}

WNC_TEST(core, base64url_round_trip) {
  for (std::size_t size = 0; size < 40; ++size) {
    std::vector<std::uint8_t> bytes(size);
    for (std::size_t i = 0; i < size; ++i) {
      bytes[i] = static_cast<std::uint8_t>((i * 37u + size * 11u) & 0xFFu);
    }
    const std::string encoded = base64url_encode(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    const std::optional<std::vector<std::uint8_t>> decoded = base64url_decode(encoded, 4096);
    WNC_CHECK(decoded.has_value());
    WNC_CHECK_EQ(decoded->size(), bytes.size());
    WNC_CHECK(std::equal(decoded->begin(), decoded->end(), bytes.begin()));
  }
  WNC_CHECK(!base64url_decode("!!!", 16).has_value());
  WNC_CHECK(!base64url_decode("AB", 1).has_value());
}

WNC_TEST(core, diagnostics_render_stable_tokens) {
  // The bound is part of the contract: a diagnostic list never grows without
  // limit, and reaching the bound is itself reported.
  DiagnosticLog log(1);
  const auto step = [](int index) {
    std::fprintf(stderr, "[core] diagnostic step %d\n", index);
    std::fflush(stderr);
  };
  step(1);
  WNC_CHECK(log.empty());
  step(2);
  log.add(Code::kJsonDuplicateKey, "one");
  step(3);
  WNC_CHECK(log.has_errors());
  step(4);
  WNC_CHECK_EQ(log.size(), std::size_t(1));
  step(5);
  WNC_CHECK(!log.truncated());
  step(6);
  log.add(Code::kJsonDuplicateKey, "two");
  step(7);
  WNC_CHECK(log.truncated());
  step(8);
  WNC_CHECK_EQ(log.size(), std::size_t(1));
  step(9);
  const std::vector<std::string> bounded = log.reasons();
  step(10);
  WNC_CHECK_EQ(bounded.size(), std::size_t(2));
  step(11);
  WNC_CHECK_EQ(bounded.back(), std::string("too_many_reasons: diagnostic bound reached"));
  step(12);

  // A bounded log that never fills up reports exactly what was added.
  DiagnosticLog open(4);
  open.add(Code::kJsonDuplicateKey, "short");
  step(13);
  WNC_CHECK_EQ(open.size(), std::size_t(1));
  WNC_CHECK(!open.truncated());
  WNC_CHECK(open.has_errors());
  WNC_CHECK_EQ(open.first_error_code(), Code::kJsonDuplicateKey);
  const Diagnostic& first = open.entries().front();
  WNC_CHECK_EQ(first.code, Code::kJsonDuplicateKey);
  WNC_CHECK_EQ(first.message, std::string("short"));
  WNC_CHECK_EQ(first.render(), std::string("json_duplicate_key: short"));
  step(14);

  // The rendered reason is a pure function of the diagnostic: no path, no
  // timestamp, no address, and the same text every time.
  const std::string rendered = Diagnostic(Code::kJsonDuplicateKey, "short").render();
  WNC_CHECK_EQ(rendered, std::string("json_duplicate_key: short"));
  step(15);
  WNC_CHECK_EQ(code_token(Code::kContractDigestMismatch),
               std::string_view("contract_digest_mismatch"));
  step(16);

  DiagnosticLog roomy(8);
  roomy.add(Code::kOk, "informational entry");
  step(17);
  WNC_CHECK(!roomy.truncated());
  WNC_CHECK(!roomy.has_errors());
  WNC_CHECK_EQ(roomy.size(), std::size_t(1));
  step(18);
}
