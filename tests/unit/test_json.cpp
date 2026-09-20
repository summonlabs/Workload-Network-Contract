// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc_test.hpp"

#include <string>

#include "wnc/json.hpp"

using namespace wnc;

namespace {

Json parse_or_fail(std::string_view text, const JsonDecodeOptions& options = {}) {
  JsonDecodeResult result = json_decode(text, options);
  WNC_CHECK_MSG(result.ok, std::string(code_token(result.code)) + ": " + result.message);
  return std::move(result.value);
}

}  // namespace

WNC_TEST(json, canonical_key_order_and_whitespace) {
  const Json value = parse_or_fail("  { \"b\" : 1 , \"a\" : [ 1 , 2 ] , \"c\" : null }  ");
  WNC_CHECK_EQ(value.dump(), std::string("{\"a\":[1,2],\"b\":1,\"c\":null}"));
}

WNC_TEST(json, number_canonicalisation) {
  WNC_CHECK_EQ(parse_or_fail("[1, 2.0, -0.0, 1e2, 0.30000000000000004]").dump(),
               std::string("[1,2.0,0.0,100.0,0.30000000000000004]"));
  WNC_CHECK_EQ(parse_or_fail("[1e-7]").dump(), std::string("[0.0000001]"));
  WNC_CHECK_EQ(parse_or_fail("[1.5e3]").dump(), std::string("[1500.0]"));
  WNC_CHECK_EQ(parse_or_fail("[123456789012]").dump(), std::string("[123456789012]"));
}

WNC_TEST(json, string_escapes) {
  WNC_CHECK_EQ(parse_or_fail("\"a\\u0041b\"").dump(), std::string("\"aAb\""));
  WNC_CHECK_EQ(parse_or_fail("\"\\u00e9\"").dump(), std::string("\"\xc3\xa9\""));
  WNC_CHECK_EQ(parse_or_fail("\"\\ud83d\\ude00\"").dump(), std::string("\"\xf0\x9f\x98\x80\""));
  WNC_CHECK_EQ(parse_or_fail("\"tab\\there\"").dump(), std::string("\"tab\\there\""));
  WNC_CHECK_EQ(parse_or_fail("\"quote\\\"slash\\\\\"").dump(),
               std::string("\"quote\\\"slash\\\\\""));
}

WNC_TEST(json, rejects_malformed_documents) {
  const std::pair<std::string_view, Code> cases[] = {
      {"", Code::kJsonSyntax},
      {"{", Code::kJsonSyntax},
      {"{}x", Code::kTrailingGarbage},
      {"{\"a\":1,\"a\":2}", Code::kJsonDuplicateKey},
      {"{\"a\":01}", Code::kJsonSyntax},
      {"{\"a\":1.}", Code::kJsonSyntax},
      {"{\"a\":tru}", Code::kJsonInvalidLiteral},
      {"{\"a\":\"unterminated}", Code::kJsonSyntax},
      {"{\"a\":\"\x01\"}", Code::kJsonSyntax},
      {"[1,2,]", Code::kJsonSyntax},
      {"\"\xff\"", Code::kJsonInvalidUtf8},
      {"\"\\ud800\"", Code::kJsonSyntax},
      {"\"\\udc00\"", Code::kJsonSyntax},
      {"[99999999999999999999]", Code::kJsonNumberOutOfRange},
      {"[1e999]", Code::kJsonNumberOutOfRange},
  };
  for (const auto& entry : cases) {
    JsonDecodeResult result = json_decode(entry.first);
    WNC_CHECK_MSG(!result.ok, std::string("accepted invalid document: ") + std::string(entry.first));
    WNC_CHECK_MSG(result.code == entry.second,
                  std::string("expected ") + std::string(code_token(entry.second)) + " for '" +
                      std::string(entry.first) + "' but got " + std::string(code_token(result.code)));
  }
}

WNC_TEST(json, bounds_are_enforced_before_allocation) {
  JsonDecodeOptions options;
  options.max_bytes = 64;
  options.max_string_bytes = 8;
  options.max_depth = 3;

  WNC_CHECK_EQ(json_decode(std::string(200, 'a'), options).code, Code::kDocumentTooLarge);
  WNC_CHECK_EQ(json_decode("\"aaaaaaaaaaaaaaaaaaa\"", options).code, Code::kJsonStringTooLong);
  WNC_CHECK_EQ(json_decode("[[[[1]]]]", options).code, Code::kJsonDepthExceeded);
  WNC_CHECK(json_decode("[[1]]", options).ok);
}

WNC_TEST(json, round_trip_preserves_value) {
  const std::string_view document =
      "{\"a\":{\"b\":[-1,0,1,2.5,\"x\"],\"c\":true},\"d\":{\"e\":null},\"f\":{}}";
  const Json first = parse_or_fail(document);
  const Json second = parse_or_fail(first.dump());
  WNC_CHECK(first == second);
  WNC_CHECK_EQ(second.dump(), first.dump());
}

WNC_TEST(json, streaming_decoder_matches_single_pass) {
  const std::string_view document = "{\"k\":[1,2,{\"n\":\"v\"}]}";
  JsonStreamingDecoder decoder;
  for (const char c : document) {
    WNC_CHECK(decoder.feed(std::string_view(&c, 1)));
  }
  const JsonDecodeResult result = decoder.finish();
  WNC_CHECK(result.ok);
  WNC_CHECK_EQ(result.value.dump(), std::string(document));
}

WNC_TEST(json, duplicates_are_detected_case_sensitively) {
  WNC_CHECK(json_decode("{\"A\":1,\"a\":2}").ok);
  WNC_CHECK_EQ(json_decode("{\"a\":1,\"a\":1}").code, Code::kJsonDuplicateKey);
}
