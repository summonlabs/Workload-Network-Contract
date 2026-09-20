// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Adversarial input surface. Every case here is hostile: corrupt lengths,
// truncation, duplicate identities, stale generations, reordered frames, invalid
// Unicode, absurd sizes, and contradictory metadata. The requirement is not that
// the runtime is clever about these inputs, only that it refuses them
// deterministically, without crashing, and without allocating from a size the
// attacker chose.

#include "wnc_test.hpp"

#include <array>
#include <string>
#include <vector>

#include "wnc/composition.hpp"
#include "wnc/contract.hpp"
#include "wnc/evaluation.hpp"
#include "wnc/hash.hpp"
#include "wnc/json.hpp"
#include "wnc/ledger.hpp"
#include "wnc/policy.hpp"
#include "wnc/wire.hpp"

using namespace wnc;

namespace {

std::string corrupt_one_byte(std::string text, std::size_t index) {
  text[index] = static_cast<char>(static_cast<unsigned char>(text[index]) ^ 0x40u);
  return text;
}

std::vector<std::uint8_t> to_bytes(const std::string& text) {
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

}  // namespace

WNC_TEST(adversarial, frame_decoder_rejects_corrupt_and_oversized_input) {
  std::string frame;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK(wire::encode_frame(wire::MessageType::kStatus, 7, "{\"a\":1}", frame, code, message));

  // The intact frame decodes.
  wire::Frame decoded;
  std::size_t consumed = 0;
  WNC_CHECK(wire::decode_frame(frame, decoded, consumed, code, message));
  WNC_CHECK_EQ(consumed, frame.size());
  WNC_CHECK_EQ(decoded.header.request_id, std::uint64_t(7));
  WNC_CHECK_EQ(decoded.body, std::string("{\"a\":1}"));

  // Every truncated prefix is refused rather than partially accepted.
  for (std::size_t length = 0; length < frame.size(); ++length) {
    wire::Frame partial;
    std::size_t partial_consumed = 0;
    Code partial_code = Code::kOk;
    std::string partial_message;
    WNC_CHECK(!wire::decode_frame(std::string_view(frame.data(), length), partial,
                                  partial_consumed, partial_code, partial_message));
  }

  // Corrupting the header is refused with the integrity code.
  {
    std::string tampered = corrupt_one_byte(frame, 6);  // message type inside the CRC range
    wire::Frame bad;
    std::size_t bad_consumed = 0;
    Code bad_code = Code::kOk;
    std::string bad_message;
    WNC_CHECK(!wire::decode_frame(tampered, bad, bad_consumed, bad_code, bad_message));
    WNC_CHECK_EQ(bad_code, Code::kFrameCrcMismatch);
  }

  // A wrong magic is refused before anything else.
  {
    std::string tampered = frame;
    tampered[0] = 'X';
    wire::Frame bad;
    std::size_t bad_consumed = 0;
    Code bad_code = Code::kOk;
    std::string bad_message;
    WNC_CHECK(!wire::decode_frame(tampered, bad, bad_consumed, bad_code, bad_message));
    WNC_CHECK_EQ(bad_code, Code::kBadMagic);
  }

  // A declared body length beyond the bound is refused without allocating.
  {
    std::string declared;
    WNC_CHECK(wire::encode_frame(wire::MessageType::kStatus, 1, "", declared, code, message));
    const std::uint32_t huge = 0xFFFFFFFFu;
    declared[12] = static_cast<char>(huge & 0xFFu);
    declared[13] = static_cast<char>((huge >> 8) & 0xFFu);
    declared[14] = static_cast<char>((huge >> 16) & 0xFFu);
    declared[15] = static_cast<char>((huge >> 24) & 0xFFu);
    const std::uint32_t crc = crc32(std::string_view(declared.data(), 24));
    for (int i = 0; i < 4; ++i) {
      declared[24 + i] = static_cast<char>((crc >> (8 * i)) & 0xFFu);
    }
    wire::Frame bad;
    std::size_t bad_consumed = 0;
    Code bad_code = Code::kOk;
    std::string bad_message;
    WNC_CHECK(!wire::decode_frame(declared, bad, bad_consumed, bad_code, bad_message));
    WNC_CHECK(bad_code == Code::kFrameTooLarge || bad_code == Code::kBodyTooLarge);
  }

  // An oversized body is refused by the encoder.
  {
    std::string encoded;
    Code encode_code = Code::kOk;
    std::string encode_message;
    const std::string huge_body(kMaxFrameBytes + 1, 'a');
    WNC_CHECK(!wire::encode_frame(wire::MessageType::kStatus, 1, huge_body, encoded, encode_code,
                                  encode_message));
    WNC_CHECK_EQ(encode_code, Code::kBodyTooLarge);
  }
}

WNC_TEST(adversarial, ledger_parser_rejects_torn_and_doctored_records) {
  const Digest zero{};
  Digest chain{};
  Digest payload_digest{};
  const std::string frame =
      ledger::build_frame(ledger::RecordType::kGenesis, 1, "{\"a\":1}", zero, chain, payload_digest);

  ledger::Record record;
  std::size_t consumed = 0;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK(ledger::parse_frame(frame, 0, record, consumed, code, message));
  WNC_CHECK_EQ(consumed, frame.size());

  for (std::size_t length = 0; length < frame.size(); ++length) {
    ledger::Record partial;
    std::size_t partial_consumed = 0;
    Code partial_code = Code::kOk;
    std::string partial_message;
    WNC_CHECK(!ledger::parse_frame(std::string_view(frame.data(), length), 0, partial,
                                   partial_consumed, partial_code, partial_message));
  }

  // A doctored payload is caught by the payload digest.
  {
    std::string tampered = frame;
    tampered[tampered.size() - 1] = 'x';
    ledger::Record bad;
    std::size_t bad_consumed = 0;
    Code bad_code = Code::kOk;
    std::string bad_message;
    WNC_CHECK(!ledger::parse_frame(tampered, 0, bad, bad_consumed, bad_code, bad_message));
    WNC_CHECK_EQ(bad_code, Code::kLedgerCorrupt);
  }

  // A doctored header is caught by the header CRC.
  {
    std::string tampered = frame;
    tampered[9] = static_cast<char>(tampered[9] ^ 0x01);
    ledger::Record bad;
    std::size_t bad_consumed = 0;
    Code bad_code = Code::kOk;
    std::string bad_message;
    WNC_CHECK(!ledger::parse_frame(tampered, 0, bad, bad_consumed, bad_code, bad_message));
    WNC_CHECK_EQ(bad_code, Code::kLedgerCorrupt);
  }

  // An absurd declared payload length is refused before allocation.
  {
    std::string huge;
    Digest chain_out{};
    Digest payload_out{};
    huge = ledger::build_frame(ledger::RecordType::kGenesis, 1, "x", zero, chain_out, payload_out);
    const std::uint64_t declared = 0xFFFFFFFFull;
    for (int i = 0; i < 8; ++i) {
      huge[16 + i] = static_cast<char>((declared >> (8 * i)) & 0xFFu);
    }
    const std::uint32_t crc = crc32(std::string_view(huge.data(), 88));
    for (int i = 0; i < 4; ++i) {
      huge[88 + i] = static_cast<char>((crc >> (8 * i)) & 0xFFu);
    }
    ledger::Record bad;
    std::size_t bad_consumed = 0;
    Code bad_code = Code::kOk;
    std::string bad_message;
    WNC_CHECK(!ledger::parse_frame(huge, 0, bad, bad_consumed, bad_code, bad_message));
    WNC_CHECK(bad_code == Code::kLedgerOversized || bad_code == Code::kLedgerCorrupt);
  }
}

WNC_TEST(adversarial, contract_decoder_rejects_hostile_documents) {
  const std::vector<std::pair<std::string, Code>> cases = {
      {"{\"body\":null}", Code::kContractSchema},
      {"{\"body\":{}}", Code::kContractSchema},
      {"[]", Code::kJsonNotAnObject},
      {"{\"body\":{\"schema_version\":999999}}", Code::kContractSchema},
      {"{\"body\":{\"schema_version\":1,\"workload\":{}}}", Code::kContractSchema},
      {"{\"body\":{\"schema_version\":1,\"workload\":{\"id\":\"00\"}}}",
       Code::kContractSchema},
      {"{\"body\":{\"schema_version\":1,\"workload\":{\"id\":\"" + std::string(64, '0') +
           "\",\"name\":\"x\",\"generation\":1},\"contract_id\":\"" + std::string(64, '0') +
           "\",\"contract_generation\":1,\"scopes\":[],\"requirements\":[]}}",
       Code::kZeroIdentity},
  };
  for (const auto& entry : cases) {
    const ContractDecodeResult result = contract_from_text(entry.first);
    WNC_CHECK_MSG(!result.ok, "accepted hostile document: " + entry.first);
  }

  // A contract with a duplicated requirement key is refused.
  Contract contract;
  contract.body.schema_version = kSchemaVersion;
  contract.body.workload.id = WorkloadId::from_digest(sha256(std::string_view("adversarial")));
  contract.body.workload.name = "hostile";
  contract.body.workload.generation.value = 1;
  contract.body.generation.value = 1;
  contract.body.policy_generation.value = 1;
  contract.body.major = 1;
  Scope scope;
  scope.name = "fabric";
  contract.body.scopes.push_back(scope);
  Requirement requirement;
  requirement.scope = "fabric";
  requirement.kind = RequirementKind::kMinBandwidth;
  requirement.strength = RequirementStrength::kRequired;
  requirement.has_numeric = true;
  requirement.target = 10.0;
  requirement.minimum = 10.0;
  contract.body.requirements.push_back(requirement);
  contract.body.requirements.push_back(requirement);
  // Two requirements with identical content derive the identical identity, so a
  // duplicate is detectable even before canonicalisation assigns it. The body is
  // canonicalised here so that the duplicate check is what reports the refusal.
  Contract canonical;
  canonical.body = contract.body;
  (void)canonicalize(canonical);
  const ValidationResult duplicate = validate_contract_body(canonical.body);
  WNC_CHECK(!duplicate.ok);
  WNC_CHECK_EQ(duplicate.diagnostics.first_error_code(), Code::kDuplicateRequirement);

  // A requirement that names an undeclared scope is refused.
  Contract unknown_scope = canonical;
  unknown_scope.body.requirements.pop_back();
  unknown_scope.body.requirements.front().scope = "not-declared";
  unknown_scope.body.requirements.front().id = RequirementId{};
  const ValidationResult scope_result = validate_contract_body(unknown_scope.body);
  WNC_CHECK(!scope_result.ok);
  WNC_CHECK(scope_result.diagnostics.first_error_code() == Code::kUnknownScope ||
            scope_result.diagnostics.first_error_code() == Code::kZeroIdentity);

  // A required requirement with a preferred band is refused.
  Contract banded = contract;
  banded.body.requirements.pop_back();
  banded.body.requirements.front().minimum = 5.0;
  const ValidationResult band_result = validate_contract_body(banded.body);
  WNC_CHECK(!band_result.ok);
  bool saw_band = false;
  for (const Diagnostic& diagnostic : band_result.diagnostics.entries()) {
    if (diagnostic.code == Code::kValueOutOfRange) {
      saw_band = true;
    }
  }
  WNC_CHECK(saw_band);
}

WNC_TEST(adversarial, evidence_with_impossible_metadata_is_refused) {
  const std::vector<std::string> cases = {
      "{\"evidence_generation\":0,\"entries\":[]}",
      "{\"evidence_generation\":1}",
      "{\"evidence_generation\":1,\"entries\":{}}",
      "{\"evidence_generation\":1,\"entries\":[{\"scope\":\"\",\"candidate\":{}}]}",
      "{\"evidence_generation\":1,\"entries\":[{\"scope\":\"a\"}]}",
      "{\"evidence_generation\":1,\"entries\":[{\"scope\":\"a\",\"candidate\":{\"max_latency\":-1}}]}",
      "{\"evidence_generation\":1,\"entries\":[{\"scope\":\"a\",\"candidate\":{\"max_latency\":1e30}}]}",
      "{\"evidence_generation\":1,\"entries\":[{\"scope\":\"a\",\"candidate\":{\"locality\":5}}]}",
      "{\"evidence_generation\":1,\"entries\":[{\"scope\":\"a\",\"candidate\":{\"attributes\":[{\"name\":\"x\"},{\"name\":\"x\",\"value\":\"y\"}]}}]}",
      "{\"evidence_generation\":1,\"evidence_id\":\"" + std::string(64, 'a') +
          "\",\"entries\":[]}",
  };
  for (const std::string& document : cases) {
    const EvidenceDecodeResult result = evidence_from_text(document);
    WNC_CHECK_MSG(!result.ok, "accepted hostile evidence: " + document);
  }
}

WNC_TEST(adversarial, policy_decoder_rejects_contradictory_rules) {
  const std::vector<std::string> cases = {
      "{\"schema_version\":1,\"policy_generation\":0,\"rules\":[]}",
      "{\"schema_version\":1,\"policy_generation\":1}",
      "{\"schema_version\":1,\"policy_generation\":1,\"rules\":{}}",
      "{\"schema_version\":1,\"policy_generation\":1,\"rules\":[{\"kind\":\"nonsense\"}]}",
      "{\"schema_version\":1,\"policy_generation\":1,\"rules\":[{\"kind\":\"min_bandwidth\",\"minimum_strength\":\"impossible\"}]}",
  };
  for (const std::string& document : cases) {
    const PolicyDecodeResult result = policy_from_text(document);
    WNC_CHECK_MSG(!result.ok, "accepted hostile policy: " + document);
  }

  Policy policy;
  policy.schema_version = 1;
  policy.generation.value = 1;
  PolicyRule rule;
  rule.kind = RequirementKind::kMinBandwidth;
  rule.min_minimum = 100.0;
  rule.max_minimum = 10.0;
  policy.rules.push_back(rule);
  const PolicyValidationResult validation = validate_policy(policy);
  WNC_CHECK(!validation.ok);
}

WNC_TEST(adversarial, composition_refuses_weakening_and_conflicts_by_name) {
  ContractBody base;
  base.schema_version = kSchemaVersion;
  base.workload.id = WorkloadId::from_digest(sha256(std::string_view("composition")));
  base.workload.name = "composed";
  // A workload generation is a required, non-zero field: the base has to be a
  // valid contract before a layer can be composed onto it.
  base.workload.generation.value = 1;
  base.generation.value = 1;
  base.policy_generation.value = 1;
  base.generation.value = 1;
  base.policy_generation.value = 1;
  base.major = 1;
  Scope scope;
  scope.name = "fabric";
  base.scopes.push_back(scope);
  Requirement required;
  required.scope = "fabric";
  required.kind = RequirementKind::kMinBandwidth;
  required.strength = RequirementStrength::kRequired;
  required.has_numeric = true;
  required.target = 1000.0;
  required.minimum = 1000.0;
  base.requirements.push_back(required);

  // A layer that lowers the bound is refused.
  OverlayLayer weaker;
  weaker.name = "weaker";
  Requirement weakened = required;
  weakened.target = 10.0;
  weakened.minimum = 10.0;
  weaker.requirements.push_back(weakened);
  const CompositionResult refused = compose(base, {weaker});
  WNC_CHECK(!refused.ok);
  // The base declares a requirement that the layer would weaken, so the refusal
  // is the weakening denial; the empty requirement set is reported when the
  // composition cannot even assemble a body.
  WNC_CHECK(refused.code == Code::kWeakeningDenied ||
            refused.code == Code::kEmptyRequirementSet);
  WNC_CHECK(!refused.reasons().empty());

  // A layer that raises the bound is accepted and wins.
  OverlayLayer stronger;
  stronger.name = "stronger";
  Requirement strengthened = required;
  strengthened.target = 5000.0;
  strengthened.minimum = 5000.0;
  stronger.requirements.push_back(strengthened);
  // The base must be a valid contract before a layer can be composed onto it.
  Contract canonical_base;
  canonical_base.body = base;
  WNC_CHECK(canonicalize(canonical_base));
  const CompositionResult accepted = compose(canonical_base.body, {stronger});
  std::string composition_detail = accepted.message;
  for (const std::string& reason : accepted.reasons()) {
    composition_detail.append("; ").append(reason);
  }
  WNC_CHECK_MSG(accepted.ok, composition_detail);
  WNC_CHECK_EQ(accepted.body.requirements.front().target, 5000.0);
  WNC_CHECK(!accepted.decisions.empty());
  WNC_CHECK_EQ(accepted.decisions.front().kind, CompositionDecisionKind::kStrengthened);

  // A layer with an incomparable numeric band is a conflict, not a silent pick.
  OverlayLayer conflicting;
  conflicting.name = "conflicting";
  Requirement conflicted = required;
  conflicted.target = 2000.0;
  conflicted.minimum = 500.0;
  conflicting.requirements.push_back(conflicted);
  const CompositionResult conflict = compose(base, {conflicting});
  WNC_CHECK(!conflict.ok);
  WNC_CHECK_EQ(conflict.code, Code::kCompositionConflict);
  WNC_CHECK(conflict.message.find("conflict") != std::string::npos);

  // Distinct textual values at the same strength are also a conflict.
  ContractBody textual_base = base;
  textual_base.requirements.clear();
  Requirement locality;
  locality.scope = "fabric";
  locality.kind = RequirementKind::kLocality;
  locality.strength = RequirementStrength::kRequired;
  locality.value = "rack";
  textual_base.requirements.push_back(locality);

  OverlayLayer other_locality;
  other_locality.name = "other-locality";
  Requirement zone = locality;
  zone.value = "zone";
  other_locality.requirements.push_back(zone);
  const CompositionResult textual_conflict = compose(textual_base, {other_locality});
  WNC_CHECK(!textual_conflict.ok);
  WNC_CHECK_EQ(textual_conflict.code, Code::kCompositionConflict);

  // The layer bound is enforced.
  std::vector<OverlayLayer> too_many;
  for (std::size_t i = 0; i < kMaxCompositionLayers + 1; ++i) {
    OverlayLayer layer;
    layer.name = "l" + std::to_string(i);
    too_many.push_back(std::move(layer));
  }
  const CompositionResult bounded = compose(base, too_many);
  WNC_CHECK(!bounded.ok);
  WNC_CHECK_EQ(bounded.code, Code::kTooManyLayers);
}

WNC_TEST(adversarial, json_decoder_refuses_unicode_and_size_attacks) {
  const std::vector<std::string> cases = {
      std::string("\"") + static_cast<char>(0xC0) + static_cast<char>(0xAF) + "\"",  // overlong
      "\"\xed\xa0\x80\"",                                                        // surrogate
      "\"\xf4\x90\x80\x80\"",                                                  // above U+10FFFF
      "\"\xff\"",                                                                  // invalid byte
      "{\"a\":1,\"b\":2,\"a\":3}",                                              // duplicate key
  };
  for (const std::string& document : cases) {
    const JsonDecodeResult result = json_decode(document);
    WNC_CHECK_MSG(!result.ok, "accepted hostile JSON: " + document);
  }

  // A deeply nested document is refused at the depth bound rather than
  // exhausting the stack.
  std::string deep;
  for (int i = 0; i < 4096; ++i) {
    deep.push_back('[');
  }
  const JsonDecodeResult nested = json_decode(deep);
  WNC_CHECK(!nested.ok);
  WNC_CHECK(nested.code == Code::kJsonDepthExceeded || nested.code == Code::kJsonSyntax);

  // A document larger than the bound is refused before parsing.
  JsonDecodeOptions options;
  options.max_bytes = 128;
  const JsonDecodeResult huge = json_decode(std::string(4096, 'a'), options);
  WNC_CHECK(!huge.ok);
  WNC_CHECK_EQ(huge.code, Code::kDocumentTooLarge);
}

WNC_TEST(adversarial, duplicate_identifier_and_stale_generation_are_refused) {
  // Two requirements with the same identity but different content cannot both
  // be canonicalised into one body.
  ContractBody body;
  body.schema_version = kSchemaVersion;
  body.workload.id = WorkloadId::from_digest(sha256(std::string_view("duplicate")));
  body.workload.name = "duplicate";
  body.workload.generation.value = 1;
  body.generation.value = 1;
  body.policy_generation.value = 1;
  body.major = 1;
  Scope scope;
  scope.name = "fabric";
  body.scopes.push_back(scope);
  Requirement first;
  first.scope = "fabric";
  first.kind = RequirementKind::kMinBandwidth;
  first.strength = RequirementStrength::kRequired;
  first.has_numeric = true;
  first.target = 1.0;
  first.minimum = 1.0;
  body.requirements.push_back(first);
  Requirement second = first;
  second.value = "textual";
  second.has_numeric = false;
  body.requirements.push_back(second);
  const ValidationResult result = validate_contract_body(body);
  WNC_CHECK(!result.ok);

  // A superseding contract whose superseded generation is not below its own is
  // refused.
  Contract contract;
  contract.body = body;
  contract.body.requirements.pop_back();
  WNC_CHECK(canonicalize(contract));
  contract.supersedes.value = contract.body.generation.value;
  contract.supersedes_digest = contract.digest;
  const ValidationResult stale = validate_contract(contract);
  WNC_CHECK(!stale.ok);
  WNC_CHECK_EQ(stale.diagnostics.first_error_code(), Code::kStaleGeneration);
}
