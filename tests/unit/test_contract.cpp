// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc_test.hpp"

#include <string>

#include "wnc/contract.hpp"
#include "wnc/hash.hpp"

using namespace wnc;

namespace {

Requirement make_bandwidth(std::string scope, RequirementStrength strength, double target,
                           double minimum) {
  Requirement requirement;
  requirement.scope = std::move(scope);
  requirement.kind = RequirementKind::kMinBandwidth;
  requirement.strength = strength;
  requirement.has_numeric = true;
  requirement.target = target;
  requirement.minimum = minimum;
  return requirement;
}

ContractBody make_body(std::string workload_name) {
  ContractBody body;
  body.schema_version = kSchemaVersion;
  body.workload.id = WorkloadId::from_digest(sha256(std::string_view("workload")));
  body.workload.name = std::move(workload_name);
  body.workload.generation.value = 1;
  body.generation.value = 1;
  body.policy_generation.value = 1;
  body.major = 1;
  Scope scope;
  scope.name = "fabric";
  body.scopes.push_back(scope);
  body.requirements.push_back(
      make_bandwidth("fabric", RequirementStrength::kRequired, 25000000000.0, 25000000000.0));
  return body;
}

}  // namespace

WNC_TEST(contract, canonicalisation_derives_identity) {
  Contract contract;
  contract.body = make_body("trainer");
  WNC_CHECK(canonicalize(contract));
  // Canonicalising twice must be a fixed point: the digest and the identity are
  // already derived from the content, so a second pass changes nothing.
  const Digest first_digest = contract.digest;
  WNC_CHECK(canonicalize(contract));
  WNC_CHECK_EQ(hex_encode(contract.digest), hex_encode(first_digest));
  const ValidationResult validation = validate_contract(contract);
  std::string detail = "no diagnostics";
  if (!validation.diagnostics.entries().empty()) {
    detail = validation.diagnostics.entries().front().render();
  }
  WNC_CHECK_MSG(validation.ok, detail);
  WNC_CHECK(!contract.body.contract_id.is_zero());
  WNC_CHECK(!contract.body.requirements.front().id.is_zero());
}

WNC_TEST(contract, digest_ignores_requirement_order) {
  Contract first;
  first.body = make_body("trainer");
  Requirement latency;
  latency.scope = "fabric";
  latency.kind = RequirementKind::kMaxLatency;
  latency.strength = RequirementStrength::kPreferred;
  latency.has_numeric = true;
  latency.target = 50.0;
  latency.minimum = 100.0;
  first.body.requirements.push_back(latency);
  WNC_CHECK(canonicalize(first));

  Contract second;
  second.body = make_body("trainer");
  second.body.requirements.insert(second.body.requirements.begin(), latency);
  WNC_CHECK(canonicalize(second));

  WNC_CHECK_EQ(hex_encode(first.digest), hex_encode(second.digest));
  WNC_CHECK_EQ(first.body.contract_id.view(), second.body.contract_id.view());
  WNC_CHECK_EQ(first.body.requirements.front().id.view(), second.body.requirements.front().id.view());
}

WNC_TEST(contract, digest_changes_with_content) {
  Contract first;
  first.body = make_body("trainer");
  WNC_CHECK(canonicalize(first));

  Contract second;
  second.body = make_body("trainer");
  second.body.requirements.front().target = 5000000000.0;
  second.body.requirements.front().minimum = 5000000000.0;
  WNC_CHECK(canonicalize(second));

  WNC_CHECK_NE(hex_encode(first.digest), hex_encode(second.digest));
}

WNC_TEST(contract, serialization_round_trip) {
  Contract contract;
  contract.body = make_body("trainer");
  contract.body.description = "canonical round trip";
  Requirement locality;
  locality.scope = "fabric";
  locality.kind = RequirementKind::kLocality;
  locality.strength = RequirementStrength::kRequired;
  locality.value = "rack";
  locality.attributes.emplace_back("zone", "a");
  contract.body.requirements.push_back(locality);
  WNC_CHECK(canonicalize(contract));

  const std::string text = contract_to_json(contract).dump();
  const ContractDecodeResult decoded = contract_from_text(text);
  WNC_CHECK_MSG(decoded.ok, decoded.message);
  WNC_CHECK_EQ(hex_encode(decoded.contract.digest), hex_encode(contract.digest));
  WNC_CHECK_EQ(decoded.contract.body.contract_id.view(), contract.body.contract_id.view());
  WNC_CHECK_EQ(contract_to_json(decoded.contract).dump(), text);
}

WNC_TEST(contract, validation_reports_exact_reasons) {
  ContractBody body = make_body("trainer");
  body.workload.generation.value = 0;
  Requirement duplicate = body.requirements.front();
  body.requirements.push_back(duplicate);
  Requirement unknown_scope = make_bandwidth("missing", RequirementStrength::kRequired, 1.0, 1.0);
  body.requirements.push_back(unknown_scope);

  const ValidationResult validation = validate_contract_body(body);
  WNC_CHECK(!validation.ok);
  const std::vector<std::string> reasons = validation.reasons();
  WNC_CHECK(!reasons.empty());
  bool saw_zero_generation = false;
  bool saw_unknown_scope = false;
  bool saw_duplicate = false;
  for (const std::string& reason : reasons) {
    if (reason.find("workload generation must be at least 1") != std::string::npos) {
      saw_zero_generation = true;
    }
    if (reason.find("undeclared scope 'missing'") != std::string::npos) {
      saw_unknown_scope = true;
    }
    if (reason.find("requirement key is repeated") != std::string::npos) {
      saw_duplicate = true;
    }
  }
  WNC_CHECK(saw_zero_generation);
  WNC_CHECK(saw_unknown_scope);
  WNC_CHECK(saw_duplicate);
}

WNC_TEST(contract, decoder_rejects_unknown_and_malformed_fields) {
  Contract contract;
  contract.body = make_body("trainer");
  WNC_CHECK(canonicalize(contract));
  const std::string good = contract_to_json(contract).dump();

  WNC_CHECK(contract_from_text(good).ok);
  WNC_CHECK_EQ(contract_from_text("[]").code, Code::kJsonNotAnObject);
  WNC_CHECK_EQ(contract_from_text("{\"body\":{}}").code, Code::kContractSchema);

  // A digest that does not describe the body is refused.
  std::string tampered = good;
  const std::size_t at = tampered.find("\"digest\":\"");
  WNC_CHECK(at != std::string::npos);
  tampered[at + 11] = tampered[at + 11] == 'a' ? 'b' : 'a';
  WNC_CHECK_EQ(contract_from_text(tampered).code, Code::kContractDigestMismatch);
}

WNC_TEST(contract, bounds_reject_oversized_contracts) {
  Json document = contract_body_to_json(make_body("trainer"));
  JsonArray requirements;
  for (std::size_t i = 0; i < kMaxRequirementsPerContract + 1; ++i) {
    Requirement requirement = make_bandwidth("fabric", RequirementStrength::kRequired, 1.0, 1.0);
    requirement.key = "k" + std::to_string(i);
    requirement.id = derive_requirement_id(requirement);
    requirements.push_back(requirement_to_json(requirement));
  }
  document.set("requirements", Json(std::move(requirements)));
  Json root;
  root.set("body", std::move(document));
  root.set("digest", hex_encode(Digest{}));
  // The decoder refuses the requirement count before it materialises anything,
  // which is the point of the bound; the exact code is the requirement bound.
  WNC_CHECK_EQ(contract_from_json(root).code, Code::kTooManyRequirements);
}
