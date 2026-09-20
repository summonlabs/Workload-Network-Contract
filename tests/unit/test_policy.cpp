// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc_test.hpp"

#include <string>

#include "wnc/hash.hpp"
#include "wnc/policy.hpp"

using namespace wnc;

namespace {

Requirement bandwidth(std::string scope, RequirementStrength strength, double target,
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

PolicyRule bandwidth_rule(std::string scope, double min_minimum, double max_minimum) {
  PolicyRule rule;
  rule.kind = RequirementKind::kMinBandwidth;
  rule.scope = std::move(scope);
  rule.min_minimum = min_minimum;
  rule.max_minimum = max_minimum;
  rule.min_target = min_minimum;
  rule.max_target = max_minimum;
  return rule;
}

ContractBody body_with(std::vector<Requirement> requirements) {
  ContractBody body;
  body.schema_version = kSchemaVersion;
  body.workload.id = WorkloadId::from_digest(sha256(std::string_view("policy-workload")));
  body.workload.name = "trainer";
  body.workload.generation.value = 1;
  body.generation.value = 1;
  body.policy_generation.value = 1;
  body.major = 1;
  Scope scope;
  scope.name = "fabric";
  body.scopes.push_back(scope);
  body.requirements = std::move(requirements);
  return body;
}

Policy policy_with(std::vector<PolicyRule> rules) {
  Policy policy;
  policy.schema_version = kSchemaVersion;
  policy.generation.value = 1;
  policy.rules = std::move(rules);
  policy.policy_id = derive_policy_id(policy_digest(policy));
  return policy;
}

}  // namespace

WNC_TEST(policy, policy_digest_is_stable_and_content_addressed) {
  Policy first = policy_with({bandwidth_rule("fabric", 1000.0, 2000.0)});
  Policy second = policy_with({bandwidth_rule("fabric", 1000.0, 2000.0)});
  WNC_CHECK_EQ(hex_encode(policy_digest(first)), hex_encode(policy_digest(second)));
  WNC_CHECK_EQ(first.policy_id.view(), second.policy_id.view());

  second.rules.front().max_minimum = 3000.0;
  second.policy_id = derive_policy_id(policy_digest(second));
  WNC_CHECK_NE(hex_encode(policy_digest(first)), hex_encode(policy_digest(second)));

  // Round trip through the wire form preserves the identity.
  const std::string text = policy_to_json(first).dump();
  const PolicyDecodeResult decoded = policy_from_text(text);
  WNC_CHECK_MSG(decoded.ok, decoded.message);
  WNC_CHECK_EQ(decoded.policy.policy_id.view(), first.policy_id.view());
  WNC_CHECK_EQ(policy_to_json(decoded.policy).dump(), text);
}

WNC_TEST(policy, validation_reports_impossible_rules) {
  Policy policy = policy_with({bandwidth_rule("fabric", 2000.0, 1000.0)});
  const PolicyValidationResult validation = validate_policy(policy);
  WNC_CHECK(!validation.ok);
  bool saw_range = false;
  for (const std::string& reason : validation.reasons()) {
    if (reason.find("max_minimum is below min_minimum") != std::string::npos) {
      saw_range = true;
    }
  }
  WNC_CHECK(saw_range);
}

WNC_TEST(policy, contract_is_checked_against_allowed_ranges) {
  const Policy policy = policy_with({bandwidth_rule("fabric", 1000.0, 5000.0)});

  const ContractBody inside = body_with({bandwidth("fabric", RequirementStrength::kRequired,
                                                   3000.0, 3000.0)});
  const PolicyValidationResult accepted = check_contract_against_policy(policy, inside);
  std::string accepted_detail = "no reasons";
  if (!accepted.reasons().empty()) {
    accepted_detail = accepted.reasons().front();
  }
  WNC_CHECK_MSG(accepted.ok, accepted_detail);

  const ContractBody too_low =
      body_with({bandwidth("fabric", RequirementStrength::kRequired, 100.0, 100.0)});
  const PolicyValidationResult refused = check_contract_against_policy(policy, too_low);
  WNC_CHECK(!refused.ok);
  WNC_CHECK_EQ(refused.diagnostics.first_error_code(), Code::kPolicyDenied);
}

WNC_TEST(policy, strength_floor_and_ceiling_are_enforced) {
  PolicyRule rule = bandwidth_rule("fabric", 0.0, 1000000.0);
  rule.minimum_strength = RequirementStrength::kRequired;
  rule.maximum_strength = RequirementStrength::kRequired;
  const Policy policy = policy_with({rule});

  const ContractBody preferred = body_with(
      {bandwidth("fabric", RequirementStrength::kPreferred, 2000.0, 1000.0)});
  const PolicyValidationResult refused = check_contract_against_policy(policy, preferred);
  WNC_CHECK(!refused.ok);
  bool saw_floor = false;
  for (const std::string& reason : refused.reasons()) {
    if (reason.find("below the policy floor") != std::string::npos) {
      saw_floor = true;
    }
  }
  WNC_CHECK(saw_floor);
}

WNC_TEST(policy, forbidden_kind_is_refused_with_scope_evidence) {
  PolicyRule rule;
  rule.kind = RequirementKind::kMinBandwidth;
  rule.scope = "fabric";
  rule.allow = false;
  const Policy policy = policy_with({rule});
  Contract canonical;
  canonical.body = body_with({bandwidth("fabric", RequirementStrength::kRequired, 10.0, 10.0)});
  WNC_CHECK(canonicalize(canonical));
  const ContractBody& body = canonical.body;
  const PolicyValidationResult refused = check_contract_against_policy(policy, body);
  WNC_CHECK(!refused.ok);
  const Diagnostic& diagnostic = refused.diagnostics.entries().front();
  WNC_CHECK_EQ(diagnostic.code, Code::kPolicyDenied);
  WNC_CHECK(!diagnostic.requirement.is_zero());
}

WNC_TEST(policy, compatibility_rejects_major_change_and_closed_requirements) {
  ContractBody previous = body_with({bandwidth("fabric", RequirementStrength::kRequired, 100.0,
                                               100.0)});

  ContractBody next = previous;
  next.generation.value = 2;
  WNC_CHECK(check_compatibility(previous, next).compatible());

  ContractBody bumped = next;
  bumped.major = 2;
  const CompatibilityResult major = check_compatibility(previous, bumped);
  WNC_CHECK(!major.compatible());
  WNC_CHECK_EQ(major.diagnostics.first_error_code(), Code::kIncompatibleMajor);

  ContractBody removed = next;
  removed.requirements.clear();
  const CompatibilityResult removal = check_compatibility(previous, removed);
  WNC_CHECK(!removal.compatible());
  WNC_CHECK_EQ(removal.diagnostics.first_error_code(), Code::kIncompatibleRequirementRemoved);

  ContractBody weakened = next;
  weakened.requirements.front().minimum = 10.0;
  weakened.requirements.front().target = 10.0;
  const CompatibilityResult weak = check_compatibility(previous, weakened);
  WNC_CHECK(!weak.compatible());
  WNC_CHECK_EQ(weak.diagnostics.first_error_code(), Code::kIncompatibleRequirementWeakened);

  ContractBody strengthened = next;
  strengthened.requirements.front().minimum = 200.0;
  strengthened.requirements.front().target = 200.0;
  WNC_CHECK(check_compatibility(previous, strengthened).compatible());

  ContractBody added = next;
  Requirement extra = bandwidth("fabric", RequirementStrength::kRequired, 5.0, 5.0);
  extra.key = "extra";
  added.requirements.push_back(extra);
  const CompatibilityResult additions = check_compatibility(previous, added);
  WNC_CHECK(additions.compatible());
  WNC_CHECK_EQ(additions.verdict, CompatibilityVerdict::kCompatibleWithAdditions);
}

WNC_TEST(policy, compatibility_rejects_stale_generation) {
  ContractBody previous = body_with({bandwidth("fabric", RequirementStrength::kRequired, 1.0, 1.0)});
  ContractBody same = previous;
  const CompatibilityResult result = check_compatibility(previous, same);
  WNC_CHECK(!result.compatible());
  WNC_CHECK_EQ(result.diagnostics.first_error_code(), Code::kStaleGeneration);
}
