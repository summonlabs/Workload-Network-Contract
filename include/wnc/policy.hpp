// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Policy constrains what a contract generation is allowed to declare. Policy is
// separate from the contract: a contract states what a workload needs, a policy
// states what an operator permits. A generation change of either one invalidates
// dependent evaluations, because both are inputs to the decision.

#ifndef WNC_POLICY_HPP
#define WNC_POLICY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "wnc/contract.hpp"
#include "wnc/error.hpp"
#include "wnc/identity.hpp"
#include "wnc/json.hpp"

namespace wnc {

struct PolicyRule {
  // The requirement the rule constrains, when the rule was derived from a
  // specific contract requirement. A policy written by hand leaves it zero and
  // matches by scope and key instead.
  RequirementId requirement{};
  RequirementKind kind = RequirementKind::kMinBandwidth;
  // Empty means "any scope".
  std::string scope;
  // Empty means "any key".
  std::string key;
  double min_target = 0.0;
  double max_target = 0.0;
  double min_minimum = 0.0;
  double max_minimum = 0.0;
  RequirementStrength minimum_strength = RequirementStrength::kInformational;
  RequirementStrength maximum_strength = RequirementStrength::kRequired;
  // When false, a contract must not declare a requirement of this kind at all.
  bool allow = true;
  // Values permitted for textual requirement kinds. Empty means "any value".
  std::vector<std::string> allowed_values;
};

struct Policy {
  std::uint32_t schema_version = kSchemaVersion;
  PolicyId policy_id{};
  PolicyGeneration generation{};
  std::string description;
  std::vector<PolicyRule> rules;
};

Digest policy_digest(const Policy& policy) noexcept;
PolicyId derive_policy_id(const Digest& digest) noexcept;

Json policy_to_json(const Policy& policy);

struct PolicyDecodeResult {
  bool ok = false;
  Policy policy;
  Code code = Code::kOk;
  std::string message;
};

PolicyDecodeResult policy_from_json(const Json& value);
PolicyDecodeResult policy_from_text(std::string_view text);

struct PolicyValidationResult {
  bool ok = false;
  DiagnosticLog diagnostics;
  [[nodiscard]] std::vector<std::string> reasons() const { return diagnostics.reasons(); }
};

PolicyValidationResult validate_policy(const Policy& policy);

// Checks a contract body against a policy. Every violation is reported with the
// scope and requirement it applies to, and with a stable code.
PolicyValidationResult check_contract_against_policy(const Policy& policy, const ContractBody& body);

// ---------------------------------------------------------------------------
// Compatibility between contract versions
// ---------------------------------------------------------------------------

enum class CompatibilityVerdict : std::uint8_t {
  kCompatible = 0,
  kCompatibleWithAdditions = 1,  // only requirements or scopes were added
  kIncompatible = 2,
};

struct CompatibilityResult {
  CompatibilityVerdict verdict = CompatibilityVerdict::kIncompatible;
  DiagnosticLog diagnostics;
  [[nodiscard]] bool compatible() const noexcept {
    return verdict != CompatibilityVerdict::kIncompatible;
  }
  [[nodiscard]] std::vector<std::string> reasons() const { return diagnostics.reasons(); }
};

// Compares two contract bodies under this boundary's rules: the major version
// must match, no scope that carried a REQUIRED requirement may disappear, no
// requirement key may change kind, and no requirement may be removed or
// weakened. Additions are compatible.
CompatibilityResult check_compatibility(const ContractBody& previous, const ContractBody& next);

}  // namespace wnc

#endif  // WNC_POLICY_HPP
