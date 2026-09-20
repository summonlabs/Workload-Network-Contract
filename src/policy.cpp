// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/policy.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

#include "wnc/hash.hpp"

namespace wnc {
namespace {

constexpr std::size_t kMaxPolicyRules = 4096;
constexpr std::size_t kMaxAllowedValues = 64;
constexpr std::uint64_t kMaxPolicyParameter = 1000000000000000ull;

std::string rule_path(std::size_t index) { return "rules[" + std::to_string(index) + "]"; }

bool read_string_field(const JsonObject& object, std::string_view field, std::string_view path,
                       std::size_t max_bytes, bool required, std::string& out, Code& code,
                       std::string& message) {
  const auto it = object.find(field);
  if (it == object.end()) {
    if (!required) {
      return true;
    }
    code = Code::kPolicyDenied;
    message = std::string(path) + "." + std::string(field) + " is required";
    return false;
  }
  if (!it->second.is_string()) {
    code = Code::kPolicyDenied;
    message = std::string(path) + "." + std::string(field) + " must be a string";
    return false;
  }
  if (it->second.as_string().size() > max_bytes) {
    code = Code::kJsonStringTooLong;
    message = std::string(path) + "." + std::string(field) + " exceeds its byte bound";
    return false;
  }
  out = it->second.as_string();
  return true;
}

bool read_number_field(const JsonObject& object, std::string_view field, std::string_view path,
                       double& out, Code& code, std::string& message) {
  const auto it = object.find(field);
  if (it == object.end()) {
    return true;
  }
  if (!it->second.is_number()) {
    code = Code::kPolicyDenied;
    message = std::string(path) + "." + std::string(field) + " must be a number";
    return false;
  }
  const double value = it->second.as_real();
  if (!std::isfinite(value) || value < 0.0 || value > static_cast<double>(kMaxPolicyParameter)) {
    code = Code::kValueOutOfRange;
    message = std::string(path) + "." + std::string(field) + " is outside the permitted range";
    return false;
  }
  out = value;
  return true;
}

}  // namespace

Digest policy_digest(const Policy& policy) noexcept {
  return digest_domain("wnc/v1/policy", policy_to_json(policy).dump());
}

PolicyId derive_policy_id(const Digest& digest) noexcept {
  const std::string digest_hex = hex_encode(digest);
  const std::array<std::string_view, 2> parts = {std::string_view("wnc/v1/policy-id"), digest_hex};
  return PolicyId::from_digest(sha256_parts(std::span<const std::string_view>(parts.data(), parts.size())));
}

Json policy_to_json(const Policy& policy) {
  Json out;
  out.set("schema_version", static_cast<std::int64_t>(policy.schema_version));
  out.set("policy_id", policy.policy_id.str());
  out.set("policy_generation", static_cast<std::int64_t>(policy.generation.value));
  out.set("description", policy.description);
  JsonArray rules;
  rules.reserve(policy.rules.size());
  for (const PolicyRule& rule : policy.rules) {
    Json item;
    item.set("kind", std::string(requirement_kind_token(rule.kind)));
    item.set("scope", rule.scope);
    item.set("key", rule.key);
    item.set("allow", rule.allow);
    item.set("min_target", rule.min_target);
    item.set("max_target", rule.max_target);
    item.set("min_minimum", rule.min_minimum);
    item.set("max_minimum", rule.max_minimum);
    item.set("minimum_strength", std::string(requirement_strength_token(rule.minimum_strength)));
    item.set("maximum_strength", std::string(requirement_strength_token(rule.maximum_strength)));
    if (!rule.allowed_values.empty()) {
      JsonArray values;
      values.reserve(rule.allowed_values.size());
      for (const std::string& value : rule.allowed_values) {
        values.push_back(Json(value));
      }
      item.set("allowed_values", Json(std::move(values)));
    }
    rules.push_back(std::move(item));
  }
  out.set("rules", Json(std::move(rules)));
  return out;
}

PolicyDecodeResult policy_from_json(const Json& value) {
  PolicyDecodeResult result;
  if (!value.is_object()) {
    result.code = Code::kJsonNotAnObject;
    result.message = "policy document must be an object";
    return result;
  }
  const JsonObject& object = value.object();
  Policy policy;

  const auto schema = object.find("schema_version");
  if (schema == object.end() || !schema->second.is_int() || schema->second.as_int() < 0 ||
      schema->second.as_int() > 1000) {
    result.code = Code::kPolicyDenied;
    result.message = "policy.schema_version is required and must be a small positive integer";
    return result;
  }
  policy.schema_version = static_cast<std::uint32_t>(schema->second.as_int());

  const auto generation = object.find("policy_generation");
  if (generation == object.end() || !generation->second.is_int() || generation->second.as_int() < 1) {
    result.code = Code::kPolicyDenied;
    result.message = "policy.policy_generation must be at least 1";
    return result;
  }
  policy.generation.value = static_cast<std::uint64_t>(generation->second.as_int());

  if (!read_string_field(object, "description", "policy", kMaxStringBytes, false, policy.description,
                         result.code, result.message)) {
    return result;
  }
  std::string policy_id;
  if (!read_string_field(object, "policy_id", "policy", kSha256HexChars, false, policy_id,
                         result.code, result.message)) {
    return result;
  }

  const auto rules = object.find("rules");
  if (rules == object.end() || !rules->second.is_array()) {
    result.code = Code::kPolicyDenied;
    result.message = "policy.rules must be an array";
    return result;
  }
  if (rules->second.size() > kMaxPolicyRules) {
    result.code = Code::kTooManyRequirements;
    result.message = "policy declares more rules than the bound permits";
    return result;
  }
  policy.rules.reserve(rules->second.size());
  for (std::size_t i = 0; i < rules->second.size(); ++i) {
    const Json* item = rules->second.at(i);
    const std::string path = rule_path(i);
    if (item == nullptr || !item->is_object()) {
      result.code = Code::kPolicyDenied;
      result.message = path + " must be an object";
      return result;
    }
    const JsonObject& rule_object = item->object();
    PolicyRule rule;

    std::string kind_token;
    if (!read_string_field(rule_object, "kind", path, 64, true, kind_token, result.code,
                           result.message)) {
      return result;
    }
    const std::optional<RequirementKind> kind = parse_requirement_kind(kind_token);
    if (!kind.has_value()) {
      result.code = Code::kInvalidKind;
      result.message = path + ".kind is not a defined requirement kind";
      return result;
    }
    rule.kind = *kind;

    if (!read_string_field(rule_object, "scope", path, kMaxStringBytes, false, rule.scope,
                           result.code, result.message) ||
        !read_string_field(rule_object, "key", path, kMaxStringBytes, false, rule.key, result.code,
                           result.message)) {
      return result;
    }

    const auto allow = rule_object.find("allow");
    if (allow != rule_object.end()) {
      if (!allow->second.is_bool()) {
        result.code = Code::kPolicyDenied;
        result.message = path + ".allow must be a boolean";
        return result;
      }
      rule.allow = allow->second.as_bool();
    }

    if (!read_number_field(rule_object, "min_target", path, rule.min_target, result.code,
                           result.message) ||
        !read_number_field(rule_object, "max_target", path, rule.max_target, result.code,
                           result.message) ||
        !read_number_field(rule_object, "min_minimum", path, rule.min_minimum, result.code,
                           result.message) ||
        !read_number_field(rule_object, "max_minimum", path, rule.max_minimum, result.code,
                           result.message)) {
      return result;
    }

    std::string minimum_strength_token;
    std::string maximum_strength_token;
    if (!read_string_field(rule_object, "minimum_strength", path, 32, false, minimum_strength_token,
                           result.code, result.message) ||
        !read_string_field(rule_object, "maximum_strength", path, 32, false, maximum_strength_token,
                           result.code, result.message)) {
      return result;
    }
    if (!minimum_strength_token.empty()) {
      const std::optional<RequirementStrength> parsed = parse_requirement_strength(minimum_strength_token);
      if (!parsed.has_value()) {
        result.code = Code::kInvalidStrength;
        result.message = path + ".minimum_strength is not a strength token";
        return result;
      }
      rule.minimum_strength = *parsed;
    }
    if (!maximum_strength_token.empty()) {
      const std::optional<RequirementStrength> parsed = parse_requirement_strength(maximum_strength_token);
      if (!parsed.has_value()) {
        result.code = Code::kInvalidStrength;
        result.message = path + ".maximum_strength is not a strength token";
        return result;
      }
      rule.maximum_strength = *parsed;
    }

    const auto allowed_values = rule_object.find("allowed_values");
    if (allowed_values != rule_object.end()) {
      if (!allowed_values->second.is_array()) {
        result.code = Code::kPolicyDenied;
        result.message = path + ".allowed_values must be an array";
        return result;
      }
      if (allowed_values->second.size() > kMaxAllowedValues) {
        result.code = Code::kTooManyAttributes;
        result.message = path + ".allowed_values exceeds its bound";
        return result;
      }
      for (std::size_t v = 0; v < allowed_values->second.size(); ++v) {
        const Json* entry = allowed_values->second.at(v);
        if (entry == nullptr || !entry->is_string()) {
          result.code = Code::kPolicyDenied;
          result.message = path + ".allowed_values entries must be strings";
          return result;
        }
        rule.allowed_values.push_back(entry->as_string());
      }
    }
    policy.rules.push_back(std::move(rule));
  }

  const Digest digest = policy_digest(policy);
  policy.policy_id = derive_policy_id(digest);
  if (!policy_id.empty()) {
    const std::optional<PolicyId> declared = PolicyId::parse(policy_id);
    if (!declared.has_value() || *declared != policy.policy_id) {
      result.code = Code::kContractDigestMismatch;
      result.message = "policy_id does not match the canonical policy bytes";
      return result;
    }
  }
  result.ok = true;
  result.policy = std::move(policy);
  return result;
}

PolicyDecodeResult policy_from_text(std::string_view text) {
  JsonDecodeResult decoded = json_decode(text);
  if (!decoded.ok) {
    PolicyDecodeResult failure;
    failure.code = decoded.code;
    failure.message = decoded.message;
    return failure;
  }
  return policy_from_json(decoded.value);
}

PolicyValidationResult validate_policy(const Policy& policy) {
  PolicyValidationResult result;
  if (policy.schema_version == 0) {
    result.diagnostics.add(Code::kPolicyDenied, "policy schema_version must be at least 1");
  }
  if (policy.generation.is_zero()) {
    result.diagnostics.add(Code::kZeroIdentity, "policy generation must be at least 1");
  }
  for (std::size_t i = 0; i < policy.rules.size(); ++i) {
    const PolicyRule& rule = policy.rules[i];
    const std::string path = rule_path(i);
    if (rule.max_target < rule.min_target) {
      result.diagnostics.add(Code::kPolicyDenied, path + " max_target is below min_target");
    }
    if (rule.max_minimum < rule.min_minimum) {
      result.diagnostics.add(Code::kPolicyDenied, path + " max_minimum is below min_minimum");
    }
    if (rule.maximum_strength < rule.minimum_strength) {
      result.diagnostics.add(Code::kPolicyDenied, path + " maximum_strength is below minimum_strength");
    }
    if (rule.kind == RequirementKind::kAttribute && rule.key.empty()) {
      result.diagnostics.add(Code::kPolicyDenied,
                             path + " must name the attribute key it constrains");
    }
    if (!rule.allow && (!rule.allowed_values.empty())) {
      result.diagnostics.add(Code::kPolicyDenied, path + " forbids the kind and lists allowed values");
    }
  }
  result.ok = !result.diagnostics.has_errors();
  return result;
}

namespace {

// True when the rule applies to the requirement. An empty scope or key in a
// rule matches any value.
bool rule_applies(const PolicyRule& rule, const Requirement& requirement) {
  if (rule.kind != requirement.kind) {
    return false;
  }
  if (!rule.scope.empty() && rule.scope != requirement.scope) {
    return false;
  }
  if (!rule.key.empty() && rule.key != requirement.key) {
    return false;
  }
  return true;
}

bool value_allowed(const PolicyRule& rule, const std::string& value) {
  if (rule.allowed_values.empty()) {
    return true;
  }
  return std::find(rule.allowed_values.begin(), rule.allowed_values.end(), value) !=
         rule.allowed_values.end();
}

}  // namespace

PolicyValidationResult check_contract_against_policy(const Policy& policy, const ContractBody& body) {
  PolicyValidationResult result;
  if (policy.rules.empty()) {
    // An empty policy constrains nothing; it does not silently allow everything
    // either. The distinction is recorded in the diagnostics of an install.
    return result;
  }

  for (const Requirement& requirement : body.requirements) {
    bool matched = false;
    for (const PolicyRule& rule : policy.rules) {
      if (!rule_applies(rule, requirement)) {
        continue;
      }
      matched = true;
      if (!rule.allow) {
        result.diagnostics.add(
            Code::kPolicyDenied,
            "requirement kind " + std::string(requirement_kind_token(requirement.kind)) +
                " is not permitted in this scope",
            ScopeId{}, requirement.id);
        continue;
      }
      if (requirement.strength < rule.minimum_strength) {
        result.diagnostics.add(Code::kPolicyDenied,
                               std::string("requirement strength ") +
                                   std::string(requirement_strength_token(requirement.strength)) +
                                   " is below the policy floor " +
                                   std::string(requirement_strength_token(rule.minimum_strength)),
                               ScopeId{}, requirement.id);
      }
      if (requirement.strength > rule.maximum_strength) {
        result.diagnostics.add(Code::kPolicyDenied,
                               std::string("requirement strength ") +
                                   std::string(requirement_strength_token(requirement.strength)) +
                                   " is above the policy ceiling " +
                                   std::string(requirement_strength_token(rule.maximum_strength)),
                               ScopeId{}, requirement.id);
      }
      if (requirement.has_numeric) {
        if (requirement.target < rule.min_target || requirement.target > rule.max_target) {
          result.diagnostics.add(Code::kPolicyDenied,
                                 "requirement target is outside the permitted range",
                                 ScopeId{}, requirement.id);
        }
        if (requirement.minimum < rule.min_minimum || requirement.minimum > rule.max_minimum) {
          result.diagnostics.add(Code::kPolicyDenied,
                                 "requirement minimum is outside the permitted range",
                                 ScopeId{}, requirement.id);
        }
      }
      if (!value_allowed(rule, requirement.value)) {
        result.diagnostics.add(Code::kPolicyDenied,
                               "requirement value '" + requirement.value +
                                   "' is not permitted by the policy",
                               ScopeId{}, requirement.id);
      }
      for (const auto& attribute : requirement.attributes) {
        if (!value_allowed(rule, attribute.second)) {
          result.diagnostics.add(Code::kPolicyDenied,
                                 "attribute '" + attribute.first +
                                     "' is not permitted by the policy",
                                 ScopeId{}, requirement.id);
        }
      }
    }
    if (!matched) {
      // Requirements with no matching rule are permitted; the policy states
      // constraints, not an allow list. This is recorded so that a reader can
      // see which requirements were unconstrained.
      result.diagnostics.add(Code::kOk,
                             "requirement is not constrained by any policy rule", ScopeId{},
                             requirement.id);
    }
  }
  result.ok = !result.diagnostics.has_errors();
  return result;
}

// ---------------------------------------------------------------------------
// Compatibility
// ---------------------------------------------------------------------------

CompatibilityResult check_compatibility(const ContractBody& previous, const ContractBody& next) {
  CompatibilityResult result;

  if (previous.major != next.major) {
    result.diagnostics.add(Code::kIncompatibleMajor,
                           "major version changed from " + std::to_string(previous.major) + " to " +
                               std::to_string(next.major));
  }
  if (previous.workload.id != next.workload.id) {
    result.diagnostics.add(Code::kIncompatibleKindChanged,
                           "compatibility is only defined within one workload identity");
  }
  if (next.generation.value <= previous.generation.value) {
    result.diagnostics.add(Code::kStaleGeneration,
                           "candidate generation is not ahead of the previous generation");
  }

  std::map<RequirementKey, const Requirement*> next_keys;
  for (const Requirement& requirement : next.requirements) {
    next_keys.emplace(requirement.composite_key(), &requirement);
  }
  std::map<std::string_view, const Scope*> next_scopes;
  for (const Scope& scope : next.scopes) {
    next_scopes.emplace(scope.name, &scope);
  }

  for (const Requirement& requirement : previous.requirements) {
    const auto match = next_keys.find(requirement.composite_key());
    if (match == next_keys.end()) {
      if (requirement.strength == RequirementStrength::kRequired) {
        result.diagnostics.add(Code::kIncompatibleRequirementRemoved,
                               "required requirement of kind " +
                                   std::string(requirement_kind_token(requirement.kind)) +
                                   " in scope '" + requirement.scope + "' was removed",
                               ScopeId{}, requirement.id);
      } else if (next_scopes.find(requirement.scope) == next_scopes.end()) {
        result.diagnostics.add(Code::kIncompatibleScopeRemoved,
                               "scope '" + requirement.scope + "' was removed", ScopeId{},
                               requirement.id);
      }
      continue;
    }
    const Requirement& candidate = *match->second;
    if (candidate.strength < requirement.strength) {
      result.diagnostics.add(
          Code::kIncompatibleRequirementWeakened,
          std::string("requirement strength fell from ") +
              std::string(requirement_strength_token(requirement.strength)) + " to " +
              std::string(requirement_strength_token(candidate.strength)),
          ScopeId{}, requirement.id);
    }
    if (requirement.has_numeric && candidate.has_numeric) {
      // Weakness is kind relative. For a floor kind a fall in either bound is a
      // weakening; for a ceiling kind a rise in either bound is a weakening.
      const bool floor = kind_is_floor(requirement.kind);
      const auto weakened = [floor](double before, double after) {
        return floor ? after < before : after > before;
      };
      const auto bound_name = [floor](bool strict) {
        if (strict) {
          return floor ? "target" : "target";
        }
        return "minimum";
      };
      if (weakened(requirement.minimum, candidate.minimum)) {
        result.diagnostics.add(Code::kIncompatibleRequirementWeakened,
                               std::string("requirement weakest bound (") +
                                   bound_name(false) + ") moved from " +
                                   std::to_string(requirement.minimum) + " to " +
                                   std::to_string(candidate.minimum),
                               ScopeId{}, requirement.id);
      }
      if (weakened(requirement.target, candidate.target)) {
        result.diagnostics.add(Code::kIncompatibleRequirementWeakened,
                               std::string("requirement strict bound (") + bound_name(true) +
                                   ") moved from " + std::to_string(requirement.target) + " to " +
                                   std::to_string(candidate.target),
                               ScopeId{}, requirement.id);
      }
    } else if (requirement.has_numeric != candidate.has_numeric) {
      result.diagnostics.add(Code::kIncompatibleKindChanged,
                             "requirement changed between numeric and textual form", ScopeId{},
                             requirement.id);
    } else if (requirement.strength == RequirementStrength::kRequired &&
               (requirement.value != candidate.value ||
                requirement.preferred_value != candidate.preferred_value)) {
      result.diagnostics.add(Code::kIncompatibleKindChanged,
                             "required requirement value changed from '" + requirement.value +
                                 "' to '" + candidate.value + "'",
                             ScopeId{}, requirement.id);
    }
  }

  if (result.diagnostics.has_errors()) {
    result.verdict = CompatibilityVerdict::kIncompatible;
    return result;
  }

  // Additions are compatible.
  bool added = next.requirements.size() > previous.requirements.size();
  for (const Requirement& requirement : next.requirements) {
    bool found = false;
    for (const Requirement& old : previous.requirements) {
      if (old.composite_key() == requirement.composite_key()) {
        found = true;
        break;
      }
    }
    if (!found) {
      added = true;
      break;
    }
  }
  result.verdict = added ? CompatibilityVerdict::kCompatibleWithAdditions
                         : CompatibilityVerdict::kCompatible;
  return result;
}

}  // namespace wnc
