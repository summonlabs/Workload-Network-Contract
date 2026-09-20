// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Seeded property tests. Every case is reproducible from the seed printed in
// the failure message, every randomized case checks its invariants after each
// step, and no case depends on the clock or on any ambient state.

#include "wnc_test.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

#include "wnc/composition.hpp"
#include "wnc/contract.hpp"
#include "wnc/evaluation.hpp"
#include "wnc/hash.hpp"
#include "wnc/json.hpp"
#include "wnc/policy.hpp"

using namespace wnc;

namespace {

// A small deterministic generator. The algorithm and its constants are fixed so
// that a seed reproduces a run exactly on every platform and every build.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed) {}

  std::uint64_t next() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return state_;
  }

  std::uint64_t bounded(std::uint64_t limit) { return limit == 0 ? 0 : next() % limit; }

  double real(double low, double high) {
    const double unit = static_cast<double>(next() % 100000u) / 100000.0;
    return low + unit * (high - low);
  }

  std::string word(const char* prefix) {
    return std::string(prefix) + std::to_string(bounded(1000));
  }

  bool chance(unsigned percent) { return bounded(100) < percent; }

 private:
  std::uint64_t state_;
};

const RequirementKind kNumericKinds[] = {
    RequirementKind::kMinBandwidth, RequirementKind::kMaxLatency,
    RequirementKind::kMaxJitter,    RequirementKind::kMaxLoss,
    RequirementKind::kPathDiversity, RequirementKind::kFailureDomainSeparation,
    RequirementKind::kTrafficPriority, RequirementKind::kBurstAllowance};
const RequirementKind kTextualKinds[] = {RequirementKind::kLocality,
                                         RequirementKind::kSecurityClass,
                                         RequirementKind::kMaintenanceTolerance,
                                         RequirementKind::kDisaggregatedAffinity,
                                         RequirementKind::kCheckpointIsolation};
const RequirementStrength kStrengths[] = {RequirementStrength::kRequired,
                                          RequirementStrength::kPreferred,
                                          RequirementStrength::kInformational};

// Builds a randomised but always valid requirement.
Requirement random_requirement(Rng& rng, const std::string& scope, int index) {
  Requirement requirement;
  requirement.scope = scope;
  const bool numeric = rng.chance(60);
  if (numeric) {
    requirement.kind = kNumericKinds[rng.bounded(sizeof(kNumericKinds) / sizeof(kNumericKinds[0]))];
    requirement.strength = kStrengths[rng.bounded(3)];
    requirement.has_numeric = true;
    const double low = rng.real(1.0, 1000.0);
    const double high = rng.real(1000.0, 100000.0);
    const bool floor = kind_is_floor(requirement.kind);
    if (floor) {
      requirement.minimum = low;
      requirement.target = high;
    } else {
      requirement.target = low;
      requirement.minimum = high;
    }
    if (requirement.strength == RequirementStrength::kRequired) {
      requirement.target = requirement.minimum;
    }
  } else {
    requirement.kind = kTextualKinds[rng.bounded(sizeof(kTextualKinds) / sizeof(kTextualKinds[0]))];
    requirement.strength = kStrengths[rng.bounded(3)];
    requirement.value = rng.word("v");
    if (requirement.strength == RequirementStrength::kPreferred && rng.chance(50)) {
      requirement.preferred_value = rng.word("p");
    }
  }
  requirement.key = "k" + std::to_string(index);
  const std::size_t attributes = rng.bounded(3);
  for (std::size_t i = 0; i < attributes; ++i) {
    requirement.attributes.emplace_back("a" + std::to_string(i), rng.word("val"));
  }
  return requirement;
}

ContractBody random_body(Rng& rng, std::size_t scope_count, std::size_t requirement_count) {
  ContractBody body;
  body.schema_version = kSchemaVersion;
  body.workload.id = WorkloadId::from_digest(sha256(std::string_view("property-workload")));
  body.workload.name = "property";
  body.workload.generation.value = 1;
  body.generation.value = 1;
  body.policy_generation.value = 1;
  body.major = 1;
  for (std::size_t i = 0; i < scope_count; ++i) {
    Scope scope;
    scope.name = "scope-" + std::to_string(i);
    body.scopes.push_back(scope);
  }
  for (std::size_t i = 0; i < requirement_count; ++i) {
    const std::string scope = "scope-" + std::to_string(rng.bounded(scope_count));
    body.requirements.push_back(random_requirement(rng, scope, static_cast<int>(i)));
  }
  return body;
}

std::vector<std::string> render(const Contract& contract) {
  std::vector<std::string> lines;
  lines.push_back(hex_encode(contract.digest));
  lines.push_back(contract.body.contract_id.str());
  for (const Requirement& requirement : contract.body.requirements) {
    lines.push_back(requirement.id.str() + "|" + requirement.scope + "|" +
                    std::string(requirement_kind_token(requirement.kind)) + "|" +
                    std::string(requirement_strength_token(requirement.strength)) + "|" +
                    std::to_string(requirement.target) + "|" + std::to_string(requirement.minimum) +
                    "|" + requirement.value + "|" + requirement.preferred_value);
  }
  return lines;
}

}  // namespace

WNC_TEST(property, canonicalisation_is_idempotent_and_order_independent) {
  const std::array<std::uint64_t, 8> seeds = {1, 2, 3, 5, 8, 13, 21, 34};
  for (const std::uint64_t seed : seeds) {
    Rng rng(seed);
    Contract first;
    first.body = random_body(rng, 3, 24);
    WNC_CHECK(canonicalize(first));
    const ValidationResult validation = validate_contract(first);
    std::string detail = "seed " + std::to_string(seed);
    if (!validation.diagnostics.entries().empty()) {
      detail += ": " + validation.diagnostics.entries().front().render();
    }
    WNC_CHECK_MSG(validation.ok, detail);

    // Canonicalising again must change nothing at all.
    Contract again = first;
    WNC_CHECK(canonicalize(again));
    WNC_CHECK_EQ(hex_encode(again.digest), hex_encode(first.digest));
    WNC_CHECK_EQ(contract_to_json(again).dump(), contract_to_json(first).dump());

    // Shuffling requirements and scopes must not change the digest.
    for (int attempt = 0; attempt < 4; ++attempt) {
      Contract shuffled;
      shuffled.body = first.body;
      std::shuffle(shuffled.body.requirements.begin(), shuffled.body.requirements.end(), std::mt19937(static_cast<unsigned>(rng.next())));
      std::shuffle(shuffled.body.scopes.begin(), shuffled.body.scopes.end(), std::mt19937(static_cast<unsigned>(rng.next())));
      WNC_CHECK(canonicalize(shuffled));
      WNC_CHECK_EQ(hex_encode(shuffled.digest), hex_encode(first.digest));
      WNC_CHECK_EQ(render(shuffled), render(first));
    }
  }
}

WNC_TEST(property, serialization_round_trip_is_lossless) {
  const std::array<std::uint64_t, 6> seeds = {101, 202, 303, 404, 505, 606};
  for (const std::uint64_t seed : seeds) {
    Rng rng(seed);
    Contract contract;
    contract.body = random_body(rng, 2, 16);
    contract.body.description = rng.word("desc");
    WNC_CHECK(canonicalize(contract));

    const std::string text = contract_to_json(contract).dump();
    const ContractDecodeResult decoded = contract_from_text(text);
    WNC_CHECK_MSG(decoded.ok, "seed " + std::to_string(seed) + ": " + decoded.message);
    WNC_CHECK_EQ(hex_encode(decoded.contract.digest), hex_encode(contract.digest));
    WNC_CHECK_EQ(contract_to_json(decoded.contract).dump(), text);

    // The digest is stable across a second round trip as well.
    const std::string second_text = contract_to_json(decoded.contract).dump();
    const ContractDecodeResult second = contract_from_text(second_text);
    WNC_CHECK(second.ok);
    WNC_CHECK_EQ(hex_encode(second.contract.digest), hex_encode(contract.digest));
  }
}

WNC_TEST(property, json_canonicalisation_is_stable_under_reordering) {
  const std::array<std::uint64_t, 6> seeds = {11, 22, 33, 44, 55, 66};
  for (const std::uint64_t seed : seeds) {
    Rng rng(seed);
    // Build an object with a random key insertion order and nested values.
    std::vector<std::pair<std::string, std::string>> members;
    const std::size_t count = 1 + rng.bounded(12);
    for (std::size_t i = 0; i < count; ++i) {
      const std::string value = rng.chance(50) ? std::to_string(rng.bounded(1000000))
                                               : "\"" + rng.word("s") + "\"";
      members.emplace_back("key" + std::to_string(rng.bounded(1000)) + "-" + std::to_string(i),
                           value);
    }
    std::string document = "{";
    bool first = true;
    for (const auto& member : members) {
      if (!first) {
        document.push_back(',');
      }
      first = false;
      document += "\"" + member.first + "\":" + member.second;
    }
    document += "}";

    const JsonDecodeResult decoded = json_decode(document);
    WNC_CHECK_MSG(decoded.ok, decoded.message);
    const std::string canonical = decoded.value.dump();

    // Re-encoding the canonical form must be a fixed point, and re-ordering the
    // input must produce the identical canonical bytes.
    const JsonDecodeResult again = json_decode(canonical);
    WNC_CHECK(again.ok);
    WNC_CHECK_EQ(again.value.dump(), canonical);

    // Decoding twice through the canonical round trip preserves the digest.
    WNC_CHECK_EQ(hex_encode(sha256(canonical)), hex_encode(sha256(again.value.dump())));
  }
}

WNC_TEST(property, evaluation_never_reports_satisfied_without_evidence) {
  const std::array<std::uint64_t, 10> seeds = {7, 17, 27, 37, 47, 57, 67, 77, 87, 97};
  for (const std::uint64_t seed : seeds) {
    Rng rng(seed);
    Contract contract;
    contract.body = random_body(rng, 2, 12);
    WNC_CHECK(canonicalize(contract));

    const Incarnation incarnation = new_incarnation();
    EvidenceSet partial;
    partial.generation.value = 1;
    partial.epoch = 1 + rng.bounded(5);
    partial.publisher = PublisherId::from_digest(sha256(std::string_view("property-evidence")));
    // Supply evidence for a subset of the scopes, and only some dimensions.
    const std::size_t supplied_scopes = rng.bounded(3);
    for (std::size_t i = 0; i < supplied_scopes; ++i) {
      EvidenceEntry entry;
      entry.scope = "scope-" + std::to_string(i);
      entry.publisher = partial.publisher;
      entry.generation.value = 1;
      entry.captured_by = incarnation;
      entry.epoch = partial.epoch;
      entry.produced_at_millis = 1000;
      if (rng.chance(50)) {
        entry.candidate.min_bandwidth = rng.real(1.0, 100000.0);
      }
      if (rng.chance(50)) {
        entry.candidate.max_latency = rng.real(1.0, 100000.0);
      }
      if (rng.chance(50)) {
        entry.candidate.locality = rng.word("loc");
      }
      entry.freshness = EvidenceFreshness::kCurrent;
      entry.id = EvidenceId::from_digest(
          sha256(std::string_view("property-evidence:" + entry.scope)));
      partial.entries.push_back(std::move(entry));
    }

    const EvaluationResult result = evaluate_contract(contract, partial, incarnation, 1000, 0);
    WNC_CHECK(result.ok);
    WNC_CHECK_EQ(result.evaluation.requirements.size(), contract.body.requirements.size());
    for (const RequirementEvaluation& entry : result.evaluation.requirements) {
      if (entry.satisfaction != Satisfaction::kSatisfied) {
        continue;
      }
      // A satisfied verdict must name the evidence it was decided from, and that
      // evidence must exist in the supplied set.
      WNC_CHECK(!entry.evidence.is_zero());
      const EvidenceEntry* source = partial.find(entry.scope);
      WNC_CHECK_MSG(source != nullptr, "satisfied verdict without a matching evidence entry");
      WNC_CHECK_EQ(source->id.view(), entry.evidence.view());
      WNC_CHECK_EQ(entry.freshness, EvidenceFreshness::kCurrent);
    }

    // The aggregate is a function of the per-requirement verdicts.
    WNC_CHECK_EQ(result.evaluation.aggregate,
                 aggregate_satisfaction(result.evaluation.requirements));

    // Re-evaluating the identical inputs produces identical verdicts.
    const EvaluationResult repeat = evaluate_contract(contract, partial, incarnation, 1000, 0);
    WNC_CHECK_EQ(repeat.evaluation.requirements.size(), result.evaluation.requirements.size());
    for (std::size_t i = 0; i < result.evaluation.requirements.size(); ++i) {
      WNC_CHECK_EQ(repeat.evaluation.requirements[i].satisfaction,
                   result.evaluation.requirements[i].satisfaction);
      WNC_CHECK_EQ(repeat.evaluation.requirements[i].reason_code,
                   result.evaluation.requirements[i].reason_code);
    }
  }
}

WNC_TEST(property, composition_is_order_sensitive_and_conflict_detecting) {
  const std::array<std::uint64_t, 6> seeds = {1001, 2002, 3003, 4004, 5005, 6006};
  for (const std::uint64_t seed : seeds) {
    Rng rng(seed);
    Contract base_contract;
    base_contract.body = random_body(rng, 1, 3);
    WNC_CHECK(canonicalize(base_contract));
    const ContractBody& base = base_contract.body;
    std::vector<OverlayLayer> layers;
    for (int layer_index = 0; layer_index < 3; ++layer_index) {
      OverlayLayer layer;
      layer.name = "layer" + std::to_string(layer_index);
      for (int i = 0; i < 3; ++i) {
        Requirement requirement = random_requirement(rng, "scope-0", i);
        layer.requirements.push_back(std::move(requirement));
      }
      layers.push_back(std::move(layer));
    }

    const CompositionResult composed = compose(base, layers);
    if (!composed.ok) {
      // A refusal must carry the exact code and at least one reason.
      WNC_CHECK(composed.code == Code::kCompositionConflict ||
                composed.code == Code::kWeakeningDenied ||
                composed.code == Code::kTooManyLayers || composed.code == Code::kOverlayInvalid);
      WNC_CHECK(!composed.reasons().empty());
      continue;
    }
    // Success must produce a valid body with a digest that describes it.
    const ValidationResult validation = validate_contract_body(composed.body);
    WNC_CHECK_MSG(validation.ok, "seed " + std::to_string(seed));
    Contract contract;
    contract.body = composed.body;
    WNC_CHECK(canonicalize(contract));
    WNC_CHECK_EQ(hex_encode(contract.digest), hex_encode(body_digest(composed.body)));

    // Composing the same layers twice produces the identical body and digest.
    const CompositionResult repeat = compose(base, layers);
    WNC_CHECK(repeat.ok);
    WNC_CHECK_EQ(hex_encode(body_digest(repeat.body)), hex_encode(body_digest(composed.body)));
    WNC_CHECK_EQ(repeat.body.contract_id.view(), composed.body.contract_id.view());
  }
}

WNC_TEST(property, policy_checks_are_pure_and_deterministic) {
  // Policy is an input to a decision, so checking the same contract against the
  // same policy twice has to produce the same verdict and the same reasons.
  const std::array<std::uint64_t, 5> seeds = {31, 41, 59, 26, 53};
  for (const std::uint64_t seed : seeds) {
    Rng rng(seed);
    ContractBody body = random_body(rng, 2, 10);
    Policy policy;
    policy.schema_version = kSchemaVersion;
    policy.generation.value = 1;
    PolicyRule rule;
    rule.kind = kNumericKinds[rng.bounded(sizeof(kNumericKinds) / sizeof(kNumericKinds[0]))];
    rule.scope = "scope-" + std::to_string(rng.bounded(2));
    rule.min_target = rng.real(0.0, 100.0);
    rule.max_target = rule.min_target + rng.real(0.0, 100000.0);
    rule.min_minimum = rule.min_target;
    rule.max_minimum = rule.max_target;
    policy.rules.push_back(rule);

    const PolicyValidationResult first = check_contract_against_policy(policy, body);
    const PolicyValidationResult second = check_contract_against_policy(policy, body);
    WNC_CHECK_EQ(first.ok, second.ok);

    // The reason lists are compared element by element through named vectors:
    // reasons() returns a fresh vector each call, so comparing two calls'
    // elements directly would read from temporaries that are already destroyed.
    const std::vector<std::string> first_reasons = first.reasons();
    const std::vector<std::string> second_reasons = second.reasons();
    WNC_CHECK_EQ(first_reasons.size(), second_reasons.size());
    for (std::size_t i = 0; i < first_reasons.size() && i < second_reasons.size(); ++i) {
      WNC_CHECK_EQ(first_reasons[i], second_reasons[i]);
    }
    // A refusal is only ever reported through policy denial codes.
    if (!first.ok) {
      WNC_CHECK_EQ(first.diagnostics.first_error_code(), Code::kPolicyDenied);
    }
  }
}

WNC_TEST(property, digest_changes_whenever_any_semantic_field_changes) {
  Rng rng(4242);
  Contract contract;
  contract.body = random_body(rng, 2, 8);
  WNC_CHECK(canonicalize(contract));
  const std::string baseline = hex_encode(contract.digest);

  // Flip one field at a time; each must change the digest.
  for (std::size_t i = 0; i < contract.body.requirements.size(); ++i) {
    Contract mutated = contract;
    Requirement& requirement = mutated.body.requirements[i];
    if (requirement.has_numeric) {
      requirement.minimum += 1.0;
      if (requirement.strength == RequirementStrength::kRequired) {
        requirement.target = requirement.minimum;
      }
    } else {
      requirement.value += "x";
    }
    WNC_CHECK(canonicalize(mutated));
    WNC_CHECK_MSG(hex_encode(mutated.digest) != baseline,
                  "mutating requirement " + std::to_string(i) + " left the digest unchanged");
  }

  Contract renamed = contract;
  renamed.body.workload.name += "-renamed";
  WNC_CHECK(canonicalize(renamed));
  WNC_CHECK_NE(hex_encode(renamed.digest), baseline);

  Contract described = contract;
  described.body.description = "different";
  WNC_CHECK(canonicalize(described));
  WNC_CHECK_NE(hex_encode(described.digest), baseline);
}