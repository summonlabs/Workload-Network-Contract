// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/composition.hpp"

#include <algorithm>
#include <array>
#include <map>

#include "wnc/hash.hpp"

namespace wnc {
namespace {

constexpr std::array<std::pair<CompositionDecisionKind, std::string_view>, 5> kDecisionTokens = {{
    {CompositionDecisionKind::kAdded, "added"},
    {CompositionDecisionKind::kStrengthened, "strengthened"},
    {CompositionDecisionKind::kKept, "kept"},
    {CompositionDecisionKind::kConflict, "conflict"},
    {CompositionDecisionKind::kRejected, "rejected"},
}};

std::string requirement_label(const Requirement& requirement) {
  return std::string(requirement_kind_token(requirement.kind)) + "/" + requirement.key +
         " in scope '" + requirement.scope + "'";
}

// True when the two requirements state exactly the same constraint.
bool same_constraint(const Requirement& a, const Requirement& b) noexcept {
  if (a.has_numeric != b.has_numeric) {
    return false;
  }
  if (!a.has_numeric) {
    return a.value == b.value && a.preferred_value == b.preferred_value;
  }
  return a.target == b.target && a.minimum == b.minimum;
}

}  // namespace

std::string_view composition_decision_token(CompositionDecisionKind kind) noexcept {
  for (const auto& entry : kDecisionTokens) {
    if (entry.first == kind) {
      return entry.second;
    }
  }
  return kDecisionTokens.front().second;
}

int compare_requirement_strength(const Requirement& a, const Requirement& b) noexcept {
  // A stronger strength always wins.
  if (a.strength != b.strength) {
    return static_cast<int>(a.strength) > static_cast<int>(b.strength) ? 1 : -1;
  }

  if (a.has_numeric && b.has_numeric) {
    const bool floor = kind_is_floor(a.kind);
    // For a floor kind higher is stronger, so the requirement that dominates in
    // both bounds is the stronger one. If each dominates in one bound they are
    // incomparable and the caller reports a conflict.
    const bool a_dominates =
        floor ? (a.target >= b.target && a.minimum >= b.minimum)
              : (a.target <= b.target && a.minimum <= b.minimum);
    const bool b_dominates =
        floor ? (b.target >= a.target && b.minimum >= a.minimum)
              : (b.target <= a.target && b.minimum <= a.minimum);
    if (a_dominates && !b_dominates) {
      return 1;
    }
    if (b_dominates && !a_dominates) {
      return -1;
    }
    if (a_dominates && b_dominates) {
      return 1;  // identical bands; either states the same constraint
    }
    return 0;
  }

  if (!a.has_numeric && !b.has_numeric) {
    // Two textual requirements of the same kind are comparable only when they
    // state the same value; distinct values are incomparable and therefore a
    // conflict rather than a silent choice.
    return same_constraint(a, b) ? 1 : 0;
  }

  return 0;
}

std::string describe_requirement_conflict(const Requirement& a, const Requirement& b) {
  if (same_constraint(a, b)) {
    return {};
  }
  std::string out = "requirements disagree on " + requirement_label(a) + ": ";
  if (a.has_numeric && b.has_numeric) {
    out += "target " + std::to_string(a.target) + " versus " + std::to_string(b.target) +
           ", minimum " + std::to_string(a.minimum) + " versus " + std::to_string(b.minimum);
  } else {
    out += "value '" + a.value + "' versus '" + b.value + "'";
  }
  return out;
}

CompositionResult compose(const ContractBody& base, const std::vector<OverlayLayer>& layers,
                          std::size_t max_layers) {
  CompositionResult result;
  if (layers.size() > max_layers) {
    result.code = Code::kTooManyLayers;
    result.message = "composition received " + std::to_string(layers.size()) +
                     " layers, above the bound " + std::to_string(max_layers);
    result.diagnostics.add(Code::kTooManyLayers, result.message);
    return result;
  }

  ContractBody composed = base;
  std::map<RequirementKey, std::size_t> index;
  for (std::size_t i = 0; i < composed.requirements.size(); ++i) {
    const auto inserted = index.emplace(composed.requirements[i].composite_key(), i);
    if (!inserted.second) {
      result.code = Code::kDuplicateRequirement;
      result.message = "the base contract repeats a requirement key";
      result.diagnostics.add(Code::kDuplicateRequirement, result.message);
      return result;
    }
  }

  for (const OverlayLayer& layer : layers) {
    if (layer.name.empty()) {
      result.code = Code::kOverlayInvalid;
      result.message = "a composition layer must be named";
      result.diagnostics.add(Code::kOverlayInvalid, result.message);
      return result;
    }

    // Scopes are added when they are new. A layer never redefines an existing
    // scope, because that would silently change the meaning of a requirement
    // that already refers to it.
    for (const Scope& scope : layer.scopes) {
      const bool exists =
          std::any_of(composed.scopes.begin(), composed.scopes.end(),
                      [&scope](const Scope& existing) { return existing.name == scope.name; });
      if (!exists) {
        composed.scopes.push_back(scope);
        result.decisions.push_back(CompositionDecision{CompositionDecisionKind::kAdded, layer.name,
                                                       scope.name, RequirementKind::kAttribute, "",
                                                       "scope '" + scope.name + "' added"});
      }
    }

    for (const Requirement& incoming : layer.requirements) {
      const RequirementKey key = incoming.composite_key();
      const auto found = index.find(key);
      if (found == index.end()) {
        composed.requirements.push_back(incoming);
        index.emplace(key, composed.requirements.size() - 1);
        result.decisions.push_back(CompositionDecision{CompositionDecisionKind::kAdded, layer.name,
                                                       incoming.scope, incoming.kind, incoming.key,
                                                       "requirement added by the layer"});
        continue;
      }

      Requirement& accumulated = composed.requirements[found->second];

      // A layer may never weaken what is already declared, neither in strength
      // nor in a bound. The check is explicit and comes before the ordering
      // comparison, so an incomparable band, which is also a weakening, is
      // reported as one rather than as a conflict.
      const bool weaker_strength =
          static_cast<int>(incoming.strength) < static_cast<int>(accumulated.strength);
      const int order = compare_requirement_strength(incoming, accumulated);
      if (weaker_strength || order < 0) {
        result.code = Code::kWeakeningDenied;
        result.message =
            "layer '" + layer.name + "' would weaken " + requirement_label(accumulated);
        result.diagnostics.add(Code::kWeakeningDenied, result.message, ScopeId{}, accumulated.id);
        result.decisions.push_back(CompositionDecision{CompositionDecisionKind::kRejected,
                                                       layer.name, incoming.scope, incoming.kind,
                                                       incoming.key, result.message});
        return result;
      }

      if (order > 0) {
        // The layer is strictly stronger, so it replaces the accumulated
        // requirement. Strengthening a requirement, including a REQUIRED one, is
        // exactly what an overlay is for.
        accumulated = incoming;
        result.decisions.push_back(CompositionDecision{CompositionDecisionKind::kStrengthened,
                                                       layer.name, incoming.scope, incoming.kind,
                                                       incoming.key,
                                                       "the layer's requirement is stronger"});
        continue;
      }

      // Neither dominates the other: an exact conflict, refused with both values.
      const std::string detail = describe_requirement_conflict(accumulated, incoming);
      result.code = Code::kCompositionConflict;
      result.message = "layer '" + layer.name + "' conflicts with the composed contract: " + detail;
      result.diagnostics.add(Code::kCompositionConflict, result.message, ScopeId{},
                             accumulated.id);
      result.decisions.push_back(CompositionDecision{CompositionDecisionKind::kConflict, layer.name,
                                                     incoming.scope, incoming.kind, incoming.key,
                                                     detail});
      return result;
    }
  }

  for (Requirement& requirement : composed.requirements) {
    std::sort(requirement.attributes.begin(), requirement.attributes.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    std::sort(requirement.members.begin(), requirement.members.end());
    requirement.id = derive_requirement_id(requirement);
  }
  std::sort(composed.scopes.begin(), composed.scopes.end(),
            [](const Scope& a, const Scope& b) { return a.name < b.name; });
  std::sort(composed.requirements.begin(), composed.requirements.end(), requirement_precedes);

  const Digest digest = body_digest(composed);
  composed.contract_id = derive_contract_id(composed.workload.id, digest);

  // A composed body is a candidate, not a publishable contract: it carries the
  // base's workload identity and generation, so validating it as a completed
  // contract would refuse every composition. What this function guarantees is
  // that the composition itself is well formed: something remains, no key is
  // repeated, and the ordering is canonical.
  if (composed.requirements.empty()) {
    result.code = Code::kEmptyRequirementSet;
    result.message = "the composed contract declares no requirements";
    result.diagnostics.add(Code::kEmptyRequirementSet, result.message);
    return result;
  }
  for (std::size_t i = 1; i < composed.requirements.size(); ++i) {
    if (composed.requirements[i].composite_key() == composed.requirements[i - 1].composite_key()) {
      result.code = Code::kCompositionConflict;
      result.message = "the composed contract repeats a requirement key";
      result.diagnostics.add(Code::kCompositionConflict, result.message);
      return result;
    }
  }

  result.ok = true;
  result.code = Code::kOk;
  result.message = "composed " + std::to_string(layers.size()) + " layers";
  result.body = std::move(composed);
  return result;
}

}  // namespace wnc
