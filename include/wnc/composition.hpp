// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Requirement inheritance and composition.
//
// A composition takes a base contract generation and a bounded, ordered list of
// overlay layers and produces one body. The rules are explicit and total:
//
//   * layers are applied in the order given; the order is part of the input and
//     the resulting digest, so two different orders are two different results;
//   * two layers that name the same requirement key are a conflict unless one
//     of them is strictly stronger, in which case the stronger one wins and the
//     decision is recorded in the report;
//   * an overlay may never weaken a REQUIRED requirement. An explicit weakening
//     is refused with the exact reason and the scope and requirement it applies
//     to, and a caller that wants to weaken a requirement must edit the base
//     contract generation instead, where the change is visible as a new digest;
//   * a layer may add scopes and requirements, and those additions are ordered
//     canonically before the digest is computed.

#ifndef WNC_COMPOSITION_HPP
#define WNC_COMPOSITION_HPP

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "wnc/contract.hpp"
#include "wnc/error.hpp"

namespace wnc {

struct OverlayLayer {
  std::string name;
  std::vector<Scope> scopes;
  std::vector<Requirement> requirements;
};

// One decision the composition made, in a stable order.
enum class CompositionDecisionKind : std::uint8_t {
  kAdded = 0,       // a requirement that only the layer declared
  kStrengthened = 1,  // the layer's requirement outranks the accumulated one
  kKept = 2,        // the accumulated requirement outranks the layer's
  kConflict = 3,    // the two are incomparable
  kRejected = 4,    // the composition refused the layer
};

std::string_view composition_decision_token(CompositionDecisionKind kind) noexcept;

struct CompositionDecision {
  CompositionDecisionKind kind = CompositionDecisionKind::kAdded;
  std::string layer;
  std::string scope;
  RequirementKind requirement_kind = RequirementKind::kMinBandwidth;
  std::string key;
  std::string reason;
};

struct CompositionResult {
  bool ok = false;
  Code code = Code::kOk;
  std::string message;
  ContractBody body;
  DiagnosticLog diagnostics;
  std::vector<CompositionDecision> decisions;

  [[nodiscard]] std::vector<std::string> reasons() const { return diagnostics.reasons(); }
};

// Composes a base body with overlay layers. The base is never modified; the
// result carries the base's workload identity, generation, and policy
// generation, and is canonicalised before it is returned.
CompositionResult compose(const ContractBody& base, const std::vector<OverlayLayer>& layers,
                          std::size_t max_layers = kMaxCompositionLayers);

// Total order used to decide which of two requirements of the same key is
// stronger. Returns 0 when they are incomparable (a conflict), a positive value
// when the first is stronger, and a negative value when the second is stronger.
int compare_requirement_strength(const Requirement& a, const Requirement& b) noexcept;

// Describes how two overlapping requirements disagree, for diagnostics. Returns
// an empty string when they do not disagree.
std::string describe_requirement_conflict(const Requirement& a, const Requirement& b);

}  // namespace wnc

#endif  // WNC_COMPOSITION_HPP
