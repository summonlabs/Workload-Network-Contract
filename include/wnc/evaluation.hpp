// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Satisfaction evaluation against supplied evidence.
//
// Evidence is supplied by the systems that own topology, capacity, and
// capability. This boundary never observes the network itself, so an absent
// dimension is UNKNOWN, and UNKNOWN is never reported as SATISFIED. Every
// verdict carries the evidence generation it was decided from and the exact
// reason it was reached.

#ifndef WNC_EVALUATION_HPP
#define WNC_EVALUATION_HPP

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

// A capability or capacity observation for one scope. Every field is optional:
// an absent field means "not supplied", which evaluates to UNKNOWN, and never
// to satisfied.
struct Candidate {
  std::optional<double> min_bandwidth;
  std::optional<double> max_latency;
  std::optional<double> max_jitter;
  std::optional<double> max_loss;
  std::optional<std::string> locality;
  std::optional<double> path_diversity;
  std::optional<double> failure_domain_separation;
  std::optional<std::string> security_class;
  std::optional<double> traffic_priority;
  std::optional<double> burst_allowance;
  std::optional<bool> collective_supported;
  std::optional<bool> checkpoint_isolation;
  std::optional<std::string> disaggregated_affinity;
  std::optional<std::string> maintenance_tolerance;
  std::vector<std::pair<std::string, std::string>> attributes;

  [[nodiscard]] const std::string* attribute(std::string_view name) const;
  [[nodiscard]] bool has_any_dimension() const noexcept;
};

struct EvidenceEntry {
  std::string scope;
  EvidenceId id{};
  PublisherId publisher{};
  EvidenceGeneration generation{};
  // Coordinator incarnation that captured the entry. An entry captured by a
  // previous incarnation is never current, whatever its generation claims.
  Incarnation captured_by{};
  std::uint64_t epoch = 0;
  std::uint64_t produced_at_millis = 0;
  Candidate candidate;
  EvidenceFreshness freshness = EvidenceFreshness::kCurrent;
};

struct EvidenceSet {
  EvidenceId evidence_id{};
  EvidenceGeneration generation{};
  std::uint64_t epoch = 0;
  PublisherId publisher{};
  std::uint64_t produced_at_millis = 0;
  std::vector<EvidenceEntry> entries;

  [[nodiscard]] const EvidenceEntry* find(std::string_view scope) const;
  [[nodiscard]] bool all_current() const noexcept;
};

Digest evidence_digest(const EvidenceSet& evidence) noexcept;
EvidenceId derive_evidence_id(const Digest& digest) noexcept;

Json evidence_to_json(const EvidenceSet& evidence);

struct EvidenceDecodeResult {
  bool ok = false;
  EvidenceSet evidence;
  Code code = Code::kOk;
  std::string message;
};

EvidenceDecodeResult evidence_from_json(const Json& value);
EvidenceDecodeResult evidence_from_text(std::string_view text);

struct EvidenceValidationResult {
  bool ok = false;
  // Entries that are not current under this incarnation, in canonical order.
  std::vector<std::string> stale_scopes;
  DiagnosticLog diagnostics;
  [[nodiscard]] std::vector<std::string> reasons() const { return diagnostics.reasons(); }
};

// Validates an evidence set against a contract's declared scopes, the current
// coordinator incarnation, and the evidence generation floor. Entries captured
// by an earlier incarnation are marked stale and revalidation is required; they
// are never silently treated as current.
// The evidence set is taken by mutable reference because validation stamps each
// entry with the freshness it was found to have; a caller may only treat an
// entry as current when validation said so under the current incarnation.
EvidenceValidationResult validate_evidence(EvidenceSet& evidence, const ContractBody& body,
                                           const Incarnation& current, std::uint64_t now_millis,
                                           std::uint64_t max_age_millis);

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

struct RequirementEvaluation {
  RequirementId requirement{};
  std::string scope;
  RequirementKind kind = RequirementKind::kMinBandwidth;
  RequirementStrength strength = RequirementStrength::kRequired;
  Satisfaction satisfaction = Satisfaction::kUnknown;
  Code reason_code = Code::kEvaluationNoEvidence;
  std::string reason;
  // The evidence entry the verdict was decided from, when there was one.
  EvidenceId evidence{};
  EvidenceGeneration evidence_generation{};
  EvidenceFreshness freshness = EvidenceFreshness::kRevalidationRequired;
  std::optional<double> observed;
};

struct EvaluationSummary {
  std::size_t required_total = 0;
  std::size_t required_satisfied = 0;
  std::size_t required_unsatisfied = 0;
  std::size_t required_unknown = 0;
  std::size_t preferred_satisfied = 0;
  std::size_t preferred_unsatisfied = 0;
  std::size_t preferred_unknown = 0;
  std::size_t informational = 0;
  std::size_t not_applicable = 0;
};

struct ContractEvaluation {
  WorkloadId workload{};
  ContractId contract{};
  ContractGeneration contract_generation{};
  Digest contract_digest{};
  PolicyGeneration policy_generation{};
  EvidenceGeneration evidence_generation{};
  // The coordinator incarnation that produced this evaluation, and the epoch.
  Incarnation evaluated_by{};
  std::uint64_t epoch = 0;
  std::uint64_t evaluated_at_millis = 0;
  Satisfaction aggregate = Satisfaction::kUnknown;
  EvaluationSummary summary;
  std::vector<RequirementEvaluation> requirements;

  [[nodiscard]] const RequirementEvaluation* find(std::string_view scope,
                                                  RequirementKind kind) const;
};

struct EvaluationResult {
  bool ok = false;
  ContractEvaluation evaluation;
  Code code = Code::kOk;
  std::string message;
};

// Evaluates every requirement of a contract against an evidence set.
// The evaluation is a pure function of its inputs: the same contract, policy
// generation, evidence generation, and coordinator incarnation always produce
// the same verdicts.
EvaluationResult evaluate_contract(const Contract& contract, const EvidenceSet& evidence,
                                   const Incarnation& current, std::uint64_t now_millis,
                                   std::uint64_t max_age_millis);

// Satisfaction of a single requirement. Exposed so that property tests can
// check the decision table directly.
struct RequirementDecision {
  Satisfaction satisfaction = Satisfaction::kUnknown;
  Code reason_code = Code::kEvaluationNoEvidence;
  std::string reason;
  std::optional<double> observed;
};

RequirementDecision decide_requirement(const Requirement& requirement, const EvidenceEntry* entry,
                                       const Incarnation& current, std::uint64_t now_millis,
                                       std::uint64_t max_age_millis);

// Aggregate of a set of per requirement verdicts. Any unsatisfied REQUIRED
// requirement makes the aggregate unsatisfied; otherwise any unknown REQUIRED
// requirement makes it unknown; otherwise it is satisfied.
Satisfaction aggregate_satisfaction(const std::vector<RequirementEvaluation>& requirements);

}  // namespace wnc

#endif  // WNC_EVALUATION_HPP
