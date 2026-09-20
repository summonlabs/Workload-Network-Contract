// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Satisfaction evaluation proof surface. The central rule under test is that an
// absent dimension is UNKNOWN and never SATISFIED.

#include "wnc_test.hpp"

#include <string>

#include "wnc/evaluation.hpp"
#include "wnc/hash.hpp"

using namespace wnc;

namespace {

constexpr std::uint64_t kNow = 1000000;

Contract make_contract(std::vector<Requirement> requirements) {
  Contract contract;
  contract.body.schema_version = kSchemaVersion;
  contract.body.workload.id = WorkloadId::from_digest(sha256(std::string_view("eval-workload")));
  contract.body.workload.name = "trainer";
  contract.body.workload.generation.value = 1;
  contract.body.generation.value = 1;
  contract.body.policy_generation.value = 1;
  contract.body.major = 1;
  Scope scope;
  scope.name = "fabric";
  contract.body.scopes.push_back(scope);
  contract.body.requirements = std::move(requirements);
  WNC_CHECK(canonicalize(contract));
  return contract;
}

Requirement numeric(RequirementKind kind, RequirementStrength strength, double target,
                    double minimum) {
  Requirement requirement;
  requirement.scope = "fabric";
  requirement.kind = kind;
  requirement.strength = strength;
  requirement.has_numeric = true;
  requirement.target = target;
  requirement.minimum = minimum;
  return requirement;
}

Requirement textual(RequirementKind kind, RequirementStrength strength, std::string value) {
  Requirement requirement;
  requirement.scope = "fabric";
  requirement.kind = kind;
  requirement.strength = strength;
  requirement.value = std::move(value);
  return requirement;
}

EvidenceSet evidence_with(Incarnation incarnation, std::uint64_t epoch, const Candidate& candidate,
                          std::uint64_t produced_at = kNow) {
  EvidenceSet evidence;
  evidence.generation.value = 1;
  evidence.epoch = epoch;
  evidence.publisher = PublisherId::from_digest(sha256(std::string_view("evidence-publisher")));
  evidence.produced_at_millis = produced_at;
  EvidenceEntry entry;
  entry.scope = "fabric";
  entry.publisher = evidence.publisher;
  entry.generation.value = 1;
  entry.captured_by = incarnation;
  entry.epoch = epoch;
  entry.produced_at_millis = produced_at;
  entry.candidate = candidate;
  entry.freshness = EvidenceFreshness::kCurrent;
  evidence.entries.push_back(std::move(entry));
  evidence.evidence_id = derive_evidence_id(evidence_digest(evidence));
  return evidence;
}

}  // namespace

WNC_TEST(evaluation, missing_evidence_is_unknown_not_satisfied) {
  const Contract contract =
      make_contract({numeric(RequirementKind::kMinBandwidth, RequirementStrength::kRequired,
                             1000.0, 1000.0)});
  EvidenceSet empty;
  empty.generation.value = 1;
  empty.epoch = 5;
  const Incarnation incarnation = new_incarnation();

  const EvaluationResult result =
      evaluate_contract(contract, empty, incarnation, kNow, 60000);
  WNC_CHECK(result.ok);
  WNC_CHECK_EQ(result.evaluation.aggregate, Satisfaction::kUnknown);
  WNC_CHECK_EQ(result.evaluation.requirements.front().satisfaction, Satisfaction::kUnknown);
  WNC_CHECK_EQ(result.evaluation.requirements.front().reason_code, Code::kEvaluationNoEvidence);
}

WNC_TEST(evaluation, absent_dimension_is_unknown) {
  const Contract contract =
      make_contract({numeric(RequirementKind::kMaxLatency, RequirementStrength::kRequired, 100.0,
                             100.0)});
  const Incarnation incarnation = new_incarnation();
  Candidate candidate;
  candidate.min_bandwidth = 1000000.0;  // bandwidth supplied, latency not
  const EvidenceSet evidence = evidence_with(incarnation, 7, candidate);

  const EvaluationResult result = evaluate_contract(contract, evidence, incarnation, kNow, 0);
  WNC_CHECK(result.ok);
  WNC_CHECK_EQ(result.evaluation.requirements.front().satisfaction, Satisfaction::kUnknown);
  WNC_CHECK_EQ(result.evaluation.requirements.front().reason_code, Code::kEvaluationMissingDimension);
}

WNC_TEST(evaluation, floor_and_ceiling_decisions) {
  const Incarnation incarnation = new_incarnation();
  Candidate candidate;
  candidate.min_bandwidth = 5000.0;
  candidate.max_latency = 80.0;
  const EvidenceSet evidence = evidence_with(incarnation, 3, candidate);

  {
    const Contract contract = make_contract({numeric(RequirementKind::kMinBandwidth,
                                                     RequirementStrength::kRequired, 4000.0,
                                                     4000.0)});
    const EvaluationResult result = evaluate_contract(contract, evidence, incarnation, kNow, 0);
    WNC_CHECK_EQ(result.evaluation.aggregate, Satisfaction::kSatisfied);
    WNC_CHECK_EQ(result.evaluation.requirements.front().observed.value_or(0.0), 5000.0);
  }
  {
    const Contract contract = make_contract({numeric(RequirementKind::kMinBandwidth,
                                                     RequirementStrength::kRequired, 6000.0,
                                                     6000.0)});
    const EvaluationResult result = evaluate_contract(contract, evidence, incarnation, kNow, 0);
    WNC_CHECK_EQ(result.evaluation.aggregate, Satisfaction::kUnsatisfied);
  }
  {
    const Contract contract = make_contract({numeric(RequirementKind::kMaxLatency,
                                                     RequirementStrength::kRequired, 100.0,
                                                     100.0)});
    const EvaluationResult result = evaluate_contract(contract, evidence, incarnation, kNow, 0);
    WNC_CHECK_EQ(result.evaluation.aggregate, Satisfaction::kSatisfied);
  }
  {
    const Contract contract = make_contract({numeric(RequirementKind::kMaxLatency,
                                                     RequirementStrength::kRequired, 50.0, 50.0)});
    const EvaluationResult result = evaluate_contract(contract, evidence, incarnation, kNow, 0);
    WNC_CHECK_EQ(result.evaluation.aggregate, Satisfaction::kUnsatisfied);
  }
}

WNC_TEST(evaluation, preferred_band_is_satisfied_but_reported) {
  const Incarnation incarnation = new_incarnation();
  Candidate candidate;
  candidate.max_latency = 80.0;
  const EvidenceSet evidence = evidence_with(incarnation, 3, candidate);

  const Contract contract =
      make_contract({numeric(RequirementKind::kMaxLatency, RequirementStrength::kPreferred, 50.0,
                             100.0)});
  const EvaluationResult result = evaluate_contract(contract, evidence, incarnation, kNow, 0);
  WNC_CHECK_EQ(result.evaluation.aggregate, Satisfaction::kNotApplicable);
  const RequirementEvaluation& entry = result.evaluation.requirements.front();
  WNC_CHECK_EQ(entry.satisfaction, Satisfaction::kSatisfied);
  WNC_CHECK(entry.reason.find("preferred band") != std::string::npos);
}

WNC_TEST(evaluation, informational_is_not_applicable) {
  const Incarnation incarnation = new_incarnation();
  Candidate candidate;
  candidate.max_latency = 10.0;
  const EvidenceSet evidence = evidence_with(incarnation, 1, candidate);
  const Contract contract = make_contract({numeric(RequirementKind::kMaxLatency,
                                                   RequirementStrength::kInformational, 1.0, 1.0)});
  const EvaluationResult result = evaluate_contract(contract, evidence, incarnation, kNow, 0);
  WNC_CHECK_EQ(result.evaluation.requirements.front().satisfaction, Satisfaction::kNotApplicable);
  WNC_CHECK_EQ(result.evaluation.aggregate, Satisfaction::kNotApplicable);
}

WNC_TEST(evaluation, evidence_from_another_incarnation_requires_revalidation) {
  const Incarnation current = new_incarnation();
  const Incarnation previous = new_incarnation();
  Candidate candidate;
  candidate.min_bandwidth = 100000.0;
  const EvidenceSet evidence = evidence_with(previous, 4, candidate);

  const Contract contract = make_contract({numeric(RequirementKind::kMinBandwidth,
                                                   RequirementStrength::kRequired, 1000.0,
                                                   1000.0)});
  const EvaluationResult result = evaluate_contract(contract, evidence, current, kNow, 0);
  WNC_CHECK_EQ(result.evaluation.requirements.front().satisfaction, Satisfaction::kUnknown);
  WNC_CHECK_EQ(result.evaluation.requirements.front().reason_code, Code::kRevalidationRequired);
  WNC_CHECK_EQ(result.evaluation.aggregate, Satisfaction::kUnknown);
}

WNC_TEST(evaluation, old_evidence_expires) {
  const Incarnation incarnation = new_incarnation();
  Candidate candidate;
  candidate.min_bandwidth = 100000.0;
  const EvidenceSet evidence = evidence_with(incarnation, 4, candidate, kNow - 100000);

  EvidenceSet stamped = evidence;
  const Contract contract = make_contract({numeric(RequirementKind::kMinBandwidth,
                                                   RequirementStrength::kRequired, 1000.0,
                                                   1000.0)});
  const EvidenceValidationResult validated =
      validate_evidence(stamped, contract.body, incarnation, kNow, 1000);
  WNC_CHECK(validated.ok);
  WNC_CHECK_EQ(stamped.entries.front().freshness, EvidenceFreshness::kExpired);
  WNC_CHECK_EQ(validated.stale_scopes.size(), std::size_t(1));

  const EvaluationResult result = evaluate_contract(contract, stamped, incarnation, kNow, 1000);
  WNC_CHECK_EQ(result.evaluation.requirements.front().satisfaction, Satisfaction::kUnknown);
  WNC_CHECK_EQ(result.evaluation.requirements.front().reason_code, Code::kEvidenceExpired);
}

WNC_TEST(evaluation, textual_requirements_match_exactly) {
  const Incarnation incarnation = new_incarnation();
  Candidate candidate;
  candidate.locality = "zone-a";
  candidate.security_class = "macsec";
  const EvidenceSet evidence = evidence_with(incarnation, 2, candidate);

  const Contract satisfied = make_contract(
      {textual(RequirementKind::kLocality, RequirementStrength::kRequired, "zone-a")});
  const EvaluationResult matched = evaluate_contract(satisfied, evidence, incarnation, kNow, 0);
  WNC_CHECK(matched.ok);
  WNC_CHECK_EQ(matched.evaluation.requirements.front().satisfaction, Satisfaction::kSatisfied);

  const Contract unsatisfied = make_contract(
      {textual(RequirementKind::kLocality, RequirementStrength::kRequired, "zone-b")});
  const EvaluationResult mismatched =
      evaluate_contract(unsatisfied, evidence, incarnation, kNow, 0);
  WNC_CHECK(mismatched.ok);
  WNC_CHECK_EQ(mismatched.evaluation.requirements.front().satisfaction,
               Satisfaction::kUnsatisfied);
}

WNC_TEST(evaluation, attribute_requirements_use_evidence_attributes) {
  const Incarnation incarnation = new_incarnation();
  Candidate candidate;
  candidate.attributes.emplace_back("gpu-fabric", "nvlink4");
  const EvidenceSet evidence = evidence_with(incarnation, 2, candidate);

  Requirement requirement;
  requirement.scope = "fabric";
  requirement.kind = RequirementKind::kAttribute;
  requirement.strength = RequirementStrength::kRequired;
  requirement.key = "gpu-fabric";
  requirement.value = "nvlink4";
  const Contract contract = make_contract({requirement});
  const EvaluationResult matched = evaluate_contract(contract, evidence, incarnation, kNow, 0);
  WNC_CHECK(matched.ok);
  WNC_CHECK_EQ(matched.evaluation.requirements.front().satisfaction, Satisfaction::kSatisfied);

  Contract other = contract;
  other.body.requirements.front().value = "pcie5";
  WNC_CHECK(canonicalize(other));
  const EvaluationResult mismatched = evaluate_contract(other, evidence, incarnation, kNow, 0);
  WNC_CHECK(mismatched.ok);
  WNC_CHECK_EQ(mismatched.evaluation.requirements.front().satisfaction,
               Satisfaction::kUnsatisfied);
}

WNC_TEST(evaluation, collective_members_must_be_reported) {
  const Incarnation incarnation = new_incarnation();
  const RequirementId member_a = RequirementId::from_digest(sha256(std::string_view("member-a")));
  const RequirementId member_b = RequirementId::from_digest(sha256(std::string_view("member-b")));

  Requirement requirement;
  requirement.scope = "fabric";
  requirement.kind = RequirementKind::kCollective;
  requirement.strength = RequirementStrength::kRequired;
  requirement.value = "all-reduce";
  requirement.members = {member_a, member_b};
  const Contract contract = make_contract({requirement});

  Candidate partial;
  partial.collective_supported = true;
  partial.attributes.emplace_back("member." + member_a.str(), "present");
  const EvaluationResult first =
      evaluate_contract(contract, evidence_with(incarnation, 2, partial), incarnation, kNow, 0);
  WNC_CHECK_EQ(first.evaluation.requirements.front().satisfaction, Satisfaction::kUnknown);
  WNC_CHECK_EQ(first.evaluation.requirements.front().reason_code,
               Code::kEvaluationMissingDimension);

  Candidate complete = partial;
  complete.attributes.emplace_back("member." + member_b.str(), "present");
  const EvaluationResult second =
      evaluate_contract(contract, evidence_with(incarnation, 3, complete), incarnation, kNow, 0);
  WNC_CHECK_EQ(second.evaluation.requirements.front().satisfaction, Satisfaction::kSatisfied);

  Candidate absent;
  absent.collective_supported = true;
  absent.attributes.emplace_back("member." + member_a.str(), "absent");
  absent.attributes.emplace_back("member." + member_b.str(), "present");
  const EvaluationResult third =
      evaluate_contract(contract, evidence_with(incarnation, 4, absent), incarnation, kNow, 0);
  WNC_CHECK_EQ(third.evaluation.requirements.front().satisfaction, Satisfaction::kUnsatisfied);
}

WNC_TEST(evaluation, summary_counts_every_strength) {
  const Incarnation incarnation = new_incarnation();
  Candidate candidate;
  candidate.min_bandwidth = 100.0;
  candidate.max_latency = 10.0;
  const EvidenceSet evidence = evidence_with(incarnation, 1, candidate);

  const Contract contract = make_contract({
      numeric(RequirementKind::kMinBandwidth, RequirementStrength::kRequired, 50.0, 50.0),
      numeric(RequirementKind::kMaxLatency, RequirementStrength::kRequired, 5.0, 5.0),
      numeric(RequirementKind::kMaxJitter, RequirementStrength::kPreferred, 1.0, 2.0),
      numeric(RequirementKind::kMaxLoss, RequirementStrength::kInformational, 1.0, 1.0),
  });
  const EvaluationResult result = evaluate_contract(contract, evidence, incarnation, kNow, 0);
  WNC_CHECK_EQ(result.evaluation.summary.required_total, std::size_t(2));
  WNC_CHECK_EQ(result.evaluation.summary.required_satisfied, std::size_t(1));
  WNC_CHECK_EQ(result.evaluation.summary.required_unsatisfied, std::size_t(1));
  WNC_CHECK_EQ(result.evaluation.summary.preferred_unknown, std::size_t(1));
  WNC_CHECK_EQ(result.evaluation.summary.informational, std::size_t(1));
  WNC_CHECK_EQ(result.evaluation.aggregate, Satisfaction::kUnsatisfied);
}

WNC_TEST(evaluation, evaluation_is_deterministic_for_identical_inputs) {
  const Incarnation incarnation = new_incarnation();
  Candidate candidate;
  candidate.min_bandwidth = 999.0;
  candidate.max_latency = 42.0;
  candidate.locality = "rack";
  const EvidenceSet evidence = evidence_with(incarnation, 9, candidate);
  const Contract contract = make_contract({
      numeric(RequirementKind::kMinBandwidth, RequirementStrength::kRequired, 1000.0, 1000.0),
      textual(RequirementKind::kLocality, RequirementStrength::kRequired, "rack"),
  });

  std::string first;
  for (int i = 0; i < 4; ++i) {
    const EvaluationResult result = evaluate_contract(contract, evidence, incarnation, kNow, 0);
    std::string rendered;
    for (const RequirementEvaluation& entry : result.evaluation.requirements) {
      rendered += std::string(satisfaction_token(entry.satisfaction));
      rendered += std::string(code_token(entry.reason_code));
      rendered += entry.reason;
    }
    if (i == 0) {
      first = rendered;
    } else {
      WNC_CHECK_EQ(rendered, first);
    }
  }
}