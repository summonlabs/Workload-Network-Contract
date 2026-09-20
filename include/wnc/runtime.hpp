// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// The coordinator runtime: authoritative registration, generation assignment,
// satisfaction evaluation, and durable history.
//
// Authority rules enforced here:
//   * identities arrive from verified signatures, never from provenance fields;
//   * contract generations are assigned from the durability point and must be
//     strictly sequential, so a repeated submission is refused as a replay;
//   * evidence captured by an earlier incarnation is never current, so a
//     restart cannot resurrect freshness;
//   * a cache entry produced by an earlier incarnation is never served as a
//     decision; it returns UNKNOWN with revalidation required;
//   * an acknowledgement is only returned after the durability point.

#ifndef WNC_RUNTIME_HPP
#define WNC_RUNTIME_HPP

#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "wnc/contract.hpp"
#include "wnc/error.hpp"
#include "wnc/evaluation.hpp"
#include "wnc/ledger.hpp"
#include "wnc/policy.hpp"
#include "wnc/signature.hpp"

namespace wnc {

struct RuntimeInfo {
  CoordinatorId coordinator{};
  Incarnation incarnation{};
  std::uint64_t epoch = 0;
  Digest trust_digest{};
  std::uint64_t started_at_millis = 0;
  bool recovered = false;
  std::uint64_t recovered_records = 0;
  std::uint64_t truncated_bytes = 0;
};

struct PublishResult {
  bool ok = false;
  Code code = Code::kOk;
  std::string message;
  WorkloadId workload{};
  ContractId contract{};
  ContractGeneration generation{};
  Digest digest{};
  std::uint64_t sequence = 0;
};

struct RegisterResult {
  bool ok = false;
  Code code = Code::kOk;
  std::string message;
  WorkloadId workload{};
  WorkloadGeneration workload_generation{};
  ContractId contract{};
  ContractGeneration contract_generation{};
  Digest digest{};
  std::uint64_t sequence = 0;
};

struct AttachEvidenceResult {
  bool ok = false;
  Code code = Code::kOk;
  std::string message;
  EvidenceId evidence{};
  EvidenceGeneration generation{};
  std::uint64_t sequence = 0;
  std::size_t invalidated_evaluations = 0;
};

struct RuntimePolicyResult {
  bool ok = false;
  Code code = Code::kOk;
  std::string message;
  PolicyId policy{};
  PolicyGeneration generation{};
  std::uint64_t sequence = 0;
};

struct GenerationHistory {
  ContractGeneration generation;
  Digest digest{};
  ContractId contract_id{};
  std::uint64_t recorded_at_millis = 0;
  bool superseded = false;
  bool retired = false;
};

struct WorkloadSnapshot {
  WorkloadId id{};
  std::string name;
  WorkloadGeneration workload_generation;
  ContractGeneration contract_generation;
  Digest digest{};
  ContractId contract{};
  PolicyGeneration policy_generation;
  EvidenceGeneration evidence_generation;
  bool retired = false;
  std::vector<GenerationHistory> history;
};

struct RetireResult {
  bool ok = false;
  Code code = Code::kOk;
  std::string message;
  std::uint64_t sequence = 0;
};

// ---------------------------------------------------------------------------
// Durable state
// ---------------------------------------------------------------------------

struct GenerationRecord {
  ContractGeneration generation;
  Digest digest{};
  ContractId contract_id{};
  Contract body;
  std::uint64_t recorded_at_millis = 0;
  bool superseded = false;
  bool retired = false;
};

struct StoredEvaluation {
  ContractEvaluation evaluation;
  // False once the decision has been invalidated by a later contract, policy,
  // evidence, or incarnation. An invalidated decision is persisted history and
  // is never served as a current decision.
  bool valid = false;
  std::string invalidation_reason;
};

struct WorkloadState {
  WorkloadId id{};
  std::string name;
  WorkloadGeneration workload_generation;
  ContractGeneration contract_generation;
  Digest digest{};
  ContractId contract{};
  PolicyGeneration policy_generation;
  EvidenceGeneration evidence_generation;
  bool retired = false;
  std::vector<GenerationRecord> generations;
  std::optional<EvidenceSet> evidence;
  std::optional<StoredEvaluation> evaluation;
};

struct RuntimeState {
  std::map<WorkloadId, WorkloadState> workloads;
  std::optional<Policy> policy;
  Digest policy_digest{};
  PolicyGeneration policy_generation;
  EvidenceGeneration evidence_floor;
  ContractGeneration contract_floor;
};

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

class Runtime {
 public:
  struct Options {
    std::filesystem::path state_directory;
    TrustSet trust;
    std::uint64_t evidence_max_age_millis = 0;  // 0 selects the default
    std::size_t max_sessions = 0;               // 0 selects the default
  };

  // Opens or creates durable state. Assigns a new epoch and incarnation, and
  // performs journal recovery, which reports a torn tail rather than hiding it.
  static std::optional<Runtime> open(const Options& options, Code& code, std::string& message);

  Runtime() = default;
  Runtime(Runtime&&) noexcept = default;
  Runtime& operator=(Runtime&&) noexcept = default;
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;
  ~Runtime();

  [[nodiscard]] const RuntimeInfo& info() const noexcept { return info_; }
  [[nodiscard]] const RuntimeState& state() const noexcept { return state_; }
  [[nodiscard]] const TrustSet& trust() const noexcept { return trust_; }
  [[nodiscard]] std::uint64_t evidence_max_age_millis() const noexcept {
    return evidence_max_age_millis_;
  }
  [[nodiscard]] std::uint64_t now_millis() const noexcept;

  // Registers the first contract generation for a workload.
  RegisterResult register_workload(const Contract& submitted);
  // Registers the next contract generation for an existing workload.
  PublishResult publish(const Contract& submitted);
  // Attaches evidence and invalidates dependent evaluations.
  AttachEvidenceResult attach_evidence(const EvidenceSet& evidence);
  // Installs or replaces the policy that constrains future generations.
  RuntimePolicyResult install_policy(const Policy& policy);
  // Marks a workload retired. Retired workloads accept no further generations
  // but retain their history and stay inspectable.
  RetireResult retire(WorkloadId workload);

  EvaluationResult evaluate(WorkloadId workload);
  EvaluationResult evaluate_with_evidence(WorkloadId workload, const EvidenceSet& evidence);

  std::optional<WorkloadSnapshot> snapshot(WorkloadId workload) const;
  std::optional<Contract> contract_at(WorkloadId workload, ContractGeneration generation) const;
  std::vector<WorkloadId> workloads() const;
  // Verifies that the journal and the derived index agree. Returns false and
  // reports the first disagreement.
  bool verify_history(Code& code, std::string& message) const;

 private:
  struct CommitOutcome {
    bool ok = false;
    Code code = Code::kOk;
    std::string message;
    std::uint64_t sequence = 0;
  };

  // plan -> validate -> prepare -> append -> flush -> commit -> publish
  CommitOutcome commit(ledger::RecordType type, const Json& payload);

  EvaluationResult evaluate_internal(const WorkloadState& workload, const EvidenceSet* supplied,
                                     bool allow_cached);

  RuntimeInfo info_{};
  RuntimeState state_{};
  TrustSet trust_{};
  ledger::Ledger ledger_{};
  std::uint64_t evidence_max_age_millis_ = 0;
};

}  // namespace wnc

#endif  // WNC_RUNTIME_HPP
