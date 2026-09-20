// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// The coordinator runtime. Every mutation follows the same order:
//
//   plan -> validate authority -> prepare -> append (durability point) ->
//   flush -> commit in memory -> publish the authoritative result
//
// The acknowledgement returned to a caller is produced only after the journal
// append has been flushed, so an acknowledgement can never precede the
// durability point it claims.

#include "wnc/runtime.hpp"

#include <algorithm>
#include <array>

#include "wnc/hash.hpp"
#include "wnc/state.hpp"

namespace wnc {
namespace {

constexpr std::string_view kDomainRegistration = "wnc/v1/submission/registration";
constexpr std::string_view kDomainPublication = "wnc/v1/submission/publication";

std::string hex_of(const Digest& digest) { return hex_encode(digest); }

std::uint64_t effective_max_age(std::uint64_t configured) {
  return configured == 0 ? kDefaultEvidenceMaxAgeMillis : configured;
}

Json key_digest_payload(std::string_view domain, const Digest& digest) {
  Json out;
  out.set("domain", std::string(domain));
  out.set("digest", hex_of(digest));
  return out;
}

// The canonical bytes a publisher signature covers. The digest is taken over
// the canonical body, and the signature covers that digest bound to the domain,
// so a registration cannot be replayed as a publication.
std::string submission_bytes(const Contract& contract) {
  return contract_body_to_json(contract.body).dump();
}

// Converts the signature carried by a contract envelope into the form the
// verification helper expects. An unsigned envelope produces an empty signature,
// which verification refuses with kSignatureMissing.
SignatureBytes signature_of(const ContractEnvelope& envelope) {
  SignatureBytes out;
  out.algorithm = envelope.algorithm;
  out.key_id = envelope.key_id;
  out.bytes = envelope.signature;
  return out;
}

}  // namespace

Runtime::~Runtime() = default;

std::uint64_t Runtime::now_millis() const noexcept { return state::wall_millis(); }

std::optional<Runtime> Runtime::open(const Options& options, Code& code, std::string& message) {
  Runtime runtime;
  runtime.evidence_max_age_millis_ = effective_max_age(options.evidence_max_age_millis);
  runtime.trust_ = options.trust;

  if (options.state_directory.empty()) {
    code = Code::kStateUnavailable;
    message = "a state directory is required";
    return std::nullopt;
  }

  // The coordinator identity is derived from the trust root and the tool
  // identity, so two installations with different trust sets never share a
  // state directory by accident.
  const ToolId tool = tool_identity("wnc-coordinator");
  const std::string trust_hex = hex_of(runtime.trust_.digest());
  const std::array<std::string_view, 3> coordinator_parts = {
      std::string_view("wnc/v1/coordinator"), tool.view(), trust_hex};
  const CoordinatorId coordinator = CoordinatorId::from_digest(
      sha256_parts(std::span<const std::string_view>(coordinator_parts.data(), coordinator_parts.size())));

  ledger::RecoveryReport recovery;
  std::optional<ledger::Ledger> ledger =
      ledger::Ledger::open(options.state_directory, coordinator, runtime.trust_.digest(), recovery, code,
                           message);
  if (!ledger.has_value()) {
    return std::nullopt;
  }
  runtime.ledger_ = std::move(*ledger);

  runtime.info_.coordinator = coordinator;
  runtime.info_.incarnation = runtime.ledger_.head().incarnation;
  runtime.info_.epoch = runtime.ledger_.head().epoch;
  runtime.info_.trust_digest = runtime.trust_.digest();
  runtime.info_.started_at_millis = state::wall_millis();
  runtime.info_.recovered = recovery.recovered;
  runtime.info_.recovered_records = recovery.valid_records;
  runtime.info_.truncated_bytes = recovery.truncated_bytes;

  // Load the derived snapshot (never authority) and replay the journal above it.
  std::uint64_t snapshot_sequence = 0;
  {
    ledger::Ledger::Snapshot snapshot;
    bool present = false;
    if (!runtime.ledger_.read_snapshot(snapshot, present, code, message)) {
      return std::nullopt;
    }
    if (present) {
      const bool usable = snapshot.sequence <= runtime.ledger_.last_sequence();
      if (!usable) {
        // A snapshot ahead of the journal claims states the journal cannot back;
        // it is discarded and the directory is reported as needing recovery.
        code = Code::kRecoveryRequired;
        message = "snapshot is ahead of the durable journal sequence";
        return std::nullopt;
      }
      JsonDecodeResult decoded = json_decode(snapshot.payload, JsonDecodeOptions{});
      if (decoded.ok && decoded.value.is_object()) {
        snapshot_sequence = snapshot.sequence;
      } else {
        snapshot_sequence = 0;
      }
    }
  }

  std::vector<ledger::Record> records;
  ledger::RecoveryReport replay;
  if (!runtime.ledger_.read_after(snapshot_sequence, records, replay, code, message)) {
    return std::nullopt;
  }

  // Replay. The snapshot is materialised again by applying records in order; a
  // record that cannot be applied is a refusal to serve, never a silent skip.
  for (const ledger::Record& record : records) {
    JsonDecodeResult decoded = json_decode(record.payload, JsonDecodeOptions{});
    if (!decoded.ok || !decoded.value.is_object()) {
      code = Code::kLedgerCorrupt;
      message = "journal record " + std::to_string(record.sequence) +
                " does not hold a canonical JSON object";
      return std::nullopt;
    }
    const Json& payload = decoded.value;
    switch (record.type) {
      case ledger::RecordType::kGenesis:
        break;
      case ledger::RecordType::kWorkloadRegistered:
      case ledger::RecordType::kContractPublished: {
        const Json* contract_json = payload.find("contract");
        if (contract_json == nullptr) {
          code = Code::kLedgerCorrupt;
          message = "contract record has no contract body";
          return std::nullopt;
        }
        ContractDecodeResult contract = contract_from_json(*contract_json);
        if (!contract.ok) {
          code = Code::kLedgerCorrupt;
          message = "contract record cannot be decoded: " + contract.message;
          return std::nullopt;
        }
        WorkloadState& workload = runtime.state_.workloads[contract.contract.body.workload.id];
        workload.id = contract.contract.body.workload.id;
        workload.name = contract.contract.body.workload.name;
        workload.workload_generation = contract.contract.body.workload.generation;
        GenerationRecord generation;
        generation.generation = contract.contract.body.generation;
        generation.digest = contract.contract.digest;
        generation.contract_id = contract.contract.body.contract_id;
        generation.body = contract.contract;
        if (const Json* recorded = payload.find("recorded_at_millis");
            recorded != nullptr && recorded->is_int()) {
          generation.recorded_at_millis = static_cast<std::uint64_t>(recorded->as_int());
        }
        for (GenerationRecord& existing : workload.generations) {
          if (existing.generation.value < generation.generation.value) {
            existing.superseded = true;
          }
        }
        if (!workload.generations.empty() &&
            workload.generations.back().generation.value == generation.generation.value) {
          code = Code::kDuplicateWorkload;
          message = "journal repeats contract generation " +
                    std::to_string(generation.generation.value);
          return std::nullopt;
        }
        workload.contract_generation = generation.generation;
        workload.digest = generation.digest;
        workload.contract = generation.contract_id;
        workload.policy_generation = contract.contract.body.policy_generation;
        workload.generations.push_back(std::move(generation));
        break;
      }
      case ledger::RecordType::kWorkloadRetired: {
        const Json* workload_id = payload.find("workload");
        if (workload_id == nullptr || !workload_id->is_string()) {
          code = Code::kLedgerCorrupt;
          message = "retirement record has no workload identity";
          return std::nullopt;
        }
        const std::optional<WorkloadId> parsed = WorkloadId::parse(workload_id->as_string());
        if (!parsed.has_value()) {
          code = Code::kLedgerCorrupt;
          message = "retirement record names an invalid workload identity";
          return std::nullopt;
        }
        auto found = runtime.state_.workloads.find(*parsed);
        if (found == runtime.state_.workloads.end()) {
          code = Code::kLedgerCorrupt;
          message = "retirement record names an unknown workload";
          return std::nullopt;
        }
        found->second.retired = true;
        break;
      }
      case ledger::RecordType::kEvidenceAttached: {
        const Json* evidence_json = payload.find("evidence");
        if (evidence_json == nullptr) {
          code = Code::kLedgerCorrupt;
          message = "evidence record has no evidence body";
          return std::nullopt;
        }
        EvidenceDecodeResult evidence = evidence_from_json(*evidence_json);
        if (!evidence.ok) {
          code = Code::kLedgerCorrupt;
          message = "evidence record cannot be decoded: " + evidence.message;
          return std::nullopt;
        }
        // Restored evidence is never current: the incarnation that captured it
        // is gone, so every entry returns as revalidation-required.
        for (EvidenceEntry& entry : evidence.evidence.entries) {
          entry.freshness = EvidenceFreshness::kRevalidationRequired;
        }
        // The record is applied to every workload whose contract declares one of
        // the scopes the evidence covers. The evidence body itself is
        // authoritative for that, so the replay does not depend on a stored
        // workload list that could disagree with it.
        std::vector<WorkloadId> affected;
        for (const auto& entry : runtime.state_.workloads) {
          if (entry.second.generations.empty()) {
            continue;
          }
          const ContractBody& body = entry.second.generations.back().body.body;
          for (const EvidenceEntry& evidence_entry : evidence.evidence.entries) {
            const bool declares = std::any_of(
                body.scopes.begin(), body.scopes.end(), [&evidence_entry](const Scope& scope) {
                  return scope.name == evidence_entry.scope;
                });
            if (declares) {
              affected.push_back(entry.first);
              break;
            }
          }
        }
        if (affected.empty()) {
          break;
        }
        for (const WorkloadId& id : affected) {
          auto found = runtime.state_.workloads.find(id);
          if (found == runtime.state_.workloads.end()) {
            continue;
          }
          found->second.evidence = evidence.evidence;
          found->second.evidence_generation = evidence.evidence.generation;
          found->second.evaluation.reset();
        }
        if (evidence.evidence.generation.value > runtime.state_.evidence_floor.value) {
          runtime.state_.evidence_floor = evidence.evidence.generation;
        }
        break;
      }
      case ledger::RecordType::kPolicyInstalled: {
        const Json* policy_json = payload.find("policy");
        if (policy_json == nullptr) {
          code = Code::kLedgerCorrupt;
          message = "policy record has no policy body";
          return std::nullopt;
        }
        PolicyDecodeResult policy = policy_from_json(*policy_json);
        if (!policy.ok) {
          code = Code::kLedgerCorrupt;
          message = "policy record cannot be decoded: " + policy.message;
          return std::nullopt;
        }
        runtime.state_.policy = std::move(policy.policy);
        runtime.state_.policy_digest = policy_digest(*runtime.state_.policy);
        runtime.state_.policy_generation = runtime.state_.policy->generation;
        break;
      }
      case ledger::RecordType::kEvaluationRecorded: {
        const Json* workload_id = payload.find("workload");
        const Json* evaluation = payload.find("evaluation");
        if (workload_id == nullptr || !workload_id->is_string() || evaluation == nullptr) {
          code = Code::kLedgerCorrupt;
          message = "evaluation record is incomplete";
          return std::nullopt;
        }
        const std::optional<WorkloadId> parsed = WorkloadId::parse(workload_id->as_string());
        if (!parsed.has_value()) {
          code = Code::kLedgerCorrupt;
          message = "evaluation record names an invalid workload identity";
          return std::nullopt;
        }
        auto found = runtime.state_.workloads.find(*parsed);
        if (found == runtime.state_.workloads.end()) {
          code = Code::kLedgerCorrupt;
          message = "evaluation record names an unknown workload";
          return std::nullopt;
        }
        // An evaluation restored from durable state is history. It is never a
        // current decision, because the evidence it was decided from is no
        // longer current under this incarnation.
        StoredEvaluation stored;
        stored.valid = false;
        stored.invalidation_reason = "restored from durable history after a coordinator restart";
        if (found->second.evaluation.has_value()) {
          stored.evaluation = found->second.evaluation->evaluation;
        }
        found->second.evaluation = std::move(stored);
        break;
      }
      case ledger::RecordType::kUnknown:
      default:
        code = Code::kLedgerIncompatible;
        message = "journal record " + std::to_string(record.sequence) +
                  " has a record type this build does not define";
        return std::nullopt;
    }
  }

  // Clear derived decisions: they belong to an earlier incarnation.
  for (auto& entry : runtime.state_.workloads) {
    if (entry.second.evaluation.has_value()) {
      entry.second.evaluation->valid = false;
      if (entry.second.evaluation->invalidation_reason.empty()) {
        entry.second.evaluation->invalidation_reason =
            "the coordinator restarted; the decision must be recomputed";
      }
    }
  }

  code = Code::kOk;
  message.clear();
  return runtime;
}

Runtime::CommitOutcome Runtime::commit(ledger::RecordType type, const Json& payload) {
  CommitOutcome outcome;
  const std::string bytes = payload.dump();
  if (bytes.size() > kMaxRecordBytes) {
    outcome.code = Code::kLedgerOversized;
    outcome.message = "record payload exceeds the configured bound";
    return outcome;
  }
  std::uint64_t sequence = 0;
  if (!ledger_.append(type, bytes, sequence, outcome.code, outcome.message)) {
    return outcome;
  }
  outcome.ok = true;
  outcome.sequence = sequence;
  return outcome;
}

RegisterResult Runtime::register_workload(const Contract& submitted) {
  RegisterResult result;
  result.workload = submitted.body.workload.id;
  result.contract = submitted.body.contract_id;
  result.contract_generation = submitted.body.generation;
  result.digest = submitted.digest;

  // 1. Plan: structural validation of the submitted body.
  const ValidationResult validation = validate_contract(submitted);
  if (!validation.ok) {
    result.code = validation.diagnostics.first_error_code();
    result.message = "submitted contract is not valid";
    for (const std::string& reason : validation.reasons()) {
      result.message.append("; ").append(reason);
    }
    return result;
  }
  if (submitted.body.generation.value != 1) {
    result.code = Code::kGenerationGap;
    result.message = "the first registration of a workload must be generation 1";
    return result;
  }
  if (submitted.has_supersedes()) {
    result.code = Code::kStaleGeneration;
    result.message = "the first registration of a workload must not supersede anything";
    return result;
  }

  // 2. Authority: the signature is verified against the trust set, and the
  //    publisher identity comes from the key that signed, not from the body.
  const VerifyOutcome verified =
      verify_signature(trust_, submitted.envelope.publisher, std::string(kDomainRegistration),
                       submission_bytes(submitted), signature_of(submitted.envelope));
  if (!verified.ok) {
    result.code = verified.code;
    result.message = verified.message;
    return result;
  }

  // 3. Policy: the body must be permitted by the installed policy generation.
  if (state_.policy.has_value()) {
    if (submitted.body.policy_generation.value != state_.policy_generation.value) {
      result.code = Code::kUnknownPolicy;
      result.message = "submitted policy generation is not the installed generation";
      return result;
    }
    const PolicyValidationResult policy_check =
        check_contract_against_policy(*state_.policy, submitted.body);
    if (!policy_check.ok) {
      result.code = policy_check.diagnostics.first_error_code();
      result.message = "submitted contract violates the installed policy";
      for (const std::string& reason : policy_check.reasons()) {
        result.message.append("; ").append(reason);
      }
      return result;
    }
  }

  if (state_.workloads.find(submitted.body.workload.id) != state_.workloads.end()) {
    result.code = Code::kDuplicateWorkload;
    result.message = "workload already has a registered contract";
    return result;
  }

  // 4. Prepare the durable payload.
  Json payload;
  payload.set("workload", submitted.body.workload.id.str());
  payload.set("contract_generation", static_cast<std::int64_t>(submitted.body.generation.value));
  payload.set("digest", hex_of(submitted.digest));
  payload.set("publisher", submitted.envelope.publisher.str());
  payload.set("recorded_at_millis", static_cast<std::int64_t>(now_millis()));
  payload.set("contract", contract_to_json(submitted));
  payload.set("proof", key_digest_payload(kDomainRegistration, submitted.digest));

  // 5. Durability point.
  const CommitOutcome outcome = commit(ledger::RecordType::kWorkloadRegistered, payload);
  if (!outcome.ok) {
    result.code = outcome.code;
    result.message = outcome.message;
    return result;
  }

  // 6. Commit in memory and publish.
  WorkloadState workload;
  workload.id = submitted.body.workload.id;
  workload.name = submitted.body.workload.name;
  workload.workload_generation = submitted.body.workload.generation;
  workload.contract_generation = submitted.body.generation;
  workload.digest = submitted.digest;
  workload.contract = submitted.body.contract_id;
  workload.policy_generation = submitted.body.policy_generation;
  GenerationRecord generation;
  generation.generation = submitted.body.generation;
  generation.digest = submitted.digest;
  generation.contract_id = submitted.body.contract_id;
  generation.body = submitted;
  generation.recorded_at_millis = now_millis();
  workload.generations.push_back(std::move(generation));
  state_.workloads.emplace(workload.id, std::move(workload));

  result.ok = true;
  result.code = Code::kOk;
  result.message = "contract registered";
  result.workload_generation = submitted.body.workload.generation;
  result.contract_generation = submitted.body.generation;
  result.sequence = outcome.sequence;
  return result;
}

PublishResult Runtime::publish(const Contract& submitted) {
  PublishResult result;
  result.workload = submitted.body.workload.id;
  result.contract = submitted.body.contract_id;
  result.generation = submitted.body.generation;
  result.digest = submitted.digest;

  const ValidationResult validation = validate_contract(submitted);
  if (!validation.ok) {
    result.code = validation.diagnostics.first_error_code();
    result.message = "submitted contract is not valid";
    for (const std::string& reason : validation.reasons()) {
      result.message.append("; ").append(reason);
    }
    return result;
  }

  const auto found = state_.workloads.find(submitted.body.workload.id);
  if (found == state_.workloads.end()) {
    result.code = Code::kUnknownWorkload;
    result.message = "no contract is registered for that workload";
    return result;
  }
  const WorkloadState& current = found->second;
  if (current.retired) {
    result.code = Code::kContractRetired;
    result.message = "workload is retired and accepts no further generations";
    return result;
  }

  // Generation authority: the coordinator, not the publisher, decides which
  // generation is next. A repeated submission is refused as a replay rather
  // than silently re-applied.
  const std::uint64_t expected = current.contract_generation.value + 1;
  if (submitted.body.generation.value < expected) {
    result.code = Code::kReplayRejected;
    result.message = "generation " + std::to_string(submitted.body.generation.value) +
                     " was already applied; the next generation is " + std::to_string(expected);
    return result;
  }
  if (submitted.body.generation.value > expected) {
    result.code = Code::kGenerationGap;
    result.message = "generation " + std::to_string(submitted.body.generation.value) +
                     " skips past the next expected generation " + std::to_string(expected);
    return result;
  }
  if (!submitted.has_supersedes() || submitted.supersedes.value != current.contract_generation.value ||
      submitted.supersedes_digest != current.digest) {
    result.code = Code::kStaleGeneration;
    result.message = "a superseding contract must name the current generation and its digest";
    return result;
  }
  if (submitted.body.major != current.generations.back().body.body.major) {
    result.code = Code::kIncompatibleMajor;
    result.message = "a superseding contract must keep the major version";
    return result;
  }

  const VerifyOutcome verified =
      verify_signature(trust_, submitted.envelope.publisher, std::string(kDomainPublication),
                       submission_bytes(submitted), signature_of(submitted.envelope));
  if (!verified.ok) {
    result.code = verified.code;
    result.message = verified.message;
    return result;
  }
  if (current.generations.back().body.envelope.publisher != verified.publisher) {
    result.code = Code::kNotContractOwner;
    result.message = "only the publisher that owns the current generation may supersede it";
    return result;
  }

  if (state_.policy.has_value()) {
    if (submitted.body.policy_generation.value != state_.policy_generation.value) {
      result.code = Code::kUnknownPolicy;
      result.message = "submitted policy generation is not the installed generation";
      return result;
    }
    const PolicyValidationResult policy_check =
        check_contract_against_policy(*state_.policy, submitted.body);
    if (!policy_check.ok) {
      result.code = policy_check.diagnostics.first_error_code();
      result.message = "submitted contract violates the installed policy";
      for (const std::string& reason : policy_check.reasons()) {
        result.message.append("; ").append(reason);
      }
      return result;
    }
  }

  const CompatibilityResult compatibility =
      check_compatibility(current.generations.back().body.body, submitted.body);
  if (!compatibility.compatible()) {
    result.code = compatibility.diagnostics.first_error_code();
    result.message = "submitted contract is not compatible with the current generation";
    for (const std::string& reason : compatibility.reasons()) {
      result.message.append("; ").append(reason);
    }
    return result;
  }

  if (current.generations.size() >= kMaxRetainedGenerations) {
    result.code = Code::kRetentionExceeded;
    result.message = "workload reached the retained generation bound";
    return result;
  }

  Json payload;
  payload.set("workload", submitted.body.workload.id.str());
  payload.set("contract_generation", static_cast<std::int64_t>(submitted.body.generation.value));
  payload.set("digest", hex_of(submitted.digest));
  payload.set("publisher", verified.publisher.str());
  payload.set("supersedes", static_cast<std::int64_t>(submitted.supersedes.value));
  payload.set("supersedes_digest", hex_of(submitted.supersedes_digest));
  payload.set("recorded_at_millis", static_cast<std::int64_t>(now_millis()));
  payload.set("contract", contract_to_json(submitted));
  payload.set("proof", key_digest_payload(kDomainPublication, submitted.digest));

  const CommitOutcome outcome = commit(ledger::RecordType::kContractPublished, payload);
  if (!outcome.ok) {
    result.code = outcome.code;
    result.message = outcome.message;
    return result;
  }

  WorkloadState& workload = state_.workloads[submitted.body.workload.id];
  for (GenerationRecord& existing : workload.generations) {
    existing.superseded = true;
  }
  // A new generation invalidates every decision that depended on the old one.
  if (workload.evaluation.has_value()) {
    workload.evaluation->valid = false;
    workload.evaluation->invalidation_reason = "the contract generation changed";
  }
  GenerationRecord generation;
  generation.generation = submitted.body.generation;
  generation.digest = submitted.digest;
  generation.contract_id = submitted.body.contract_id;
  generation.body = submitted;
  generation.recorded_at_millis = now_millis();
  workload.generations.push_back(std::move(generation));
  workload.contract_generation = submitted.body.generation;
  workload.digest = submitted.digest;
  workload.contract = submitted.body.contract_id;
  workload.policy_generation = submitted.body.policy_generation;
  workload.workload_generation = submitted.body.workload.generation;

  result.ok = true;
  result.code = Code::kOk;
  result.message = "contract published";
  result.sequence = outcome.sequence;
  return result;
}

AttachEvidenceResult Runtime::attach_evidence(const EvidenceSet& submitted) {
  AttachEvidenceResult result;
  result.evidence = submitted.evidence_id;
  result.generation = submitted.generation;

  if (submitted.entries.empty()) {
    result.code = Code::kEvaluationNoEvidence;
    result.message = "evidence carries no entries";
    return result;
  }
  if (!submitted.generation.is_zero() && submitted.generation.value <= state_.evidence_floor.value) {
    result.code = Code::kEvidenceGenerationBackwards;
    result.message = "evidence generation does not advance past " +
                     std::to_string(state_.evidence_floor.value);
    return result;
  }

  // The publisher of evidence is bound by the same trust set as contracts.
  const Issuer* issuer = trust_.find(submitted.publisher);
  if (issuer == nullptr) {
    result.code = Code::kPublisherNotTrusted;
    result.message = "evidence publisher is not present in the trust set";
    return result;
  }

  // Evidence is stamped with this incarnation before it is durable: a restored
  // entry must be recognisable as belonging to an earlier boot.
  EvidenceSet stamped = submitted;
  stamped.epoch = info_.epoch;
  for (EvidenceEntry& entry : stamped.entries) {
    entry.captured_by = info_.incarnation;
    entry.epoch = info_.epoch;
    entry.publisher = stamped.publisher;
    entry.freshness = EvidenceFreshness::kCurrent;
    if (entry.produced_at_millis == 0) {
      entry.produced_at_millis = now_millis();
    }
  }
  // The identity is derived from the stamped bytes, so it has to be computed
  // after every field that participates in the digest has been written. Deriving
  // it earlier would stamp a set whose identity does not describe it, and the
  // durable record would then be refused on the next recovery.
  stamped.evidence_id = derive_evidence_id(evidence_digest(stamped));

  // Workloads are affected in a deterministic order so that two identical
  // submissions produce identical durable records.
  std::vector<WorkloadId> affected;
  for (const auto& entry : state_.workloads) {
    if (entry.second.retired) {
      continue;
    }
    for (const EvidenceEntry& evidence_entry : stamped.entries) {
      for (const Scope& scope : entry.second.generations.back().body.body.scopes) {
        if (scope.name == evidence_entry.scope) {
          affected.push_back(entry.first);
          break;
        }
      }
    }
  }
  std::sort(affected.begin(), affected.end());
  affected.erase(std::unique(affected.begin(), affected.end()), affected.end());

  Json payload;
  payload.set("evidence", evidence_to_json(stamped));
  payload.set("publisher", stamped.publisher.str());
  payload.set("recorded_at_millis", static_cast<std::int64_t>(now_millis()));
  if (!affected.empty()) {
    JsonArray workloads;
    for (const WorkloadId& id : affected) {
      workloads.push_back(Json(id.str()));
    }
    payload.set("workloads", Json(std::move(workloads)));
  }

  const CommitOutcome outcome = commit(ledger::RecordType::kEvidenceAttached, payload);
  if (!outcome.ok) {
    result.code = outcome.code;
    result.message = outcome.message;
    return result;
  }

  for (const WorkloadId& id : affected) {
    WorkloadState& workload = state_.workloads[id];
    workload.evidence = stamped;
    workload.evidence_generation = stamped.generation;
    if (workload.evaluation.has_value()) {
      workload.evaluation->valid = false;
      workload.evaluation->invalidation_reason = "the evidence generation changed";
      ++result.invalidated_evaluations;
    }
  }
  state_.evidence_floor = stamped.generation;

  result.ok = true;
  result.code = Code::kOk;
  result.message = "evidence attached";
  result.sequence = outcome.sequence;
  result.evidence = stamped.evidence_id;
  return result;
}

RuntimePolicyResult Runtime::install_policy(const Policy& policy) {
  RuntimePolicyResult result;
  result.policy = policy.policy_id;
  result.generation = policy.generation;

  const PolicyValidationResult validation = validate_policy(policy);
  if (!validation.ok) {
    result.code = validation.diagnostics.first_error_code();
    result.message = "policy is not valid";
    for (const std::string& reason : validation.reasons()) {
      result.message.append("; ").append(reason);
    }
    return result;
  }
  if (state_.policy.has_value() && policy.generation.value < state_.policy_generation.value) {
    result.code = Code::kStaleGeneration;
    result.message = "policy generation is behind the installed generation";
    return result;
  }
  if (state_.policy.has_value() && policy.generation.value == state_.policy_generation.value &&
      policy.policy_id != state_.policy->policy_id) {
    result.code = Code::kDuplicateWorkload;
    result.message = "policy generation is already installed with different content";
    return result;
  }

  Json payload;
  payload.set("policy", policy_to_json(policy));
  payload.set("digest", hex_of(policy_digest(policy)));
  payload.set("recorded_at_millis", static_cast<std::int64_t>(now_millis()));

  const CommitOutcome outcome = commit(ledger::RecordType::kPolicyInstalled, payload);
  if (!outcome.ok) {
    result.code = outcome.code;
    result.message = outcome.message;
    return result;
  }

  state_.policy = policy;
  state_.policy_digest = policy_digest(policy);
  state_.policy_generation = policy.generation;
  for (auto& entry : state_.workloads) {
    if (entry.second.evaluation.has_value()) {
      entry.second.evaluation->valid = false;
      entry.second.evaluation->invalidation_reason = "the policy generation changed";
    }
  }

  result.ok = true;
  result.code = Code::kOk;
  result.message = "policy installed";
  result.sequence = outcome.sequence;
  return result;
}

RetireResult Runtime::retire(WorkloadId workload) {
  RetireResult result;
  const auto found = state_.workloads.find(workload);
  if (found == state_.workloads.end()) {
    result.code = Code::kUnknownWorkload;
    result.message = "no contract is registered for that workload";
    return result;
  }
  if (found->second.retired) {
    result.code = Code::kContractRetired;
    result.message = "workload is already retired";
    return result;
  }

  Json payload;
  payload.set("workload", workload.str());
  payload.set("recorded_at_millis", static_cast<std::int64_t>(now_millis()));

  // Retirement is appended after the workload record it names, so the replay
  // order above is the order the records were produced in.
  const CommitOutcome outcome = commit(ledger::RecordType::kWorkloadRetired, payload);
  if (!outcome.ok) {
    result.code = outcome.code;
    result.message = outcome.message;
    return result;
  }

  WorkloadState& state = state_.workloads[workload];
  state.retired = true;
  for (GenerationRecord& generation : state.generations) {
    generation.retired = true;
  }
  if (state.evaluation.has_value()) {
    state.evaluation->valid = false;
    state.evaluation->invalidation_reason = "the workload was retired";
  }

  result.ok = true;
  result.code = Code::kOk;
  result.message = "workload retired";
  result.sequence = outcome.sequence;
  return result;
}

EvaluationResult Runtime::evaluate(WorkloadId workload) {
  const auto found = state_.workloads.find(workload);
  if (found == state_.workloads.end()) {
    EvaluationResult result;
    result.code = Code::kUnknownWorkload;
    result.message = "no contract is registered for that workload";
    return result;
  }
  return evaluate_internal(found->second, nullptr, true);
}

EvaluationResult Runtime::evaluate_with_evidence(WorkloadId workload, const EvidenceSet& evidence) {
  const auto found = state_.workloads.find(workload);
  if (found == state_.workloads.end()) {
    EvaluationResult result;
    result.code = Code::kUnknownWorkload;
    result.message = "no contract is registered for that workload";
    return result;
  }
  return evaluate_internal(found->second, &evidence, false);
}

EvaluationResult Runtime::evaluate_internal(const WorkloadState& workload, const EvidenceSet* supplied,
                                            bool allow_cached) {
  EvaluationResult result;
  const Contract& contract = workload.generations.back().body;

  // A cached decision is only ever served when it was produced by this
  // incarnation, for this contract generation, this policy generation, and this
  // evidence generation. Anything else is recomputed from the current evidence.
  if (allow_cached && workload.evaluation.has_value() && workload.evaluation->valid &&
      workload.evaluation->evaluation.evaluated_by == info_.incarnation &&
      workload.evaluation->evaluation.contract_digest == contract.digest &&
      workload.evaluation->evaluation.policy_generation.value ==
          contract.body.policy_generation.value &&
      workload.evaluation->evaluation.evidence_generation.value ==
          workload.evidence_generation.value) {
    result.ok = true;
    result.evaluation = workload.evaluation->evaluation;
    result.message = "cached decision for the current generations";
    return result;
  }

  EvidenceSet evidence;
  if (supplied != nullptr) {
    evidence = *supplied;
    evidence.epoch = info_.epoch;
    for (EvidenceEntry& entry : evidence.entries) {
      entry.captured_by = info_.incarnation;
      entry.epoch = info_.epoch;
    }
    const EvidenceValidationResult validated =
        validate_evidence(evidence, contract.body, info_.incarnation, now_millis(),
                          evidence_max_age_millis_);
    if (!validated.ok) {
      result.code = validated.diagnostics.first_error_code();
      result.message = "supplied evidence was rejected";
      for (const std::string& reason : validated.reasons()) {
        result.message.append("; ").append(reason);
      }
      return result;
    }
  } else if (workload.evidence.has_value()) {
    evidence = *workload.evidence;
  } else {
    // No evidence has ever been supplied for this workload. The verdict is
    // unknown, never satisfied, and the contract digest is still reported so a
    // caller can see exactly which generation was asked about.
    ContractEvaluation evaluation;
    evaluation.workload = workload.id;
    evaluation.contract = contract.body.contract_id;
    evaluation.contract_generation = contract.body.generation;
    evaluation.contract_digest = contract.digest;
    evaluation.policy_generation = contract.body.policy_generation;
    evaluation.evidence_generation = EvidenceGeneration{};
    evaluation.evaluated_by = info_.incarnation;
    evaluation.epoch = info_.epoch;
    evaluation.evaluated_at_millis = now_millis();
    evaluation.aggregate = Satisfaction::kUnknown;
    for (const Requirement& requirement : contract.body.requirements) {
      RequirementEvaluation item;
      item.requirement = requirement.id;
      item.scope = requirement.scope;
      item.kind = requirement.kind;
      item.strength = requirement.strength;
      item.satisfaction = requirement.strength == RequirementStrength::kInformational
                              ? Satisfaction::kNotApplicable
                              : Satisfaction::kUnknown;
      item.reason_code = requirement.strength == RequirementStrength::kInformational
                             ? Code::kOk
                             : Code::kEvaluationNoEvidence;
      item.reason = requirement.strength == RequirementStrength::kInformational
                        ? "informational requirements are recorded but not evaluated"
                        : "no evidence has been supplied for scope '" + requirement.scope + "'";
      item.freshness = EvidenceFreshness::kRevalidationRequired;
      evaluation.requirements.push_back(std::move(item));
    }
    evaluation.summary.required_total = 0;
    for (const RequirementEvaluation& item : evaluation.requirements) {
      if (item.strength == RequirementStrength::kRequired) {
        ++evaluation.summary.required_total;
        ++evaluation.summary.required_unknown;
      } else if (item.strength == RequirementStrength::kPreferred) {
        ++evaluation.summary.preferred_unknown;
      } else {
        ++evaluation.summary.informational;
        ++evaluation.summary.not_applicable;
      }
    }
    result.ok = true;
    result.code = Code::kEvaluationNoEvidence;
    result.message = "no evidence is available; every required verdict is unknown";
    result.evaluation = std::move(evaluation);
    return result;
  }

  const EvaluationResult evaluated = evaluate_contract(contract, evidence, info_.incarnation,
                                                       now_millis(), evidence_max_age_millis_);
  if (!evaluated.ok) {
    return evaluated;
  }
  result = evaluated;
  result.message = "evaluated against evidence generation " +
                   std::to_string(evidence.generation.value);
  return result;
}

std::optional<WorkloadSnapshot> Runtime::snapshot(WorkloadId workload) const {
  const auto found = state_.workloads.find(workload);
  if (found == state_.workloads.end()) {
    return std::nullopt;
  }
  const WorkloadState& state = found->second;
  WorkloadSnapshot out;
  out.id = state.id;
  out.name = state.name;
  out.workload_generation = state.workload_generation;
  out.contract_generation = state.contract_generation;
  out.digest = state.digest;
  out.contract = state.contract;
  out.policy_generation = state.policy_generation;
  out.evidence_generation = state.evidence_generation;
  out.retired = state.retired;
  for (const GenerationRecord& generation : state.generations) {
    GenerationHistory history;
    history.generation = generation.generation;
    history.digest = generation.digest;
    history.contract_id = generation.contract_id;
    history.recorded_at_millis = generation.recorded_at_millis;
    history.superseded = generation.superseded;
    history.retired = generation.retired;
    out.history.push_back(std::move(history));
  }
  return out;
}

std::optional<Contract> Runtime::contract_at(WorkloadId workload,
                                             ContractGeneration generation) const {
  const auto found = state_.workloads.find(workload);
  if (found == state_.workloads.end()) {
    return std::nullopt;
  }
  for (const GenerationRecord& record : found->second.generations) {
    if (record.generation.value == generation.value) {
      return record.body;
    }
  }
  return std::nullopt;
}

std::vector<WorkloadId> Runtime::workloads() const {
  std::vector<WorkloadId> out;
  out.reserve(state_.workloads.size());
  for (const auto& entry : state_.workloads) {
    out.push_back(entry.first);
  }
  return out;
}

bool Runtime::verify_history(Code& code, std::string& message) const {
  std::vector<ledger::Record> records;
  ledger::RecoveryReport report;
  if (!ledger_.read_all(records, report, code, message)) {
    return false;
  }
  if (report.recovered) {
    code = Code::kLedgerTruncated;
    message = "journal has a torn tail: " + report.detail;
    return false;
  }
  // Every durable contract record must be present in the derived index.
  std::map<WorkloadId, std::uint64_t> highest;
  for (const auto& entry : state_.workloads) {
    highest[entry.first] = entry.second.contract_generation.value;
  }
  for (const ledger::Record& record : records) {
    if (record.type != ledger::RecordType::kContractPublished &&
        record.type != ledger::RecordType::kWorkloadRegistered) {
      continue;
    }
    JsonDecodeResult decoded = json_decode(record.payload, JsonDecodeOptions{});
    if (!decoded.ok) {
      code = Code::kLedgerCorrupt;
      message = "record " + std::to_string(record.sequence) + " is not canonical JSON";
      return false;
    }
    const Json* workload = decoded.value.find("workload");
    const Json* generation = decoded.value.find("contract_generation");
    const Json* digest = decoded.value.find("digest");
    if (workload == nullptr || generation == nullptr || digest == nullptr) {
      code = Code::kLedgerCorrupt;
      message = "record " + std::to_string(record.sequence) + " is missing contract fields";
      return false;
    }
    const std::optional<WorkloadId> id = WorkloadId::parse(workload->as_string());
    if (!id.has_value()) {
      code = Code::kLedgerCorrupt;
      message = "record " + std::to_string(record.sequence) + " names an invalid workload";
      return false;
    }
    const auto found = state_.workloads.find(*id);
    if (found == state_.workloads.end()) {
      code = Code::kIndexMismatch;
      message = "journal holds a contract for a workload the index does not";
      return false;
    }
    bool matched = false;
    for (const GenerationRecord& record_generation : found->second.generations) {
      if (record_generation.generation.value ==
              static_cast<std::uint64_t>(generation->as_int()) &&
          hex_of(record_generation.digest) == digest->as_string()) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      code = Code::kIndexMismatch;
      message = "journal and index disagree about a contract generation";
      return false;
    }
  }
  code = Code::kOk;
  message.clear();
  return true;
}

}  // namespace wnc