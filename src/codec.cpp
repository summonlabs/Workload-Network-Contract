// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/error.hpp"

#include <array>
#include <utility>

namespace wnc {
namespace {

struct CodeInfo {
  Code code;
  std::string_view token;
  std::string_view description;
};

// Every code maps to exactly one token and one description. The table is
// linear; lookups happen on failure paths only.
constexpr std::array<CodeInfo, 109> kCodeTable = {{
    {Code::kOk, "ok", "operation accepted"},
    {Code::kBadMagic, "bad_magic", "frame magic does not match this protocol"},
    {Code::kBadVersion, "bad_version", "protocol version is not supported"},
    {Code::kFrameTooLarge, "frame_too_large", "frame exceeds the configured byte bound"},
    {Code::kTruncatedFrame, "truncated_frame", "frame ended before its declared length"},
    {Code::kFrameCrcMismatch, "frame_crc_mismatch", "frame integrity check failed"},
    {Code::kTrailingGarbage, "trailing_garbage", "bytes remained after the complete document"},
    {Code::kUnknownFrameType, "unknown_frame_type", "frame type is not defined by this version"},
    {Code::kMalformedFrameHeader, "malformed_frame_header", "frame header fields are inconsistent"},
    {Code::kBodyTooLarge, "body_too_large", "frame body exceeds the configured byte bound"},
    {Code::kUnknownPayloadSchema, "unknown_payload_schema", "payload schema tag is not supported"},
    {Code::kSessionClosed, "session_closed", "session is closed and cannot carry new work"},
    {Code::kBackpressure, "backpressure", "pending request bound reached; request refused"},
    {Code::kConnectFailed, "connect_failed", "transport connection could not be established"},
    {Code::kBindFailed, "bind_failed", "listening address could not be bound"},
    {Code::kListenFailed, "listen_failed", "listening socket could not be created"},
    {Code::kIoFailed, "io_failed", "transport input or output failed"},
    {Code::kDeadlineExceeded, "deadline_exceeded", "bounded wait elapsed before completion"},

    {Code::kJsonSyntax, "json_syntax", "document is not well formed JSON"},
    {Code::kJsonDepthExceeded, "json_depth_exceeded", "nesting depth exceeds the configured bound"},
    {Code::kJsonDuplicateKey, "json_duplicate_key", "object repeats a key"},
    {Code::kJsonNotAnObject, "json_not_an_object", "value is not a JSON object"},
    {Code::kJsonNotAnArray, "json_not_an_array", "value is not a JSON array"},
    {Code::kJsonMissingField, "json_missing_field", "required field is absent"},
    {Code::kJsonWrongType, "json_wrong_type", "field has the wrong JSON type"},
    {Code::kJsonInvalidUtf8, "json_invalid_utf8", "string contains an invalid UTF-8 sequence"},
    {Code::kJsonStringTooLong, "json_string_too_long", "string exceeds the configured byte bound"},
    {Code::kJsonNumberOutOfRange, "json_number_out_of_range", "number is not representable exactly"},
    {Code::kJsonUnknownField, "json_unknown_field", "object contains a field this schema forbids"},
    {Code::kJsonTooManyElements, "json_too_many_elements", "array exceeds the configured bound"},
    {Code::kJsonInvalidLiteral, "json_invalid_literal", "literal token is malformed"},
    {Code::kDocumentTooLarge, "document_too_large", "document exceeds the configured byte bound"},

    {Code::kContractSchema, "contract_schema", "contract does not satisfy its schema"},
    {Code::kEmptyRequirementSet, "empty_requirement_set", "contract declares no requirements"},
    {Code::kDuplicateRequirement, "duplicate_requirement", "two requirements share scope, kind and key"},
    {Code::kUnknownScope, "unknown_scope", "requirement references an undeclared scope"},
    {Code::kMissingRequirementKey, "missing_requirement_key", "requirement kind requires an explicit key"},
    {Code::kTooManyScopes, "too_many_scopes", "scope count exceeds the configured bound"},
    {Code::kTooManyRequirements, "too_many_requirements", "requirement count exceeds the configured bound"},
    {Code::kTooManyRankedScopes, "too_many_ranked_scopes", "ranked scope count exceeds the configured bound"},
    {Code::kInvalidStrength, "invalid_strength", "strength token is not required, preferred or informational"},
    {Code::kInvalidKind, "invalid_kind", "requirement kind token is not defined"},
    {Code::kInvalidValue, "invalid_value", "requirement parameters are malformed"},
    {Code::kValueOutOfRange, "value_out_of_range", "requirement parameter is outside its permitted range"},
    {Code::kMissingPublisher, "missing_publisher", "contract carries no publisher identity"},
    {Code::kZeroIdentity, "zero_identity", "identity is the zero identity"},
    {Code::kEmptyCollective, "empty_collective", "collective requirement names no members"},
    {Code::kDuplicateCollectiveMember, "duplicate_collective_member", "collective repeats a member identity"},
    {Code::kTooManyAttributes, "too_many_attributes", "attribute count exceeds the configured bound"},
    {Code::kEmptyScopeName, "empty_scope_name", "scope name is empty"},

    {Code::kUnknownContract, "unknown_contract", "no contract is registered for that identity"},
    {Code::kUnknownWorkload, "unknown_workload", "no contract is registered for that workload"},
    {Code::kStaleGeneration, "stale_generation", "generation is behind the current generation"},
    {Code::kGenerationGap, "generation_gap", "generation skips past the next expected generation"},
    {Code::kSuperseded, "superseded", "object was superseded by a later generation"},
    {Code::kContractRetired, "contract_retired", "workload contract is retired and accepts no update"},
    {Code::kWriterFenced, "writer_fenced", "writer incarnation is fenced by a newer boot"},
    {Code::kPublisherNotTrusted, "publisher_not_trusted", "publisher identity is not in the trust set"},
    {Code::kSignatureInvalid, "signature_invalid", "signature does not verify for the covered bytes"},
    {Code::kSignatureMissing, "signature_missing", "signed submission carries no signature"},
    {Code::kReplayRejected, "replay_rejected", "submission was already applied under this boot"},
    {Code::kPublisherMismatch, "publisher_mismatch", "envelope identity disagrees with the signing key"},
    {Code::kNotContractOwner, "not_contract_owner", "publisher does not own the current generation"},
    {Code::kContractDigestMismatch, "contract_digest_mismatch", "declared digest does not match canonical bytes"},
    {Code::kWrongCoordinatorIncarnation, "wrong_coordinator_incarnation", "request targets a different coordinator incarnation"},
    {Code::kDuplicateWorkload, "duplicate_workload", "workload already has an active contract"},
    {Code::kRetentionExceeded, "retention_exceeded", "retention bound reached; oldest generations must be pruned"},
    {Code::kUnknownPolicy, "unknown_policy", "policy identity or generation is not current"},

    {Code::kCompositionConflict, "composition_conflict", "composed layers disagree on the same requirement key"},
    {Code::kWeakeningDenied, "weakening_denied", "override attempts to weaken a stronger requirement"},
    {Code::kPolicyDenied, "policy_denied", "requirement violates an allowed range or strength floor"},
    {Code::kLayerNotFound, "layer_not_found", "composition layer does not exist"},
    {Code::kTooManyLayers, "too_many_layers", "layer count exceeds the configured bound"},
    {Code::kOverlayInvalid, "overlay_invalid", "overlay is not a valid contract fragment"},
    {Code::kCompositionCycle, "composition_cycle", "layer graph contains a cycle"},

    {Code::kIncompatibleMajor, "incompatible_major", "contract major version differs"},
    {Code::kIncompatibleRequirementRemoved, "incompatible_requirement_removed", "required requirement disappeared"},
    {Code::kIncompatibleRequirementWeakened, "incompatible_requirement_weakened", "required requirement was weakened"},
    {Code::kIncompatibleScopeRemoved, "incompatible_scope_removed", "scope disappeared for a required requirement"},
    {Code::kIncompatibleKindChanged, "incompatible_kind_changed", "requirement key changed kind"},
    {Code::kContractSchemaVersionUnsupported, "contract_schema_version_unsupported", "contract schema version is not supported"},

    {Code::kEvidenceUnknownScope, "evidence_unknown_scope", "evidence references an undeclared scope"},
    {Code::kEvidenceStale, "evidence_stale", "evidence generation or epoch is behind the current one"},
    {Code::kEvidenceExpired, "evidence_expired", "evidence age exceeds the policy maximum"},
    {Code::kEvidenceGenerationBackwards, "evidence_generation_backwards", "evidence generation does not advance"},
    {Code::kEvidenceDuplicate, "evidence_duplicate", "evidence repeats a scope and dimension"},
    {Code::kEvidenceTooManyEntries, "evidence_too_many_entries", "evidence entry count exceeds the configured bound"},
    {Code::kEvaluationNoEvidence, "evaluation_no_evidence", "no evidence covers this requirement dimension"},
    {Code::kEvaluationMissingDimension, "evaluation_missing_dimension", "evidence omits a dimension the requirement needs"},
    {Code::kEvidenceNotCurrent, "evidence_not_current", "evidence is not current under this coordinator incarnation"},
    {Code::kRevalidationRequired, "revalidation_required", "evidence must be re-established by a publisher"},
    {Code::kEvidenceRejected, "evidence_rejected", "evidence failed validation and was refused"},

    {Code::kLedgerCorrupt, "ledger_corrupt", "persisted record fails integrity or structure checks"},
    {Code::kLedgerTruncated, "ledger_truncated", "persisted record ends before its declared length"},
    {Code::kLedgerOversized, "ledger_oversized", "persisted record exceeds the configured byte bound"},
    {Code::kLedgerIncompatible, "ledger_incompatible", "ledger format version is not supported"},
    {Code::kIndexMismatch, "index_mismatch", "derived index disagrees with durable records"},
    {Code::kStateUnavailable, "state_unavailable", "state directory is missing or unusable"},
    {Code::kAtomicReplaceFailed, "atomic_replace_failed", "atomic file replacement did not complete"},
    {Code::kSnapshotInvalid, "snapshot_invalid", "snapshot does not satisfy its schema"},
    {Code::kLockHeld, "lock_held", "another live holder owns the state directory"},
    {Code::kIndexGapDetected, "index_gap_detected", "durable sequence has a gap; recovery is required"},
    {Code::kDirectoryUnavailable, "directory_unavailable", "required directory could not be created or read"},
    {Code::kPathRejected, "path_rejected", "path escapes the state root or is otherwise refused"},
    {Code::kRecoveryRequired, "recovery_required", "state must be recovered before serving"},

    {Code::kIdentityReconciled, "identity_reconciled",
     "a submitted identity disagreed with the canonical bytes and was recomputed from them"},

    {Code::kTooManyReasons, "too_many_reasons", "diagnostic list was truncated at its bound"},
    {Code::kInternalInvariant, "internal_invariant", "internal invariant violated"},
    {Code::kNotImplemented, "not_implemented", "capability is not implemented in this build"},
}};

constexpr CodeInfo kUnknownCode{Code::kInternalInvariant, "unknown_code", "unrecognised code"};

const CodeInfo& lookup(Code code) noexcept {
  for (const CodeInfo& info : kCodeTable) {
    if (info.code == code) {
      return info;
    }
  }
  return kUnknownCode;
}

}  // namespace

std::string_view code_token(Code code) noexcept { return lookup(code).token; }

std::string_view code_description(Code code) noexcept { return lookup(code).description; }

std::string Diagnostic::render() const {
  std::string out;
  out.reserve(message.size() + 80);
  out.append(code_token(code));
  out.append(": ");
  out.append(message);
  if (!scope.is_zero()) {
    out.append(" [scope=");
    out.append(scope.view());
    out.append("]");
  }
  if (!requirement.is_zero()) {
    out.append(" [requirement=");
    out.append(requirement.view());
    out.append("]");
  }
  return out;
}

void DiagnosticLog::add(const Diagnostic& diagnostic) {
  if (entries_.size() >= limit_) {
    truncated_ = true;
    return;
  }
  entries_.push_back(diagnostic);
}

void DiagnosticLog::add(Code code, std::string message) {
  add(Diagnostic(code, std::move(message)));
}

void DiagnosticLog::add(Code code, std::string message, ScopeId scope) {
  add(Diagnostic(code, std::move(message), scope));
}

void DiagnosticLog::add(Code code, std::string message, ScopeId scope, RequirementId requirement) {
  add(Diagnostic(code, std::move(message), scope, requirement));
}

bool DiagnosticLog::has_errors() const noexcept {
  for (const Diagnostic& entry : entries_) {
    if (!entry.ok()) {
      return true;
    }
  }
  return false;
}

std::vector<std::string> DiagnosticLog::reasons() const {
  std::vector<std::string> out;
  out.reserve(entries_.size() + (truncated_ ? 1 : 0));
  for (const Diagnostic& entry : entries_) {
    out.push_back(entry.render());
  }
  if (truncated_) {
    out.push_back(Diagnostic(Code::kTooManyReasons, "diagnostic bound reached").render());
  }
  return out;
}

Code DiagnosticLog::first_error_code() const noexcept {
  for (const Diagnostic& entry : entries_) {
    if (!entry.ok()) {
      return entry.code;
    }
  }
  return Code::kOk;
}

}  // namespace wnc
