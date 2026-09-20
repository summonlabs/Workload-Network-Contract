// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Deterministic, machine readable denial reasons. Nothing in this boundary
// reports failure as a bare boolean: every denial carries a stable code that a
// caller, a CLI, or a test can assert on.

#ifndef WNC_ERROR_HPP
#define WNC_ERROR_HPP

#include <string>
#include <string_view>
#include <vector>

#include "wnc/identity.hpp"

namespace wnc {

enum class Code : std::uint32_t {
  kOk = 0,

  // Structural / protocol failures (100-199)
  kBadMagic = 100,
  kBadVersion = 101,
  kFrameTooLarge = 102,
  kTruncatedFrame = 103,
  kFrameCrcMismatch = 104,
  kTrailingGarbage = 105,
  kUnknownFrameType = 106,
  kMalformedFrameHeader = 107,
  kBodyTooLarge = 108,
  kUnknownPayloadSchema = 109,
  kSessionClosed = 110,
  kBackpressure = 111,
  kConnectFailed = 112,
  kBindFailed = 113,
  kListenFailed = 114,
  kIoFailed = 115,
  kDeadlineExceeded = 116,

  // Document failures (200-299)
  kJsonSyntax = 200,
  kJsonDepthExceeded = 201,
  kJsonDuplicateKey = 202,
  kJsonNotAnObject = 203,
  kJsonNotAnArray = 204,
  kJsonMissingField = 205,
  kJsonWrongType = 206,
  kJsonInvalidUtf8 = 207,
  kJsonStringTooLong = 208,
  kJsonNumberOutOfRange = 209,
  kJsonUnknownField = 210,
  kJsonTooManyElements = 211,
  kJsonInvalidLiteral = 212,
  kDocumentTooLarge = 213,

  // Contract failures (300-399)
  kContractSchema = 300,
  kEmptyRequirementSet = 301,
  kDuplicateRequirement = 302,
  kUnknownScope = 303,
  kMissingRequirementKey = 304,
  kTooManyScopes = 305,
  kTooManyRequirements = 306,
  kTooManyRankedScopes = 307,
  kInvalidStrength = 308,
  kInvalidKind = 309,
  kInvalidValue = 310,
  kValueOutOfRange = 311,
  kMissingPublisher = 312,
  kZeroIdentity = 313,
  kEmptyCollective = 314,
  kDuplicateCollectiveMember = 315,
  kTooManyAttributes = 316,
  kEmptyScopeName = 317,

  // Authority and lifecycle failures (400-499)
  kUnknownContract = 400,
  kUnknownWorkload = 401,
  kStaleGeneration = 402,
  kGenerationGap = 403,
  kSuperseded = 404,
  kContractRetired = 405,
  kWriterFenced = 406,
  kPublisherNotTrusted = 407,
  kSignatureInvalid = 408,
  kSignatureMissing = 409,
  kReplayRejected = 410,
  kPublisherMismatch = 411,
  kNotContractOwner = 412,
  kContractDigestMismatch = 413,
  kWrongCoordinatorIncarnation = 414,
  kDuplicateWorkload = 415,
  kRetentionExceeded = 416,
  kUnknownPolicy = 417,

  // Composition and policy failures (500-599)
  kCompositionConflict = 500,
  kWeakeningDenied = 501,
  kPolicyDenied = 502,
  kLayerNotFound = 503,
  kTooManyLayers = 504,
  kOverlayInvalid = 505,
  kCompositionCycle = 506,

  // Compatibility failures (600-699)
  kIncompatibleMajor = 600,
  kIncompatibleRequirementRemoved = 601,
  kIncompatibleRequirementWeakened = 602,
  kIncompatibleScopeRemoved = 603,
  kIncompatibleKindChanged = 604,
  kContractSchemaVersionUnsupported = 605,

  // Evidence and evaluation failures (700-799)
  kEvidenceUnknownScope = 700,
  kEvidenceStale = 701,
  kEvidenceExpired = 702,
  kEvidenceGenerationBackwards = 703,
  kEvidenceDuplicate = 704,
  kEvidenceTooManyEntries = 705,
  kEvaluationNoEvidence = 706,
  kEvaluationMissingDimension = 707,
  kEvidenceNotCurrent = 708,
  kRevalidationRequired = 709,
  kEvidenceRejected = 710,

  // Persistence failures (800-899)
  kLedgerCorrupt = 800,
  kLedgerTruncated = 801,
  kLedgerOversized = 802,
  kLedgerIncompatible = 803,
  kIndexMismatch = 804,
  kStateUnavailable = 805,
  kAtomicReplaceFailed = 806,
  kSnapshotInvalid = 807,
  kLockHeld = 808,
  kIndexGapDetected = 809,
  kDirectoryUnavailable = 810,
  kPathRejected = 811,
  kRecoveryRequired = 812,

  // Reconstruction (850-899)
  kIdentityReconciled = 850,

  // Reporting bounds (900-999)
  kTooManyReasons = 900,
  kInternalInvariant = 901,
  kNotImplemented = 902,
};

// Short stable token for a code, suitable for CLI output and tests.
std::string_view code_token(Code code) noexcept;

// One-line human readable explanation of a code.
std::string_view code_description(Code code) noexcept;

struct Diagnostic {
  Code code = Code::kOk;
  std::string message;
  ScopeId scope{};
  RequirementId requirement{};

  Diagnostic() = default;
  Diagnostic(Code code_value, std::string text) : code(code_value), message(std::move(text)) {}
  Diagnostic(Code code_value, std::string text, ScopeId scope_id)
      : code(code_value), message(std::move(text)), scope(scope_id) {}
  Diagnostic(Code code_value, std::string text, ScopeId scope_id, RequirementId requirement_id)
      : code(code_value), message(std::move(text)), scope(scope_id), requirement(requirement_id) {}

  [[nodiscard]] bool ok() const noexcept { return code == Code::kOk; }

  // Stable single-line rendering: "code: message [scope=...] [requirement=...]".
  [[nodiscard]] std::string render() const;
};

// Bounded diagnostic collection. Appending beyond the bound records a single
// truncation marker instead of growing without limit.
class DiagnosticLog {
 public:
  explicit DiagnosticLog(std::size_t limit = 64) : limit_(limit == 0 ? 1 : limit) {}

  void add(const Diagnostic& diagnostic);
  void add(Code code, std::string message);
  void add(Code code, std::string message, ScopeId scope);
  void add(Code code, std::string message, ScopeId scope, RequirementId requirement);

  [[nodiscard]] bool has_errors() const noexcept;
  [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
  [[nodiscard]] bool truncated() const noexcept { return truncated_; }
  [[nodiscard]] const std::vector<Diagnostic>& entries() const noexcept { return entries_; }

  // Reasons in stable order, one per entry.
  [[nodiscard]] std::vector<std::string> reasons() const;

  [[nodiscard]] Code first_error_code() const noexcept;

 private:
  std::vector<Diagnostic> entries_;
  std::size_t limit_;
  bool truncated_ = false;
};

using Reasons = std::vector<std::string>;

}  // namespace wnc

#endif  // WNC_ERROR_HPP
