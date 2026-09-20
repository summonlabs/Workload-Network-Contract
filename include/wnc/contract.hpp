// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// The contract model: what a workload generation declares about the network it
// requires, how strongly it requires it, and what makes two declarations the
// same declaration.
//
// This boundary owns the declaration. It does not own scheduling, routing,
// admission, bandwidth allocation, QoS enforcement, topology discovery, or
// network telemetry; those systems consume the contract through narrow
// interfaces and their observable state enters this boundary only as evidence.

#ifndef WNC_CONTRACT_HPP
#define WNC_CONTRACT_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "wnc/error.hpp"
#include "wnc/identity.hpp"
#include "wnc/json.hpp"
#include "wnc/signature.hpp"

namespace wnc {

// ---------------------------------------------------------------------------
// Requirement dimensions
// ---------------------------------------------------------------------------

enum class RequirementKind : std::uint8_t {
  kMinBandwidth = 0,
  kMaxLatency = 1,
  kMaxJitter = 2,
  kMaxLoss = 3,
  kLocality = 4,
  kPathDiversity = 5,
  kFailureDomainSeparation = 6,
  kSecurityClass = 7,
  kTrafficPriority = 8,
  kBurstAllowance = 9,
  kCollective = 10,
  kCheckpointIsolation = 11,
  kDisaggregatedAffinity = 12,
  kMaintenanceTolerance = 13,
  kAttribute = 14,
};

// Strengths are ordered: REQUIRED outranks PREFERRED which outranks
// INFORMATIONAL. The ordering is what makes "silently weakened" a decidable
// question rather than a judgement call.
enum class RequirementStrength : std::uint8_t {
  kInformational = 0,
  kPreferred = 1,
  kRequired = 2,
};

enum class Satisfaction : std::uint8_t {
  kSatisfied = 0,
  kUnsatisfied = 1,
  kUnknown = 2,
  kNotApplicable = 3,
};

enum class EvidenceFreshness : std::uint8_t {
  kCurrent = 0,       // captured by the running coordinator incarnation
  kStale = 1,         // restored from durable state after a restart
  kExpired = 2,       // age exceeded the policy maximum
  kRevalidationRequired = 3,  // restored and must be re-established by a publisher
};

std::string_view requirement_kind_token(RequirementKind kind) noexcept;
std::optional<RequirementKind> parse_requirement_kind(std::string_view token) noexcept;
std::string_view requirement_strength_token(RequirementStrength strength) noexcept;
std::optional<RequirementStrength> parse_requirement_strength(std::string_view token) noexcept;
std::string_view satisfaction_token(Satisfaction value) noexcept;
std::optional<Satisfaction> parse_satisfaction(std::string_view token) noexcept;
std::string_view freshness_token(EvidenceFreshness value) noexcept;

// Decodes the token back to the value. An unrecognised token is refused rather
// than defaulted, so a document can never smuggle in a freshness that this
// boundary does not define.
std::optional<EvidenceFreshness> parse_freshness(std::string_view text) noexcept;

// True when the kind is expressed through a numeric target and minimum.
bool kind_is_numeric(RequirementKind kind) noexcept;
// True when the kind's ordering is "at least" (bandwidth, priority, diversity)
// rather than "at most" (latency, jitter, loss).
bool kind_is_floor(RequirementKind kind) noexcept;
// True when the kind is expressed through free form attributes only.
bool kind_is_attribute_only(RequirementKind kind) noexcept;

// ---------------------------------------------------------------------------
// Requirements
// ---------------------------------------------------------------------------

struct RequirementKey {
  std::string scope;
  RequirementKind kind = RequirementKind::kMinBandwidth;
  std::string key;

  friend bool operator==(const RequirementKey& a, const RequirementKey& b) noexcept {
    return a.scope == b.scope && a.kind == b.kind && a.key == b.key;
  }
  friend bool operator<(const RequirementKey& a, const RequirementKey& b) noexcept {
    if (a.scope != b.scope) {
      return a.scope < b.scope;
    }
    if (a.kind != b.kind) {
      return a.kind < b.kind;
    }
    return a.key < b.key;
  }
};

struct Requirement {
  RequirementId id{};
  std::string scope;
  RequirementKind kind = RequirementKind::kMinBandwidth;
  RequirementStrength strength = RequirementStrength::kRequired;
  // Numeric target and floor in the kind's canonical unit. The target is the
  // strict bound; the floor is the weakest still-acceptable bound, which is what
  // turns an unmet PREFERRED requirement into a preference rather than a
  // violation. For a floor kind the target is above the floor; for a ceiling
  // kind it is below it.
  double target = 0.0;
  double minimum = 0.0;
  bool has_numeric = false;
  // Textual value: locality class, security class, isolation class, and the
  // free form value of an attribute requirement. This is the required value.
  std::string value;
  // Optional additional accepted textual value for a PREFERRED requirement: the
  // target text is the strict value, and this is the still-acceptable one.
  std::string preferred_value;

  // The value a satisfaction decision compares against the strict bound.
  [[nodiscard]] std::string_view target_text() const noexcept {
    return value.empty() ? std::string_view() : std::string_view(value);
  }
  [[nodiscard]] std::string_view preferred_text() const noexcept {
    return preferred_value.empty() ? std::string_view() : std::string_view(preferred_value);
  }
  // Collective membership, ordered and free of duplicates after validation.
  std::vector<RequirementId> members;
  // Additional parameters. Keys must be unique and sorted.
  std::vector<std::pair<std::string, std::string>> attributes;
  // Disambiguates several requirements of the same kind inside one scope.
  std::string key;

  [[nodiscard]] RequirementKey composite_key() const;
};

// Canonical scope names carried by transport bodies must be explicit; a contract
// declares its scopes so that evidence and requirements cannot refer to scopes
// that no participant agreed on.
struct Scope {
  std::string name;
  bool has_rank = false;
  std::uint32_t rank = 0;
  std::string parent;
};

struct Workload {
  WorkloadId id{};
  std::string name;
  WorkloadGeneration generation{};
};

struct ContractEnvelope {
  PublisherId publisher{};
  SignatureAlgorithm algorithm = SignatureAlgorithm::kNone;
  std::string key_id;
  std::vector<std::uint8_t> signature;
  std::uint64_t issued_millis = 0;

  [[nodiscard]] bool is_signed() const noexcept {
    return algorithm != SignatureAlgorithm::kNone && !signature.empty();
  }
};

struct ContractBody {
  std::uint32_t schema_version = kSchemaVersion;
  Workload workload{};
  ContractId contract_id{};
  ContractGeneration generation{};
  PolicyGeneration policy_generation{};
  std::uint32_t major = 1;
  std::uint32_t minor = 0;
  std::uint32_t patch = 0;
  std::string description;
  std::vector<Scope> scopes;
  std::vector<Requirement> requirements;
};

struct Contract {
  ContractBody body;
  Digest digest{};
  ContractEnvelope envelope;
  // Generation this contract supersedes, when it continues an existing chain.
  ContractGeneration supersedes{};
  // Digest of the superseded contract, when present.
  Digest supersedes_digest{};

  [[nodiscard]] bool has_supersedes() const noexcept { return !supersedes.is_zero(); }
};

// ---------------------------------------------------------------------------
// Identity derivation
// ---------------------------------------------------------------------------

// Requirement identity: a function of the composite key and the requirement
// content, never of its position in a list.
RequirementId derive_requirement_id(const Requirement& requirement) noexcept;

// Contract identity: a function of the workload identity and the canonical
// digest of the body, so two contracts with identical bodies share an identity.
ContractId derive_contract_id(const WorkloadId& workload, const Digest& body_digest) noexcept;

Digest body_digest(const ContractBody& body) noexcept;

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

Json contract_body_to_json(const ContractBody& body);
Json requirement_to_json(const Requirement& requirement);
Json contract_to_json(const Contract& contract);

struct ContractDecodeResult {
  bool ok = false;
  Contract contract;
  Code code = Code::kOk;
  std::string message;
};

ContractDecodeResult contract_from_json(const Json& value, const JsonDecodeOptions& options = {});
ContractDecodeResult contract_from_text(std::string_view text, const JsonDecodeOptions& options = {});

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

struct ValidationResult {
  bool ok = false;
  DiagnosticLog diagnostics;
  [[nodiscard]] std::vector<std::string> reasons() const { return diagnostics.reasons(); }
};

ValidationResult validate_contract_body(const ContractBody& body,
                                        const JsonDecodeOptions& options = {});
ValidationResult validate_contract(const Contract& contract, const JsonDecodeOptions& options = {});

// Sorts scopes, requirements, members, and attributes into canonical order and
// recomputes every derived identity. Returns false when the body is malformed
// enough that canonicalisation cannot proceed.
bool canonicalize(Contract& contract);

// Settings that bound what a contract may declare.
struct ContractLimits {
  std::size_t max_scopes = kMaxScopesPerContract;
  std::size_t max_requirements = kMaxRequirementsPerContract;
  std::size_t max_requirements_per_scope = kMaxRequirementsPerScope;
  std::size_t max_ranked_scopes = kMaxRankedScopesPerContract;
  std::size_t max_attributes = kMaxAttributesPerRequirement;
  std::size_t max_distinct_kinds_per_scope = kMaxDistinctKindsPerScope;
  // Largest supported schema version. Bodies above it are refused before any
  // structure is materialised.
  std::uint32_t max_schema_version = kSchemaVersion;
};

const ContractLimits& default_contract_limits() noexcept;

// Canonical ordering used everywhere: scope name, then kind, then key, then id.
bool requirement_precedes(const Requirement& a, const Requirement& b) noexcept;

}  // namespace wnc

#endif  // WNC_CONTRACT_HPP
