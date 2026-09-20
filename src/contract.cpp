// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/contract.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <limits>

#include "wnc/hash.hpp"

namespace wnc {
namespace {

// ---------------------------------------------------------------------------
// Token tables
// ---------------------------------------------------------------------------

struct KindInfo {
  RequirementKind kind;
  std::string_view token;
  bool numeric;
  bool floor;
};

constexpr std::array<KindInfo, 15> kKindTable = {{
    {RequirementKind::kMinBandwidth, "min_bandwidth", true, true},
    {RequirementKind::kMaxLatency, "max_latency", true, false},
    {RequirementKind::kMaxJitter, "max_jitter", true, false},
    {RequirementKind::kMaxLoss, "max_loss", true, false},
    {RequirementKind::kLocality, "locality", false, false},
    {RequirementKind::kPathDiversity, "path_diversity", true, true},
    {RequirementKind::kFailureDomainSeparation, "failure_domain_separation", true, true},
    {RequirementKind::kSecurityClass, "security_class", false, false},
    {RequirementKind::kTrafficPriority, "traffic_priority", true, true},
    {RequirementKind::kBurstAllowance, "burst_allowance", true, true},
    {RequirementKind::kCollective, "collective", false, false},
    {RequirementKind::kCheckpointIsolation, "checkpoint_isolation", false, false},
    {RequirementKind::kDisaggregatedAffinity, "disaggregated_affinity", false, false},
    {RequirementKind::kMaintenanceTolerance, "maintenance_tolerance", false, false},
    {RequirementKind::kAttribute, "attribute", false, false},
}};

constexpr std::array<std::pair<RequirementStrength, std::string_view>, 3> kStrengthTable = {{
    {RequirementStrength::kRequired, "required"},
    {RequirementStrength::kPreferred, "preferred"},
    {RequirementStrength::kInformational, "informational"},
}};

constexpr std::array<std::pair<Satisfaction, std::string_view>, 4> kSatisfactionTable = {{
    {Satisfaction::kSatisfied, "satisfied"},
    {Satisfaction::kUnsatisfied, "unsatisfied"},
    {Satisfaction::kUnknown, "unknown"},
    {Satisfaction::kNotApplicable, "not_applicable"},
}};

constexpr std::array<std::pair<EvidenceFreshness, std::string_view>, 4> kFreshnessTable = {{
    {EvidenceFreshness::kCurrent, "current"},
    {EvidenceFreshness::kStale, "stale"},
    {EvidenceFreshness::kExpired, "expired"},
    {EvidenceFreshness::kRevalidationRequired, "revalidation_required"},
}};

constexpr std::string_view kUnknownToken = "unknown";

// Numeric kinds declare a canonical unit so that a value is never ambiguous.
std::string_view kind_unit(RequirementKind kind) noexcept {
  switch (kind) {
    case RequirementKind::kMinBandwidth:
      return "bits_per_second";
    case RequirementKind::kMaxLatency:
      return "microseconds";
    case RequirementKind::kMaxJitter:
      return "microseconds";
    case RequirementKind::kMaxLoss:
      return "parts_per_million";
    case RequirementKind::kPathDiversity:
      return "paths";
    case RequirementKind::kFailureDomainSeparation:
      return "domains";
    case RequirementKind::kTrafficPriority:
      return "class";
    case RequirementKind::kBurstAllowance:
      return "bits";
    default:
      return "none";
  }
}

// Finds an existing attribute value, or nullptr.
const Json* find_member(const JsonObject& object, std::string_view key) {
  const auto it = object.find(key);
  if (it == object.end()) {
    return nullptr;
  }
  return &it->second;
}

struct ReadError {
  Code code = Code::kContractSchema;
  std::string message;
};

std::string path_join(std::string_view path, std::string_view field) {
  std::string out(path);
  if (!out.empty()) {
    out.push_back('.');
  }
  out.append(field);
  return out;
}

bool read_id(const JsonObject& object, std::string_view field, std::string_view path,
             std::string& out, ReadError& error) {
  const Json* value = find_member(object, field);
  if (value == nullptr) {
    error = {Code::kContractSchema, path_join(path, field) + " is required"};
    return false;
  }
  if (!value->is_string()) {
    error = {Code::kContractSchema, path_join(path, field) + " must be a string"};
    return false;
  }
  const std::string_view text = value->as_string();
  if (text.size() != kSha256HexChars) {
    error = {Code::kContractSchema, path_join(path, field) + " must be a 64 character identifier"};
    return false;
  }
  for (const char c : text) {
    const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    if (!hex) {
      error = {Code::kContractSchema, path_join(path, field) + " must be lowercase hexadecimal"};
      return false;
    }
  }
  out.assign(text);
  return true;
}

bool read_string(const JsonObject& object, std::string_view field, std::string_view path,
                 std::size_t max_bytes, bool required, std::string& out, ReadError& error) {
  const Json* value = find_member(object, field);
  if (value == nullptr) {
    if (required) {
      error = {Code::kContractSchema, path_join(path, field) + " is required"};
      return false;
    }
    return true;
  }
  if (!value->is_string()) {
    error = {Code::kContractSchema, path_join(path, field) + " must be a string"};
    return false;
  }
  if (value->as_string().size() > max_bytes) {
    error = {Code::kJsonStringTooLong, path_join(path, field) + " exceeds the string bound"};
    return false;
  }
  out = value->as_string();
  return true;
}

bool read_uint(const JsonObject& object, std::string_view field, std::string_view path,
               std::uint64_t maximum, bool required, std::uint64_t& out, ReadError& error) {
  const Json* value = find_member(object, field);
  if (value == nullptr) {
    if (required) {
      error = {Code::kContractSchema, path_join(path, field) + " is required"};
      return false;
    }
    return true;
  }
  if (!value->is_int()) {
    error = {Code::kContractSchema, path_join(path, field) + " must be an integer"};
    return false;
  }
  if (value->as_int() < 0 || static_cast<std::uint64_t>(value->as_int()) > maximum) {
    error = {Code::kValueOutOfRange, path_join(path, field) + " is outside the permitted range"};
    return false;
  }
  out = static_cast<std::uint64_t>(value->as_int());
  return true;
}

bool read_real(const JsonObject& object, std::string_view field, std::string_view path,
               std::uint64_t maximum, bool& present, double& out, ReadError& error) {
  const Json* value = find_member(object, field);
  if (value == nullptr) {
    present = false;
    return true;
  }
  if (!value->is_number()) {
    error = {Code::kContractSchema, path_join(path, field) + " must be a number"};
    return false;
  }
  const double raw = value->as_real();
  if (!std::isfinite(raw) || raw < 0.0 || raw > static_cast<double>(maximum)) {
    error = {Code::kValueOutOfRange, path_join(path, field) + " is outside the permitted range"};
    return false;
  }
  present = true;
  out = raw;
  return true;
}

bool read_bool(const JsonObject& object, std::string_view field, std::string_view path,
               bool required, bool& out, ReadError& error) {
  const Json* value = find_member(object, field);
  if (value == nullptr) {
    if (required) {
      error = {Code::kContractSchema, path_join(path, field) + " is required"};
      return false;
    }
    return true;
  }
  if (!value->is_bool()) {
    error = {Code::kContractSchema, path_join(path, field) + " must be a boolean"};
    return false;
  }
  out = value->as_bool();
  return true;
}

// Largest magnitude accepted for a numeric requirement parameter. This bound is
// applied before the value is stored, and it is far above any real network
// quantity, so it exists to make arithmetic total rather than to model a limit.
constexpr std::uint64_t kMaxNumericParameter = 1000000000000000ull;  // 1e15

constexpr std::size_t kMaxNameBytes = 200;
constexpr std::size_t kMaxMemberCount = 4096;

}  // namespace

std::string_view requirement_kind_token(RequirementKind kind) noexcept {
  for (const KindInfo& info : kKindTable) {
    if (info.kind == kind) {
      return info.token;
    }
  }
  return kUnknownToken;
}

std::optional<RequirementKind> parse_requirement_kind(std::string_view token) noexcept {
  for (const KindInfo& info : kKindTable) {
    if (info.token == token) {
      return info.kind;
    }
  }
  return std::nullopt;
}

std::string_view requirement_strength_token(RequirementStrength strength) noexcept {
  for (const auto& entry : kStrengthTable) {
    if (entry.first == strength) {
      return entry.second;
    }
  }
  return kUnknownToken;
}

std::optional<RequirementStrength> parse_requirement_strength(std::string_view token) noexcept {
  for (const auto& entry : kStrengthTable) {
    if (entry.second == token) {
      return entry.first;
    }
  }
  return std::nullopt;
}

std::string_view satisfaction_token(Satisfaction value) noexcept {
  for (const auto& entry : kSatisfactionTable) {
    if (entry.first == value) {
      return entry.second;
    }
  }
  return kUnknownToken;
}

std::optional<Satisfaction> parse_satisfaction(std::string_view token) noexcept {
  for (const auto& entry : kSatisfactionTable) {
    if (entry.second == token) {
      return entry.first;
    }
  }
  return std::nullopt;
}

std::string_view freshness_token(EvidenceFreshness value) noexcept {
  for (const auto& entry : kFreshnessTable) {
    if (entry.first == value) {
      return entry.second;
    }
  }
  return kUnknownToken;
}

std::optional<EvidenceFreshness> parse_freshness(std::string_view text) noexcept {
  for (const auto& entry : kFreshnessTable) {
    if (entry.second == text) {
      return entry.first;
    }
  }
  return std::nullopt;
}

bool kind_is_numeric(RequirementKind kind) noexcept {
  for (const KindInfo& info : kKindTable) {
    if (info.kind == kind) {
      return info.numeric;
    }
  }
  return false;
}

bool kind_is_floor(RequirementKind kind) noexcept {
  for (const KindInfo& info : kKindTable) {
    if (info.kind == kind) {
      return info.floor;
    }
  }
  return false;
}

bool kind_is_attribute_only(RequirementKind kind) noexcept { return !kind_is_numeric(kind); }

RequirementKey Requirement::composite_key() const {
  RequirementKey out;
  out.scope = scope;
  out.kind = kind;
  out.key = key;
  return out;
}

// ---------------------------------------------------------------------------
// Identity derivation
// ---------------------------------------------------------------------------

RequirementId derive_requirement_id(const Requirement& requirement) noexcept {
  Json document;
  document.set("scope", requirement.scope);
  document.set("kind", std::string(requirement_kind_token(requirement.kind)));
  document.set("key", requirement.key);
  document.set("strength", std::string(requirement_strength_token(requirement.strength)));
  if (requirement.has_numeric) {
    document.set("target", requirement.target);
    document.set("minimum", requirement.minimum);
  }
  if (!requirement.value.empty()) {
    document.set("value", requirement.value);
  }
  if (!requirement.preferred_value.empty()) {
    document.set("preferred_value", requirement.preferred_value);
  }
  if (!requirement.attributes.empty()) {
    JsonArray attributes;
    for (const auto& attribute : requirement.attributes) {
      Json item;
      item.set("name", attribute.first);
      item.set("value", attribute.second);
      attributes.push_back(std::move(item));
    }
    document.set("attributes", Json(std::move(attributes)));
  }
  if (!requirement.members.empty()) {
    JsonArray members;
    for (const RequirementId& member : requirement.members) {
      members.push_back(Json(member.str()));
    }
    document.set("members", Json(std::move(members)));
  }
  return RequirementId::from_digest(digest_domain("wnc/v1/requirement", document.dump()));
}

ContractId derive_contract_id(const WorkloadId& workload, const Digest& digest) noexcept {
  // The identity is a function of the workload and the digest of the body, so
  // two contracts with the same semantic content share an identity and two
  // different contents never do. It is deliberately independent of the
  // generation number: a generation is a position in a chain, not a property of
  // the content.
  //
  // The hex text has to outlive the array of views that refers to it. Building
  // the array from a temporary would leave every element pointing at freed
  // bytes, which is a use-after-free that only shows up when the allocator
  // reuses the block.
  const std::string digest_hex = hex_encode(digest);
  const std::array<std::string_view, 3> parts = {std::string_view("wnc/v1/contract"),
                                                 workload.view(), digest_hex};
  return ContractId::from_digest(sha256_parts(std::span<const std::string_view>(parts.data(), parts.size())));
}

namespace {

// The digest covers every semantic field of the body except the contract
// identity itself. The identity is derived from the digest, so folding it back
// in would make the two mutually dependent and no fixed point would exist.
Json body_digest_material(const ContractBody& body) {
  Json document = contract_body_to_json(body);
  document.set("contract_id", std::string(64, '0'));
  return document;
}

}  // namespace

Digest body_digest(const ContractBody& body) noexcept {
  return digest_domain("wnc/v1/contract-body", body_digest_material(body).dump());
}

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

Json requirement_to_json(const Requirement& requirement) {
  Json out;
  out.set("id", requirement.id.str());
  out.set("scope", requirement.scope);
  out.set("kind", std::string(requirement_kind_token(requirement.kind)));
  out.set("strength", std::string(requirement_strength_token(requirement.strength)));
  if (requirement.has_numeric) {
    out.set("target", requirement.target);
    out.set("minimum", requirement.minimum);
    out.set("unit", std::string(kind_unit(requirement.kind)));
  }
  if (!requirement.value.empty()) {
    out.set("value", requirement.value);
  }
  if (!requirement.preferred_value.empty()) {
    out.set("preferred_value", requirement.preferred_value);
  }
  if (!requirement.members.empty()) {
    JsonArray members;
    members.reserve(requirement.members.size());
    for (const RequirementId& member : requirement.members) {
      members.push_back(Json(member.str()));
    }
    out.set("members", Json(std::move(members)));
  }
  if (!requirement.attributes.empty()) {
    JsonArray attributes;
    attributes.reserve(requirement.attributes.size());
    for (const auto& attribute : requirement.attributes) {
      Json item;
      item.set("name", attribute.first);
      item.set("value", attribute.second);
      attributes.push_back(std::move(item));
    }
    out.set("attributes", Json(std::move(attributes)));
  }
  out.set("key", requirement.key);
  return out;
}

Json contract_body_to_json(const ContractBody& body) {
  Json out;
  out.set("schema_version", static_cast<std::int64_t>(body.schema_version));
  Json workload;
  workload.set("id", body.workload.id.str());
  workload.set("name", body.workload.name);
  workload.set("generation", static_cast<std::int64_t>(body.workload.generation.value));
  out.set("workload", std::move(workload));
  out.set("contract_id", body.contract_id.str());
  out.set("contract_generation", static_cast<std::int64_t>(body.generation.value));
  out.set("policy_generation", static_cast<std::int64_t>(body.policy_generation.value));
  Json version;
  version.set("major", static_cast<std::int64_t>(body.major));
  version.set("minor", static_cast<std::int64_t>(body.minor));
  version.set("patch", static_cast<std::int64_t>(body.patch));
  out.set("version", std::move(version));
  out.set("description", body.description);

  JsonArray scopes;
  scopes.reserve(body.scopes.size());
  for (const Scope& scope : body.scopes) {
    Json item;
    item.set("name", scope.name);
    if (scope.has_rank) {
      item.set("rank", static_cast<std::int64_t>(scope.rank));
    }
    if (!scope.parent.empty()) {
      item.set("parent", scope.parent);
    }
    scopes.push_back(std::move(item));
  }
  out.set("scopes", Json(std::move(scopes)));

  JsonArray requirements;
  requirements.reserve(body.requirements.size());
  for (const Requirement& requirement : body.requirements) {
    requirements.push_back(requirement_to_json(requirement));
  }
  out.set("requirements", Json(std::move(requirements)));
  return out;
}

Json contract_to_json(const Contract& contract) {
  Json out;
  out.set("body", contract_body_to_json(contract.body));
  out.set("digest", hex_encode(contract.digest));
  if (contract.has_supersedes()) {
    out.set("supersedes", static_cast<std::int64_t>(contract.supersedes.value));
    out.set("supersedes_digest", hex_encode(contract.supersedes_digest));
  }
  Json envelope;
  envelope.set("publisher", contract.envelope.publisher.str());
  envelope.set("algorithm", std::string(signature_algorithm_token(contract.envelope.algorithm)));
  envelope.set("key_id", contract.envelope.key_id);
  envelope.set("issued_millis", static_cast<std::int64_t>(contract.envelope.issued_millis));
  if (!contract.envelope.signature.empty()) {
    envelope.set("signature", base64url_encode(
                                  std::span<const std::uint8_t>(contract.envelope.signature.data(),
                                                                contract.envelope.signature.size())));
  }
  out.set("envelope", std::move(envelope));
  return out;
}

namespace {

bool decode_attributes(const Json& value, std::string_view path, Requirement& requirement,
                       ReadError& error) {
  if (!value.is_array()) {
    error = {Code::kContractSchema, std::string(path) + ".attributes must be an array"};
    return false;
  }
  if (value.size() > kMaxAttributesPerRequirement) {
    error = {Code::kTooManyAttributes, std::string(path) + ".attributes exceeds the attribute bound"};
    return false;
  }
  for (std::size_t i = 0; i < value.size(); ++i) {
    const Json* item = value.at(i);
    if (item == nullptr || !item->is_object()) {
      error = {Code::kContractSchema, std::string(path) + ".attributes entries must be objects"};
      return false;
    }
    std::string name;
    std::string attribute_value;
    if (!read_string(item->object(), "name", path, kMaxNameBytes, true, name, error) ||
        !read_string(item->object(), "value", path, kMaxStringBytes, true, attribute_value, error)) {
      return false;
    }
    if (name.empty()) {
      error = {Code::kMissingRequirementKey, std::string(path) + ".attributes name must not be empty"};
      return false;
    }
    requirement.attributes.emplace_back(std::move(name), std::move(attribute_value));
  }
  return true;
}

bool decode_requirement(const Json& value, std::size_t index, Requirement& requirement,
                        ReadError& error) {
  const std::string path = "requirements[" + std::to_string(index) + "]";
  if (!value.is_object()) {
    error = {Code::kContractSchema, path + " must be an object"};
    return false;
  }
  const JsonObject& object = value.object();

  std::string scope;
  if (!read_string(object, "scope", path, kMaxNameBytes, true, scope, error)) {
    return false;
  }
  requirement.scope = std::move(scope);

  const Json* kind_value = find_member(object, "kind");
  if (kind_value == nullptr || !kind_value->is_string()) {
    error = {Code::kContractSchema, path + ".kind is required and must be a string"};
    return false;
  }
  const std::optional<RequirementKind> kind = parse_requirement_kind(kind_value->as_string());
  if (!kind.has_value()) {
    error = {Code::kInvalidKind, path + ".kind is not a defined requirement kind"};
    return false;
  }
  requirement.kind = *kind;

  const Json* strength_value = find_member(object, "strength");
  if (strength_value == nullptr || !strength_value->is_string()) {
    error = {Code::kContractSchema, path + ".strength is required and must be a string"};
    return false;
  }
  const std::optional<RequirementStrength> strength =
      parse_requirement_strength(strength_value->as_string());
  if (!strength.has_value()) {
    error = {Code::kInvalidStrength, path + ".strength is not required, preferred or informational"};
    return false;
  }
  requirement.strength = *strength;

  if (!read_string(object, "key", path, kMaxNameBytes, false, requirement.key, error)) {
    return false;
  }
  if (!read_string(object, "value", path, kMaxStringBytes, false, requirement.value, error)) {
    return false;
  }
  if (!read_string(object, "preferred_value", path, kMaxStringBytes, false,
                   requirement.preferred_value, error)) {
    return false;
  }

  double target = 0.0;
  double minimum = 0.0;
  bool has_target = false;
  bool has_minimum = false;
  if (!read_real(object, "target", path, kMaxNumericParameter, has_target, target, error) ||
      !read_real(object, "minimum", path, kMaxNumericParameter, has_minimum, minimum, error)) {
    return false;
  }
  if (has_target != has_minimum) {
    error = {Code::kInvalidValue, path + " must declare target and minimum together"};
    return false;
  }
  if (has_target) {
    // The strict bound and the weakest acceptable bound must be ordered for the
    // kind; the decoder refuses a body that states an impossible band.
    const bool floor_kind = kind_is_floor(*kind);
    const bool ordered = floor_kind ? (target >= minimum) : (target <= minimum);
    if (!ordered) {
      error = {Code::kValueOutOfRange,
               path + ".target must be the strict bound and minimum the weakest acceptable bound"};
      return false;
    }
  }
  requirement.has_numeric = has_target;
  requirement.target = target;
  requirement.minimum = minimum;

  const Json* members = find_member(object, "members");
  if (members != nullptr) {
    if (!members->is_array()) {
      error = {Code::kContractSchema, path + ".members must be an array"};
      return false;
    }
    if (members->size() > kMaxMemberCount) {
      error = {Code::kTooManyAttributes, path + ".members exceeds the member bound"};
      return false;
    }
    for (std::size_t i = 0; i < members->size(); ++i) {
      const Json* item = members->at(i);
      if (item == nullptr || !item->is_string()) {
        error = {Code::kContractSchema, path + ".members entries must be strings"};
        return false;
      }
      const std::optional<RequirementId> member = RequirementId::parse(item->as_string());
      if (!member.has_value()) {
        error = {Code::kContractSchema, path + ".members entries must be 64 character identifiers"};
        return false;
      }
      requirement.members.push_back(*member);
    }
  }

  const Json* attributes = find_member(object, "attributes");
  if (attributes != nullptr && !decode_attributes(*attributes, path, requirement, error)) {
    return false;
  }

  const Json* id = find_member(object, "id");
  if (id != nullptr) {
    if (!id->is_string()) {
      error = {Code::kContractSchema, path + ".id must be a string"};
      return false;
    }
    const std::optional<RequirementId> parsed = RequirementId::parse(id->as_string());
    if (!parsed.has_value()) {
      error = {Code::kContractSchema, path + ".id must be a 64 character identifier"};
      return false;
    }
    requirement.id = *parsed;
  }
  return true;
}

bool decode_scope(const Json& value, std::size_t index, Scope& scope, ReadError& error) {
  const std::string path = "scopes[" + std::to_string(index) + "]";
  if (!value.is_object()) {
    error = {Code::kContractSchema, path + " must be an object"};
    return false;
  }
  const JsonObject& object = value.object();
  if (!read_string(object, "name", path, kMaxNameBytes, true, scope.name, error)) {
    return false;
  }
  if (scope.name.empty()) {
    error = {Code::kEmptyScopeName, path + ".name must not be empty"};
    return false;
  }
  if (!read_string(object, "parent", path, kMaxNameBytes, false, scope.parent, error)) {
    return false;
  }
  const Json* rank = find_member(object, "rank");
  if (rank != nullptr) {
    std::uint64_t parsed = 0;
    if (!read_uint(object, "rank", path, 1000000u, false, parsed, error)) {
      return false;
    }
    scope.has_rank = true;
    scope.rank = static_cast<std::uint32_t>(parsed);
  }
  return true;
}

bool decode_envelope(const Json& value, ContractEnvelope& envelope, ReadError& error) {
  const std::string path = "envelope";
  if (!value.is_object()) {
    error = {Code::kContractSchema, "envelope must be an object"};
    return false;
  }
  const JsonObject& object = value.object();
  std::string publisher;
  if (!read_id(object, "publisher", path, publisher, error)) {
    return false;
  }
  const std::optional<PublisherId> parsed_publisher = PublisherId::parse(publisher);
  if (!parsed_publisher.has_value()) {
    error = {Code::kContractSchema, "envelope.publisher is not a valid identifier"};
    return false;
  }
  envelope.publisher = *parsed_publisher;
  // A zero publisher is structurally acceptable here: this decoder describes
  // the document, and it is the coordinator that refuses an unsigned or
  // unattributed submission before it can change any state.

  const Json* algorithm = find_member(object, "algorithm");
  if (algorithm == nullptr || !algorithm->is_string()) {
    error = {Code::kContractSchema, "envelope.algorithm is required and must be a string"};
    return false;
  }
  const std::optional<SignatureAlgorithm> parsed_algorithm =
      parse_signature_algorithm(algorithm->as_string());
  if (!parsed_algorithm.has_value()) {
    error = {Code::kSignatureInvalid, "envelope.algorithm is not a supported algorithm"};
    return false;
  }
  envelope.algorithm = *parsed_algorithm;

  if (!read_string(object, "key_id", path, kSha256HexChars, true, envelope.key_id, error)) {
    return false;
  }
  std::uint64_t issued = 0;
  if (!read_uint(object, "issued_millis", path, std::numeric_limits<std::uint64_t>::max(), false,
                 issued, error)) {
    return false;
  }
  envelope.issued_millis = issued;

  const Json* signature = find_member(object, "signature");
  if (signature != nullptr) {
    if (!signature->is_string()) {
      error = {Code::kContractSchema, "envelope.signature must be a string"};
      return false;
    }
    const std::optional<std::vector<std::uint8_t>> decoded =
        base64url_decode(signature->as_string(), 1024);
    if (!decoded.has_value()) {
      error = {Code::kSignatureInvalid, "envelope.signature is not valid base64url"};
      return false;
    }
    envelope.signature = *decoded;
  }
  return true;
}

}  // namespace

ContractDecodeResult contract_from_json(const Json& value, const JsonDecodeOptions& options) {
  (void)options;
  ContractDecodeResult result;
  if (!value.is_object()) {
    result.code = Code::kJsonNotAnObject;
    result.message = "contract document must be an object";
    return result;
  }
  ReadError error;

  const Json* body = find_member(value.object(), "body");
  if (body == nullptr || !body->is_object()) {
    result.code = Code::kContractSchema;
    result.message = "contract document requires a body object";
    return result;
  }
  const JsonObject& body_object = body->object();

  Contract contract;
  std::uint64_t schema_version = 0;
  if (!read_uint(body_object, "schema_version", "body", 1000u, true, schema_version, error)) {
    result.code = error.code;
    result.message = error.message;
    return result;
  }
  contract.body.schema_version = static_cast<std::uint32_t>(schema_version);

  // Bounds are checked before anything is materialised. A document that declares
  // more structure than this boundary accepts is refused on its declared size,
  // before a single requirement or scope object exists, so a hostile document
  // cannot make the decoder allocate first and refuse second.
  {
    const ContractLimits& limits = default_contract_limits();
    if (schema_version > limits.max_schema_version) {
      result.code = Code::kContractSchemaVersionUnsupported;
      result.message = "body.schema_version " + std::to_string(schema_version) +
                        " exceeds the supported version " +
                        std::to_string(limits.max_schema_version);
      return result;
    }
    if (const Json* declared = find_member(body_object, "scopes");
        declared != nullptr && declared->is_array() && declared->size() > limits.max_scopes) {
      result.code = Code::kTooManyScopes;
      result.message = "body.scopes exceeds the scope bound";
      return result;
    }
    if (const Json* declared = find_member(body_object, "requirements");
        declared != nullptr && declared->is_array() &&
        declared->size() > limits.max_requirements) {
      result.code = Code::kTooManyRequirements;
      result.message = "body.requirements exceeds the requirement bound";
      return result;
    }
  }

  const Json* workload = find_member(body_object, "workload");
  if (workload == nullptr || !workload->is_object()) {
    result.code = Code::kContractSchema;
    result.message = "body.workload must be an object";
    return result;
  }
  {
    std::string workload_id;
    if (!read_id(workload->object(), "id", "body.workload", workload_id, error)) {
      result.code = error.code;
      result.message = error.message;
      return result;
    }
    const std::optional<WorkloadId> parsed = WorkloadId::parse(workload_id);
    if (!parsed.has_value() || parsed->is_zero()) {
      result.code = Code::kZeroIdentity;
      result.message = "body.workload.id must be a non zero identifier";
      return result;
    }
    contract.body.workload.id = *parsed;
    if (!read_string(workload->object(), "name", "body.workload", kMaxNameBytes, true,
                     contract.body.workload.name, error)) {
      result.code = error.code;
      result.message = error.message;
      return result;
    }
    std::uint64_t generation = 0;
    if (!read_uint(workload->object(), "generation", "body.workload",
                   std::numeric_limits<std::uint64_t>::max(), true, generation, error)) {
      result.code = error.code;
      result.message = error.message;
      return result;
    }
    contract.body.workload.generation.value = generation;
  }

  {
    std::string contract_id;
    if (!read_id(body_object, "contract_id", "body", contract_id, error)) {
      result.code = error.code;
      result.message = error.message;
      return result;
    }
    const std::optional<ContractId> parsed = ContractId::parse(contract_id);
    if (!parsed.has_value()) {
      result.code = Code::kContractSchema;
      result.message = "body.contract_id must be a 64 character identifier";
      return result;
    }
    // A zero contract identity is refused by validate_contract rather than by the
    // decoder: the decoder describes a document, and a composition fragment
    // legitimately carries no identity while a registered generation always does.
    contract.body.contract_id = *parsed;
  }

  std::uint64_t generation = 0;
  if (!read_uint(body_object, "contract_generation", "body",
                 std::numeric_limits<std::uint64_t>::max(), true, generation, error)) {
    result.code = error.code;
    result.message = error.message;
    return result;
  }
  contract.body.generation.value = generation;

  std::uint64_t policy_generation = 0;
  if (!read_uint(body_object, "policy_generation", "body",
                 std::numeric_limits<std::uint64_t>::max(), false, policy_generation, error)) {
    result.code = error.code;
    result.message = error.message;
    return result;
  }
  contract.body.policy_generation.value = policy_generation;

  const Json* version = find_member(body_object, "version");
  if (version != nullptr) {
    if (!version->is_object()) {
      result.code = Code::kContractSchema;
      result.message = "body.version must be an object";
      return result;
    }
    std::uint64_t major = 0;
    std::uint64_t minor = 0;
    std::uint64_t patch = 0;
    if (!read_uint(version->object(), "major", "body.version", 1000000u, false, major, error) ||
        !read_uint(version->object(), "minor", "body.version", 1000000u, false, minor, error) ||
        !read_uint(version->object(), "patch", "body.version", 1000000u, false, patch, error)) {
      result.code = error.code;
      result.message = error.message;
      return result;
    }
    contract.body.major = static_cast<std::uint32_t>(major);
    contract.body.minor = static_cast<std::uint32_t>(minor);
    contract.body.patch = static_cast<std::uint32_t>(patch);
  }

  if (!read_string(body_object, "description", "body", kMaxStringBytes, false,
                   contract.body.description, error)) {
    result.code = error.code;
    result.message = error.message;
    return result;
  }

  const Json* scopes = find_member(body_object, "scopes");
  if (scopes == nullptr || !scopes->is_array()) {
    result.code = Code::kContractSchema;
    result.message = "body.scopes must be an array";
    return result;
  }
  if (scopes->size() > kMaxScopesPerContract) {
    result.code = Code::kTooManyScopes;
    result.message = "body.scopes exceeds the scope bound";
    return result;
  }
  contract.body.scopes.reserve(scopes->size());
  for (std::size_t i = 0; i < scopes->size(); ++i) {
    Scope scope;
    if (!decode_scope(*scopes->at(i), i, scope, error)) {
      result.code = error.code;
      result.message = error.message;
      return result;
    }
    contract.body.scopes.push_back(std::move(scope));
  }

  const Json* requirements = find_member(body_object, "requirements");
  if (requirements == nullptr || !requirements->is_array()) {
    result.code = Code::kContractSchema;
    result.message = "body.requirements must be an array";
    return result;
  }
  // The count is checked before any requirement is materialised, so an oversized
  // document is refused at its declared size rather than after decoding it.
  if (requirements->size() > default_contract_limits().max_requirements) {
    result.code = Code::kTooManyRequirements;
    result.message = "body.requirements exceeds the requirement bound";
    return result;
  }
  contract.body.requirements.reserve(requirements->size());
  for (std::size_t i = 0; i < requirements->size(); ++i) {
    Requirement requirement;
    if (!decode_requirement(*requirements->at(i), i, requirement, error)) {
      result.code = error.code;
      result.message = error.message;
      return result;
    }
    contract.body.requirements.push_back(std::move(requirement));
  }

  const Json* envelope = find_member(value.object(), "envelope");
  if (envelope != nullptr && !decode_envelope(*envelope, contract.envelope, error)) {
    result.code = error.code;
    result.message = error.message;
    return result;
  }

  const Json* supersedes = find_member(value.object(), "supersedes");
  if (supersedes != nullptr) {
    std::uint64_t parsed = 0;
    if (!read_uint(value.object(), "supersedes", "", std::numeric_limits<std::uint64_t>::max(), false,
                   parsed, error)) {
      result.code = error.code;
      result.message = error.message;
      return result;
    }
    contract.supersedes.value = parsed;
  }
  const Json* supersedes_digest = find_member(value.object(), "supersedes_digest");
  if (supersedes_digest != nullptr) {
    if (!supersedes_digest->is_string()) {
      result.code = Code::kContractSchema;
      result.message = "supersedes_digest must be a string";
      return result;
    }
    const std::optional<Digest> parsed = hex_decode_digest(supersedes_digest->as_string());
    if (!parsed.has_value()) {
      result.code = Code::kContractDigestMismatch;
      result.message = "supersedes_digest is not a 64 character digest";
      return result;
    }
    contract.supersedes_digest = *parsed;
  }

  const Json* declared_digest = find_member(value.object(), "digest");
  if (declared_digest != nullptr) {
    if (!declared_digest->is_string()) {
      result.code = Code::kContractSchema;
      result.message = "digest must be a string";
      return result;
    }
    const std::optional<Digest> parsed = hex_decode_digest(declared_digest->as_string());
    if (!parsed.has_value()) {
      result.code = Code::kContractDigestMismatch;
      result.message = "digest is not a 64 character digest";
      return result;
    }
    const Digest computed = body_digest(contract.body);
    if (*parsed == Digest{}) {
      // A zero digest means "not yet derived": the author wrote a body and the
      // envelope has not been sealed. The digest is derived from the content
      // instead, exactly as the contract identity is.
      contract.digest = computed;
    } else if (*parsed != computed) {
      result.code = Code::kContractDigestMismatch;
      result.message = "declared digest does not match the canonical body bytes";
      return result;
    } else {
      contract.digest = *parsed;
    }
  } else {
    contract.digest = body_digest(contract.body);
  }

  result.ok = true;
  result.contract = std::move(contract);
  return result;
}

ContractDecodeResult contract_from_text(std::string_view text, const JsonDecodeOptions& options) {
  JsonDecodeResult decoded = json_decode(text, options);
  if (!decoded.ok) {
    ContractDecodeResult failure;
    failure.code = decoded.code;
    failure.message = decoded.message;
    return failure;
  }
  return contract_from_json(decoded.value, options);
}

// ---------------------------------------------------------------------------
// Ordering and validation
// ---------------------------------------------------------------------------

bool requirement_precedes(const Requirement& a, const Requirement& b) noexcept {
  if (a.scope != b.scope) {
    return a.scope < b.scope;
  }
  if (a.kind != b.kind) {
    return a.kind < b.kind;
  }
  if (a.key != b.key) {
    return a.key < b.key;
  }
  return a.id < b.id;
}

const ContractLimits& default_contract_limits() noexcept {
  static const ContractLimits limits;
  return limits;
}

namespace {

void validate_body(const ContractBody& body, const ContractLimits& limits,
                   DiagnosticLog& diagnostics) {
  if (body.schema_version == 0) {
    diagnostics.add(Code::kContractSchema, "schema_version must be at least 1");
  } else if (body.schema_version > limits.max_schema_version) {
    diagnostics.add(Code::kContractSchemaVersionUnsupported,
                    "schema_version " + std::to_string(body.schema_version) +
                        " exceeds the supported version " + std::to_string(limits.max_schema_version));
  }
  if (body.workload.id.is_zero()) {
    diagnostics.add(Code::kZeroIdentity, "workload identity is the zero identity");
  }
  if (body.workload.generation.is_zero()) {
    diagnostics.add(Code::kZeroIdentity, "workload generation must be at least 1");
  }
  if (body.contract_id.is_zero()) {
    diagnostics.add(Code::kZeroIdentity, "contract identity is the zero identity");
  }
  if (body.generation.is_zero()) {
    diagnostics.add(Code::kZeroIdentity, "contract generation must be at least 1");
  }
  if (body.policy_generation.is_zero()) {
    diagnostics.add(Code::kZeroIdentity, "policy generation must be at least 1");
  }
  if (body.workload.name.empty()) {
    diagnostics.add(Code::kContractSchema, "workload name must not be empty");
  }
  if (body.major == 0) {
    diagnostics.add(Code::kContractSchema, "contract major version must be at least 1");
  }
  if (body.scopes.size() > limits.max_scopes) {
    diagnostics.add(Code::kTooManyScopes,
                    "scope count " + std::to_string(body.scopes.size()) + " exceeds the bound " +
                        std::to_string(limits.max_scopes));
  }
  if (body.requirements.size() > limits.max_requirements) {
    diagnostics.add(Code::kTooManyRequirements,
                    "requirement count " + std::to_string(body.requirements.size()) +
                        " exceeds the bound " + std::to_string(limits.max_requirements));
  }
  if (body.requirements.empty()) {
    diagnostics.add(Code::kEmptyRequirementSet, "contract declares no requirements");
  }

  std::map<std::string_view, const Scope*> scopes;
  std::size_t ranked = 0;
  for (const Scope& scope : body.scopes) {
    if (scope.name.empty()) {
      diagnostics.add(Code::kEmptyScopeName, "scope name must not be empty");
      continue;
    }
    if (scope.has_rank) {
      ++ranked;
    }
    const auto inserted = scopes.emplace(scope.name, &scope);
    if (!inserted.second) {
      diagnostics.add(Code::kDuplicateRequirement, "scope '" + scope.name + "' is declared twice");
    }
  }
  if (ranked > limits.max_ranked_scopes) {
    diagnostics.add(Code::kTooManyRankedScopes,
                    "ranked scope count " + std::to_string(ranked) + " exceeds the bound " +
                        std::to_string(limits.max_ranked_scopes));
  }
  for (const Scope& scope : body.scopes) {
    if (scope.parent.empty()) {
      continue;
    }
    const auto parent = scopes.find(scope.parent);
    if (parent == scopes.end()) {
      diagnostics.add(Code::kUnknownScope,
                      "scope '" + scope.name + "' names undeclared parent '" + scope.parent + "'");
      continue;
    }
    if (scope.parent == scope.name) {
      diagnostics.add(Code::kCompositionCycle, "scope '" + scope.name + "' is its own parent");
      continue;
    }
    if (parent->second->has_rank && scope.has_rank && parent->second->rank >= scope.rank) {
      diagnostics.add(Code::kCompositionConflict,
                      "scope '" + scope.name + "' parent '" + scope.parent +
                          "' must have a strictly lower rank");
    }
  }
  // Cycle detection over the parent relation, bounded by the scope count.
  for (const Scope& start : body.scopes) {
    std::string_view current = start.name;
    std::size_t steps = 0;
    while (!current.empty() && steps <= body.scopes.size()) {
      const auto it = scopes.find(current);
      if (it == scopes.end()) {
        break;
      }
      current = it->second->parent;
      ++steps;
    }
    if (steps > body.scopes.size()) {
      diagnostics.add(Code::kCompositionCycle,
                      "scope '" + start.name + "' participates in a parent cycle");
      break;
    }
  }

  std::map<RequirementKey, RequirementId> keys;
  std::map<std::string_view, std::size_t> per_scope;
  std::map<std::string_view, std::map<RequirementKind, std::size_t>> kinds_per_scope;
  std::map<RequirementId, std::size_t> identities;
  for (const Requirement& requirement : body.requirements) {
    const auto scope = scopes.find(requirement.scope);
    if (requirement.scope.empty() || scope == scopes.end()) {
      diagnostics.add(Code::kUnknownScope,
                      "requirement references undeclared scope '" + requirement.scope + "'",
                      ScopeId{}, requirement.id);
    }
    if (requirement.id.is_zero()) {
      diagnostics.add(Code::kZeroIdentity, "requirement identity is the zero identity");
    }
    const auto identity = identities.emplace(requirement.id, 0);
    if (!identity.second) {
      diagnostics.add(Code::kDuplicateRequirement, "requirement identity is repeated",
                      ScopeId{}, requirement.id);
    }
    const RequirementKey key = requirement.composite_key();
    const auto inserted = keys.emplace(key, requirement.id);
    if (!inserted.second) {
      diagnostics.add(Code::kDuplicateRequirement,
                      "requirement key is repeated for scope '" + requirement.scope + "'",
                      ScopeId{}, requirement.id);
    }
    ++per_scope[requirement.scope];
    ++kinds_per_scope[requirement.scope][requirement.kind];

    if (kind_is_numeric(requirement.kind) && !requirement.has_numeric) {
      diagnostics.add(Code::kInvalidValue,
                      std::string("numeric requirement of kind ") +
                          std::string(requirement_kind_token(requirement.kind)) +
                          " must declare target and minimum",
                      ScopeId{}, requirement.id);
    }
    if (!kind_is_numeric(requirement.kind) && requirement.has_numeric) {
      diagnostics.add(Code::kInvalidValue,
                      std::string("requirement of kind ") +
                          std::string(requirement_kind_token(requirement.kind)) +
                          " must not declare numeric parameters",
                      ScopeId{}, requirement.id);
    }
    if (requirement.has_numeric) {
      if (!std::isfinite(requirement.target) || !std::isfinite(requirement.minimum)) {
        diagnostics.add(Code::kInvalidValue, "numeric parameters must be finite", ScopeId{},
                        requirement.id);
      } else if (requirement.target < 0.0 || requirement.minimum < 0.0) {
        diagnostics.add(Code::kValueOutOfRange, "numeric parameters must not be negative", ScopeId{},
                        requirement.id);
      } else {
        // One convention for every kind: the target is the strict bound and the
        // minimum is the weakest still-acceptable bound, so the target is always
        // the stronger of the two and can never sit below the minimum. For a
        // floor kind "stronger" means higher; for a ceiling kind it means lower.
        // The comparison is therefore expressed through the kind's direction.
        const bool floor = kind_is_floor(requirement.kind);
        const bool ordered = floor ? (requirement.target >= requirement.minimum)
                                   : (requirement.target <= requirement.minimum);
        if (!ordered) {
          diagnostics.add(Code::kValueOutOfRange,
                          "target must be the strict bound and minimum the weakest acceptable "
                          "bound for this requirement kind",
                          ScopeId{}, requirement.id);
        }
        if (requirement.strength == RequirementStrength::kRequired &&
            requirement.target != requirement.minimum) {
          diagnostics.add(Code::kValueOutOfRange,
                          "a required requirement has no preferred band: target must equal minimum",
                          ScopeId{}, requirement.id);
        }
        if (requirement.strength == RequirementStrength::kPreferred &&
            requirement.target == requirement.minimum) {
          diagnostics.add(Code::kValueOutOfRange,
                          "a preferred requirement must declare a distinct preferred band",
                          ScopeId{}, requirement.id);
        }
      }
    }
    // Kinds whose value is part of their meaning require an explicit value.
    const bool needs_value = requirement.kind == RequirementKind::kLocality ||
                             requirement.kind == RequirementKind::kSecurityClass ||
                             requirement.kind == RequirementKind::kCheckpointIsolation ||
                             requirement.kind == RequirementKind::kDisaggregatedAffinity ||
                             requirement.kind == RequirementKind::kMaintenanceTolerance ||
                             requirement.kind == RequirementKind::kAttribute;
    if (needs_value && requirement.value.empty()) {
      diagnostics.add(Code::kInvalidValue,
                      std::string("requirement of kind ") +
                          std::string(requirement_kind_token(requirement.kind)) +
                          " must declare a value",
                      ScopeId{}, requirement.id);
    }
    if (!requirement.preferred_value.empty()) {
      // A preferred band is only meaningful on a PREFERRED requirement, and it
      // must differ from the strict value, otherwise it states nothing.
      if (requirement.strength != RequirementStrength::kPreferred) {
        diagnostics.add(Code::kInvalidValue,
                        "preferred_value is only permitted on a preferred requirement",
                        ScopeId{}, requirement.id);
      }
      if (requirement.preferred_value == requirement.value) {
        diagnostics.add(Code::kInvalidValue,
                        "preferred_value must differ from the required value", ScopeId{},
                        requirement.id);
      }
    }
    if (requirement.key.size() > kMaxNameBytes || requirement.value.size() > kMaxStringBytes) {
      diagnostics.add(Code::kValueOutOfRange, "requirement parameter exceeds its byte bound",
                      ScopeId{}, requirement.id);
    }
    if (requirement.attributes.size() > limits.max_attributes) {
      diagnostics.add(Code::kTooManyAttributes, "requirement attribute count exceeds the bound",
                      ScopeId{}, requirement.id);
    }
    std::map<std::string_view, std::size_t> attribute_names;
    for (const auto& attribute : requirement.attributes) {
      const auto attribute_insert = attribute_names.emplace(attribute.first, 0);
      if (!attribute_insert.second) {
        diagnostics.add(Code::kDuplicateRequirement,
                        "requirement repeats attribute '" + attribute.first + "'", ScopeId{},
                        requirement.id);
      }
      if (attribute.first.size() > kMaxNameBytes || attribute.second.size() > kMaxStringBytes) {
        diagnostics.add(Code::kValueOutOfRange, "attribute exceeds its byte bound", ScopeId{},
                        requirement.id);
      }
    }
    if (requirement.kind == RequirementKind::kCollective) {
      if (requirement.members.empty()) {
        diagnostics.add(Code::kEmptyCollective, "collective requirement names no members", ScopeId{},
                        requirement.id);
      }
      std::map<RequirementId, std::size_t> member_counts;
      for (const RequirementId& member : requirement.members) {
        if (member.is_zero()) {
          diagnostics.add(Code::kZeroIdentity, "collective member is the zero identity", ScopeId{},
                          requirement.id);
        }
        const auto member_insert = member_counts.emplace(member, 0);
        if (!member_insert.second) {
          diagnostics.add(Code::kDuplicateCollectiveMember,
                          "collective names member " + member.str() + " more than once", ScopeId{},
                          requirement.id);
        }
      }
    } else if (!requirement.members.empty()) {
      diagnostics.add(Code::kInvalidValue, "only collective requirements may name members", ScopeId{},
                      requirement.id);
    }
  }

  for (const auto& entry : per_scope) {
    if (entry.second > limits.max_requirements_per_scope) {
      diagnostics.add(Code::kTooManyRequirements,
                      "scope '" + std::string(entry.first) + "' declares " +
                          std::to_string(entry.second) + " requirements, above the bound " +
                          std::to_string(limits.max_requirements_per_scope));
    }
  }
  for (const auto& entry : kinds_per_scope) {
    if (entry.second.size() > limits.max_distinct_kinds_per_scope) {
      diagnostics.add(Code::kTooManyRequirements,
                      "scope '" + std::string(entry.first) + "' declares " +
                          std::to_string(entry.second.size()) + " distinct kinds, above the bound " +
                          std::to_string(limits.max_distinct_kinds_per_scope));
    }
  }
}

}  // namespace

ValidationResult validate_contract_body(const ContractBody& body, const JsonDecodeOptions& options) {
  (void)options;
  ValidationResult result;
  const ContractLimits& limits = default_contract_limits();
  validate_body(body, limits, result.diagnostics);

  // Derived identities must agree with the content, otherwise a caller could
  // present a contract whose identity does not describe it.
  for (const Requirement& requirement : body.requirements) {
    if (requirement.id.is_zero()) {
      continue;
    }
    const RequirementId derived = derive_requirement_id(requirement);
    if (derived != requirement.id) {
      result.diagnostics.add(Code::kContractDigestMismatch,
                             "requirement identity does not match its content", ScopeId{},
                             requirement.id);
    }
  }
  result.ok = !result.diagnostics.has_errors();
  return result;
}

ValidationResult validate_contract(const Contract& contract, const JsonDecodeOptions& options) {
  ValidationResult result = validate_contract_body(contract.body, options);
  const Digest computed = body_digest(contract.body);
  if (computed != contract.digest) {
    result.diagnostics.add(Code::kContractDigestMismatch,
                           "contract digest does not match the canonical body bytes");
  }
  if (contract.body.contract_id.is_zero()) {
    // A body with no identity is a fragment, not a contract: it is publishable
    // only after canonicalising, which derives the identity from the content.
    result.diagnostics.add(Code::kZeroIdentity,
                           "contract identity is not set; canonicalise the body first");
  } else {
    const ContractId derived = derive_contract_id(contract.body.workload.id, computed);
    if (derived != contract.body.contract_id) {
      result.diagnostics.add(Code::kContractDigestMismatch,
                             "contract identity does not match the workload and body digest");
    }
  }
  if (contract.has_supersedes()) {
    if (contract.supersedes.value >= contract.body.generation.value) {
      result.diagnostics.add(Code::kStaleGeneration,
                             "superseded generation must be below the contract generation");
    }
    if (contract.supersedes_digest == Digest{}) {
      result.diagnostics.add(Code::kContractSchema,
                             "a superseding contract must carry the superseded digest");
    }
  } else if (contract.supersedes_digest != Digest{}) {
    result.diagnostics.add(Code::kContractSchema,
                           "superseded digest present without a superseded generation");
  }
  result.ok = !result.diagnostics.has_errors();
  return result;
}

bool canonicalize(Contract& contract) {
  ContractBody& body = contract.body;

  // Scopes are ordered by name and then rank, so two bodies that declare the
  // same scopes produce the same canonical bytes whatever order they arrived in.
  std::sort(body.scopes.begin(), body.scopes.end(), [](const Scope& a, const Scope& b) {
    if (a.name != b.name) {
      return a.name < b.name;
    }
    return a.rank < b.rank;
  });

  // Requirement identity is a function of the requirement content, so it is
  // recomputed here rather than carried in from the input.
  for (Requirement& requirement : body.requirements) {
    std::sort(requirement.attributes.begin(), requirement.attributes.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    std::sort(requirement.members.begin(), requirement.members.end());
    requirement.id = derive_requirement_id(requirement);
  }
  std::sort(body.requirements.begin(), body.requirements.end(), requirement_precedes);

  contract.digest = body_digest(body);
  body.contract_id = derive_contract_id(body.workload.id, contract.digest);
  // Recomputing the digest after the identity is assigned must be a no-op: the
  // digest covers the body with the identity field masked out, so assigning the
  // identity cannot change it. validate_contract asserts exactly this.
  contract.digest = body_digest(body);
  return true;
}

}  // namespace wnc
