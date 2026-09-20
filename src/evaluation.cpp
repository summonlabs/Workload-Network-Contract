// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/evaluation.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <map>

#include "wnc/hash.hpp"

namespace wnc {
namespace {

constexpr std::size_t kMaxEvidenceEntries = 4096;
constexpr std::uint64_t kMaxEvidenceMillis = 1ull << 60;
constexpr std::uint64_t kMaxNumericParameter = 1000000000000000ull;

std::string join_path(std::string_view path, std::string_view field) {
  std::string out(path);
  if (!out.empty()) {
    out.push_back('.');
  }
  out.append(field);
  return out;
}

const Json* member(const JsonObject& object, std::string_view key) {
  const auto it = object.find(key);
  if (it == object.end()) {
    return nullptr;
  }
  return &it->second;
}

bool read_optional_real(const JsonObject& object, std::string_view field, std::string_view path,
                        std::optional<double>& out, Code& code, std::string& message) {
  const Json* value = member(object, field);
  if (value == nullptr) {
    return true;
  }
  if (!value->is_number()) {
    code = Code::kJsonWrongType;
    message = join_path(path, field) + " must be a number";
    return false;
  }
  const double number = value->as_real();
  if (!std::isfinite(number) || number < 0.0 || number > static_cast<double>(kMaxNumericParameter)) {
    code = Code::kValueOutOfRange;
    message = join_path(path, field) + " is outside the permitted range";
    return false;
  }
  out = number;
  return true;
}

bool read_optional_bool(const JsonObject& object, std::string_view field, std::string_view path,
                        std::optional<bool>& out, Code& code, std::string& message) {
  const Json* value = member(object, field);
  if (value == nullptr) {
    return true;
  }
  if (!value->is_bool()) {
    code = Code::kJsonWrongType;
    message = join_path(path, field) + " must be a boolean";
    return false;
  }
  out = value->as_bool();
  return true;
}

bool read_optional_string(const JsonObject& object, std::string_view field, std::string_view path,
                          std::optional<std::string>& out, bool allow_empty, Code& code,
                          std::string& message) {
  const Json* value = member(object, field);
  if (value == nullptr) {
    return true;
  }
  if (!value->is_string()) {
    code = Code::kJsonWrongType;
    message = join_path(path, field) + " must be a string";
    return false;
  }
  if (value->as_string().size() > kMaxStringBytes) {
    code = Code::kJsonStringTooLong;
    message = join_path(path, field) + " exceeds its byte bound";
    return false;
  }
  if (!allow_empty && value->as_string().empty()) {
    code = Code::kValueOutOfRange;
    message = join_path(path, field) + " must not be empty";
    return false;
  }
  out = value->as_string();
  return true;
}

void add_optional_real(Json& object, std::string_view field, const std::optional<double>& value) {
  if (value.has_value()) {
    object.set(std::string(field), *value);
  }
}

void add_optional_string(Json& object, std::string_view field,
                         const std::optional<std::string>& value) {
  if (value.has_value()) {
    object.set(std::string(field), *value);
  }
}

void add_optional_bool(Json& object, std::string_view field, const std::optional<bool>& value) {
  if (value.has_value()) {
    object.set(std::string(field), *value);
  }
}

Json candidate_to_json(const Candidate& candidate) {
  Json out;
  add_optional_real(out, "min_bandwidth", candidate.min_bandwidth);
  add_optional_real(out, "max_latency", candidate.max_latency);
  add_optional_real(out, "max_jitter", candidate.max_jitter);
  add_optional_real(out, "max_loss", candidate.max_loss);
  add_optional_string(out, "locality", candidate.locality);
  add_optional_real(out, "path_diversity", candidate.path_diversity);
  add_optional_real(out, "failure_domain_separation", candidate.failure_domain_separation);
  add_optional_string(out, "security_class", candidate.security_class);
  add_optional_real(out, "traffic_priority", candidate.traffic_priority);
  add_optional_real(out, "burst_allowance", candidate.burst_allowance);
  add_optional_bool(out, "collective_supported", candidate.collective_supported);
  add_optional_bool(out, "checkpoint_isolation", candidate.checkpoint_isolation);
  add_optional_string(out, "disaggregated_affinity", candidate.disaggregated_affinity);
  add_optional_string(out, "maintenance_tolerance", candidate.maintenance_tolerance);
  if (!candidate.attributes.empty()) {
    JsonArray attributes;
    attributes.reserve(candidate.attributes.size());
    for (const auto& attribute : candidate.attributes) {
      Json item;
      item.set("name", attribute.first);
      item.set("value", attribute.second);
      attributes.push_back(std::move(item));
    }
    out.set("attributes", Json(std::move(attributes)));
  }
  return out;
}

Code decode_candidate(const Json& value, Candidate& candidate) {
  if (!value.is_object()) {
    return Code::kJsonNotAnObject;
  }
  const JsonObject& object = value.object();
  Code code = Code::kOk;
  std::string message;
  if (!read_optional_real(object, "min_bandwidth", "candidate", candidate.min_bandwidth, code,
                          message) ||
      !read_optional_real(object, "max_latency", "candidate", candidate.max_latency, code, message) ||
      !read_optional_real(object, "max_jitter", "candidate", candidate.max_jitter, code, message) ||
      !read_optional_real(object, "max_loss", "candidate", candidate.max_loss, code, message) ||
      !read_optional_real(object, "path_diversity", "candidate", candidate.path_diversity, code,
                          message) ||
      !read_optional_real(object, "failure_domain_separation", "candidate",
                          candidate.failure_domain_separation, code, message) ||
      !read_optional_real(object, "traffic_priority", "candidate", candidate.traffic_priority, code,
                          message) ||
      !read_optional_real(object, "burst_allowance", "candidate", candidate.burst_allowance, code,
                          message) ||
      !read_optional_string(object, "locality", "candidate", candidate.locality, false, code,
                            message) ||
      !read_optional_string(object, "security_class", "candidate", candidate.security_class, false,
                            code, message) ||
      !read_optional_string(object, "disaggregated_affinity", "candidate",
                            candidate.disaggregated_affinity, false, code, message) ||
      !read_optional_string(object, "maintenance_tolerance", "candidate",
                            candidate.maintenance_tolerance, false, code, message) ||
      !read_optional_bool(object, "collective_supported", "candidate", candidate.collective_supported,
                          code, message) ||
      !read_optional_bool(object, "checkpoint_isolation", "candidate", candidate.checkpoint_isolation,
                          code, message)) {
    return code;
  }
  const Json* attributes = member(object, "attributes");
  if (attributes != nullptr) {
    if (!attributes->is_array()) {
      return Code::kJsonWrongType;
    }
    if (attributes->size() > kMaxAttributesPerRequirement) {
      return Code::kTooManyAttributes;
    }
    for (std::size_t i = 0; i < attributes->size(); ++i) {
      const Json* item = attributes->at(i);
      if (item == nullptr || !item->is_object()) {
        return Code::kJsonWrongType;
      }
      const Json* name = member(item->object(), "name");
      const Json* attribute_value = member(item->object(), "value");
      if (name == nullptr || attribute_value == nullptr || !name->is_string() ||
          !attribute_value->is_string()) {
        return Code::kJsonWrongType;
      }
      if (name->as_string().size() > kMaxStringBytes ||
          attribute_value->as_string().size() > kMaxStringBytes) {
        return Code::kJsonStringTooLong;
      }
      candidate.attributes.emplace_back(name->as_string(), attribute_value->as_string());
    }
    std::sort(candidate.attributes.begin(), candidate.attributes.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    for (std::size_t i = 1; i < candidate.attributes.size(); ++i) {
      if (candidate.attributes[i].first == candidate.attributes[i - 1].first) {
        return Code::kDuplicateRequirement;
      }
    }
  }
  return Code::kOk;
}

// Comparison helper for a ceiling observable: satisfied when the observed value
// is at or below the requirement target.
RequirementDecision ceiling(const std::optional<double>& observed, const Requirement& requirement,
                            std::string_view dimension) {
  RequirementDecision decision;
  if (!observed.has_value()) {
    decision.satisfaction = Satisfaction::kUnknown;
    decision.reason_code = Code::kEvaluationMissingDimension;
    decision.reason = std::string(dimension) + " was not supplied by the evidence";
    return decision;
  }
  decision.observed = *observed;
  if (*observed <= requirement.target) {
    decision.satisfaction = Satisfaction::kSatisfied;
    decision.reason_code = Code::kOk;
    decision.reason = std::string(dimension) + " is within the required bound";
  } else if (*observed <= requirement.minimum) {
    // Between the strict bound and the weakest acceptable bound. A preferred
    // requirement is still satisfied here; a required requirement is not, and
    // the difference is reported rather than hidden.
    decision.satisfaction = requirement.strength == RequirementStrength::kPreferred
                                ? Satisfaction::kSatisfied
                                : Satisfaction::kUnsatisfied;
    decision.reason_code = Code::kOk;
    decision.reason = std::string(dimension) +
                      (requirement.strength == RequirementStrength::kPreferred
                           ? " is within the preferred band"
                           : " exceeds the required bound but is within the acceptable band");
  } else {
    decision.satisfaction = Satisfaction::kUnsatisfied;
    decision.reason_code = Code::kOk;
    decision.reason = std::string(dimension) + " exceeds the acceptable band";
  }
  return decision;
}

RequirementDecision floor_value(const std::optional<double>& observed,
                                const Requirement& requirement, std::string_view dimension) {
  RequirementDecision decision;
  if (!observed.has_value()) {
    decision.satisfaction = Satisfaction::kUnknown;
    decision.reason_code = Code::kEvaluationMissingDimension;
    decision.reason = std::string(dimension) + " was not supplied by the evidence";
    return decision;
  }
  decision.observed = *observed;
  if (*observed >= requirement.target) {
    decision.satisfaction = Satisfaction::kSatisfied;
    decision.reason_code = Code::kOk;
    decision.reason = std::string(dimension) + " meets the required floor";
  } else if (*observed >= requirement.minimum) {
    decision.satisfaction = requirement.strength == RequirementStrength::kPreferred
                                ? Satisfaction::kSatisfied
                                : Satisfaction::kUnsatisfied;
    decision.reason_code = Code::kOk;
    decision.reason = std::string(dimension) +
                      (requirement.strength == RequirementStrength::kPreferred
                           ? " meets the preferred floor"
                           : " is below the required floor but above the acceptable one");
  } else {
    decision.satisfaction = Satisfaction::kUnsatisfied;
    decision.reason_code = Code::kOk;
    decision.reason = std::string(dimension) + " is below the acceptable floor";
  }
  return decision;
}

RequirementDecision textual(const std::optional<std::string>& observed, const Requirement& requirement,
                            std::string_view dimension, bool exact) {
  RequirementDecision decision;
  if (!observed.has_value() || observed->empty()) {
    decision.satisfaction = Satisfaction::kUnknown;
    decision.reason_code = Code::kEvaluationMissingDimension;
    decision.reason = std::string(dimension) + " was not supplied by the evidence";
    return decision;
  }
  const auto matches = [&](std::string_view wanted) {
    return exact ? *observed == wanted : observed->find(wanted) != std::string::npos;
  };
  if (matches(requirement.target_text())) {
    decision.satisfaction = Satisfaction::kSatisfied;
    decision.reason_code = Code::kOk;
    decision.reason = std::string(dimension) + " matches the required value";
  } else if (requirement.strength != RequirementStrength::kRequired &&
             !requirement.preferred_text().empty() && matches(requirement.preferred_text())) {
    decision.satisfaction = Satisfaction::kSatisfied;
    decision.reason_code = Code::kOk;
    decision.reason = std::string(dimension) + " matches the preferred value";
  } else {
    decision.satisfaction = Satisfaction::kUnsatisfied;
    decision.reason_code = Code::kOk;
    decision.reason = std::string(dimension) + " does not match the required value";
  }
  return decision;
}

}  // namespace

const std::string* Candidate::attribute(std::string_view name) const {
  for (const auto& attribute : attributes) {
    if (attribute.first == name) {
      return &attribute.second;
    }
  }
  return nullptr;
}

bool Candidate::has_any_dimension() const noexcept {
  return min_bandwidth.has_value() || max_latency.has_value() || max_jitter.has_value() ||
         max_loss.has_value() || locality.has_value() || path_diversity.has_value() ||
         failure_domain_separation.has_value() || security_class.has_value() ||
         traffic_priority.has_value() || burst_allowance.has_value() ||
         collective_supported.has_value() || checkpoint_isolation.has_value() ||
         disaggregated_affinity.has_value() || maintenance_tolerance.has_value() ||
         !attributes.empty();
}

const EvidenceEntry* EvidenceSet::find(std::string_view scope) const {
  for (const EvidenceEntry& entry : entries) {
    if (entry.scope == scope) {
      return &entry;
    }
  }
  return nullptr;
}

bool EvidenceSet::all_current() const noexcept {
  for (const EvidenceEntry& entry : entries) {
    if (entry.freshness != EvidenceFreshness::kCurrent) {
      return false;
    }
  }
  return true;
}

Digest evidence_digest(const EvidenceSet& evidence) noexcept {
  return digest_domain_generation("wnc/v1/evidence", evidence_to_json(evidence).dump(),
                                  evidence.generation.value);
}

EvidenceId derive_evidence_id(const Digest& digest) noexcept {
  const std::string digest_hex = hex_encode(digest);
  const std::array<std::string_view, 2> parts = {std::string_view("wnc/v1/evidence-id"), digest_hex};
  return EvidenceId::from_digest(sha256_parts(std::span<const std::string_view>(parts.data(), parts.size())));
}

Json evidence_to_json(const EvidenceSet& evidence) {
  Json out;
  out.set("schema_version", static_cast<std::int64_t>(kSchemaVersion));
  out.set("evidence_id", evidence.evidence_id.str());
  out.set("evidence_generation", static_cast<std::int64_t>(evidence.generation.value));
  out.set("epoch", static_cast<std::int64_t>(evidence.epoch));
  out.set("publisher", evidence.publisher.str());
  out.set("produced_at_millis", static_cast<std::int64_t>(evidence.produced_at_millis));
  JsonArray entries;
  entries.reserve(evidence.entries.size());
  for (const EvidenceEntry& entry : evidence.entries) {
    Json item;
    item.set("scope", entry.scope);
    item.set("id", entry.id.str());
    item.set("publisher", entry.publisher.str());
    item.set("generation", static_cast<std::int64_t>(entry.generation.value));
    // An entry that has never been stamped by a coordinator carries the zero
    // incarnation, which is not a value: it is omitted rather than written as an
    // unparseable placeholder, and the decoder then leaves it zero too.
    if (!entry.captured_by.is_zero()) {
      item.set("captured_by", entry.captured_by.str());
    }
    item.set("epoch", static_cast<std::int64_t>(entry.epoch));
    item.set("produced_at_millis", static_cast<std::int64_t>(entry.produced_at_millis));
    item.set("freshness", std::string(freshness_token(entry.freshness)));
    item.set("candidate", candidate_to_json(entry.candidate));
    entries.push_back(std::move(item));
  }
  out.set("entries", Json(std::move(entries)));
  return out;
}

EvidenceDecodeResult evidence_from_json(const Json& value) {
  EvidenceDecodeResult result;
  if (!value.is_object()) {
    result.code = Code::kJsonNotAnObject;
    result.message = "evidence document must be an object";
    return result;
  }
  const JsonObject& object = value.object();
  EvidenceSet evidence;

  const Json* generation = member(object, "evidence_generation");
  if (generation == nullptr || !generation->is_int() || generation->as_int() < 1) {
    result.code = Code::kEvidenceGenerationBackwards;
    result.message = "evidence_generation must be at least 1";
    return result;
  }
  evidence.generation.value = static_cast<std::uint64_t>(generation->as_int());

  const Json* epoch = member(object, "epoch");
  if (epoch != nullptr) {
    if (!epoch->is_int() || epoch->as_int() < 0) {
      result.code = Code::kJsonWrongType;
      result.message = "epoch must be a non negative integer";
      return result;
    }
    evidence.epoch = static_cast<std::uint64_t>(epoch->as_int());
  }
  const Json* produced = member(object, "produced_at_millis");
  if (produced != nullptr) {
    if (!produced->is_int() || produced->as_int() < 0 ||
        static_cast<std::uint64_t>(produced->as_int()) > kMaxEvidenceMillis) {
      result.code = Code::kValueOutOfRange;
      result.message = "produced_at_millis is outside the permitted range";
      return result;
    }
    evidence.produced_at_millis = static_cast<std::uint64_t>(produced->as_int());
  }
  const Json* publisher = member(object, "publisher");
  if (publisher != nullptr) {
    if (!publisher->is_string()) {
      result.code = Code::kJsonWrongType;
      result.message = "publisher must be a string";
      return result;
    }
    const std::optional<PublisherId> parsed = PublisherId::parse(publisher->as_string());
    if (!parsed.has_value()) {
      result.code = Code::kJsonWrongType;
      result.message = "publisher must be a 64 character identifier";
      return result;
    }
    evidence.publisher = *parsed;
  }

  const Json* entries = member(object, "entries");
  if (entries == nullptr || !entries->is_array()) {
    result.code = Code::kJsonMissingField;
    result.message = "evidence.entries must be an array";
    return result;
  }
  if (entries->size() > kMaxEvidenceEntries) {
    result.code = Code::kEvidenceTooManyEntries;
    result.message = "evidence declares more entries than the bound permits";
    return result;
  }
  evidence.entries.reserve(entries->size());
  for (std::size_t i = 0; i < entries->size(); ++i) {
    const Json* item = entries->at(i);
    if (item == nullptr || !item->is_object()) {
      result.code = Code::kJsonWrongType;
      result.message = "evidence entries must be objects";
      return result;
    }
    const JsonObject& entry_object = item->object();
    EvidenceEntry entry;
    const Json* scope = member(entry_object, "scope");
    if (scope == nullptr || !scope->is_string() || scope->as_string().empty() ||
        scope->as_string().size() > kMaxStringBytes) {
      result.code = Code::kJsonWrongType;
      result.message = "evidence entry scope must be a non empty bounded string";
      return result;
    }
    entry.scope = scope->as_string();

    const Json* entry_generation = member(entry_object, "generation");
    if (entry_generation != nullptr) {
      if (!entry_generation->is_int() || entry_generation->as_int() < 0) {
        result.code = Code::kJsonWrongType;
        result.message = "evidence entry generation must be a non negative integer";
        return result;
      }
      entry.generation.value = static_cast<std::uint64_t>(entry_generation->as_int());
    }
    const Json* captured = member(entry_object, "captured_by");
    if (captured != nullptr) {
      if (!captured->is_string()) {
        result.code = Code::kJsonWrongType;
        result.message = "captured_by must be a string";
        return result;
      }
      const std::optional<Incarnation> parsed = Incarnation::parse(captured->as_string());
      if (!parsed.has_value()) {
        result.code = Code::kJsonWrongType;
        result.message = "captured_by must be a 16 byte base64url incarnation";
        return result;
      }
      entry.captured_by = *parsed;
    }
    const Json* entry_epoch = member(entry_object, "epoch");
    if (entry_epoch != nullptr) {
      if (!entry_epoch->is_int() || entry_epoch->as_int() < 0) {
        result.code = Code::kJsonWrongType;
        result.message = "evidence entry epoch must be a non negative integer";
        return result;
      }
      entry.epoch = static_cast<std::uint64_t>(entry_epoch->as_int());
    }
    const Json* entry_produced = member(entry_object, "produced_at_millis");
    if (entry_produced != nullptr) {
      if (!entry_produced->is_int() || entry_produced->as_int() < 0 ||
          static_cast<std::uint64_t>(entry_produced->as_int()) > kMaxEvidenceMillis) {
        result.code = Code::kValueOutOfRange;
        result.message = "evidence entry produced_at_millis is outside the permitted range";
        return result;
      }
      entry.produced_at_millis = static_cast<std::uint64_t>(entry_produced->as_int());
    }
    const Json* entry_publisher = member(entry_object, "publisher");
    if (entry_publisher != nullptr) {
      if (!entry_publisher->is_string()) {
        result.code = Code::kJsonWrongType;
        result.message = "evidence entry publisher must be a string";
        return result;
      }
      const std::optional<PublisherId> parsed = PublisherId::parse(entry_publisher->as_string());
      if (!parsed.has_value()) {
        result.code = Code::kJsonWrongType;
        result.message = "evidence entry publisher must be a 64 character identifier";
        return result;
      }
      entry.publisher = *parsed;
    }
    const Json* candidate = member(entry_object, "candidate");
    if (candidate == nullptr) {
      result.code = Code::kJsonMissingField;
      result.message = "evidence entry requires a candidate object";
      return result;
    }
    const Code candidate_code = decode_candidate(*candidate, entry.candidate);
    if (candidate_code != Code::kOk) {
      result.code = candidate_code;
      result.message = "evidence entry candidate was rejected";
      return result;
    }
    // Freshness is decoded as written, because it is part of the bytes the
    // evidence identity covers: forcing it here would make the identity disagree
    // with its own document and every durable record would be refused on
    // recovery. It is not a claim the coordinator trusts: a restored entry is
    // re-stamped as revalidation-required when it is loaded, and an evaluation
    // reads that stamped value rather than this one.
    const Json* entry_freshness = member(entry_object, "freshness");
    if (entry_freshness != nullptr) {
      if (!entry_freshness->is_string()) {
        result.code = Code::kJsonWrongType;
        result.message = "evidence entry freshness must be a string";
        return result;
      }
      const std::optional<EvidenceFreshness> parsed =
          parse_freshness(entry_freshness->as_string());
      if (!parsed.has_value()) {
        result.code = Code::kJsonWrongType;
        result.message = "evidence entry freshness '" + entry_freshness->as_string() +
                         "' is not a defined freshness";
        return result;
      }
      entry.freshness = *parsed;
    }
    evidence.entries.push_back(std::move(entry));
  }

  const Digest digest = evidence_digest(evidence);
  evidence.evidence_id = derive_evidence_id(digest);
  const Json* declared_id = member(object, "evidence_id");
  // A declared identity of all zeros means "not stated": the identity is derived
  // from the content. A non-zero declaration must match the content exactly.
  if (declared_id != nullptr && declared_id->is_string() &&
      declared_id->as_string() == std::string(kSha256HexChars, '0')) {
    declared_id = nullptr;
  }
  if (declared_id != nullptr) {
    if (!declared_id->is_string()) {
      result.code = Code::kJsonWrongType;
      result.message = "evidence_id must be a string";
      return result;
    }
    const std::optional<EvidenceId> parsed = EvidenceId::parse(declared_id->as_string());
    if (!parsed.has_value() || *parsed != evidence.evidence_id) {
      result.code = Code::kContractDigestMismatch;
      result.message = "declared evidence_id does not match the canonical evidence bytes";
      return result;
    }
  }

  result.ok = true;
  result.evidence = std::move(evidence);
  return result;
}

EvidenceDecodeResult evidence_from_text(std::string_view text) {
  JsonDecodeResult decoded = json_decode(text);
  if (!decoded.ok) {
    EvidenceDecodeResult failure;
    failure.code = decoded.code;
    failure.message = decoded.message;
    return failure;
  }
  return evidence_from_json(decoded.value);
}

EvidenceValidationResult validate_evidence(EvidenceSet& evidence, const ContractBody& body,
                                           const Incarnation& current, std::uint64_t now_millis,
                                           std::uint64_t max_age_millis) {
  EvidenceValidationResult result;
  std::map<std::string_view, const Scope*> scopes;
  for (const Scope& scope : body.scopes) {
    scopes.emplace(scope.name, &scope);
  }
  std::map<std::string_view, std::size_t> seen;
  for (EvidenceEntry& entry : evidence.entries) {
    if (scopes.find(entry.scope) == scopes.end()) {
      result.diagnostics.add(Code::kEvidenceUnknownScope,
                             "evidence references undeclared scope '" + entry.scope + "'");
    }
    if (!seen.emplace(entry.scope, 0).second) {
      result.diagnostics.add(Code::kEvidenceDuplicate,
                             "evidence repeats scope '" + entry.scope + "'");
    }
    if (!entry.candidate.has_any_dimension()) {
      result.diagnostics.add(Code::kEvaluationMissingDimension,
                             "evidence for scope '" + entry.scope + "' carries no dimension");
    }
    if (entry.captured_by != current || entry.epoch != evidence.epoch) {
      entry.freshness = EvidenceFreshness::kRevalidationRequired;
      result.stale_scopes.push_back(entry.scope);
    } else if (max_age_millis > 0 && now_millis > entry.produced_at_millis &&
               now_millis - entry.produced_at_millis > max_age_millis) {
      entry.freshness = EvidenceFreshness::kExpired;
      result.stale_scopes.push_back(entry.scope);
    } else {
      entry.freshness = EvidenceFreshness::kCurrent;
    }
  }
  std::sort(result.stale_scopes.begin(), result.stale_scopes.end());
  result.ok = !result.diagnostics.has_errors();
  return result;
}

RequirementDecision decide_requirement(const Requirement& requirement, const EvidenceEntry* entry,
                                       const Incarnation& current, std::uint64_t now_millis,
                                       std::uint64_t max_age_millis) {
  RequirementDecision decision;
  if (requirement.strength == RequirementStrength::kInformational) {
    decision.satisfaction = Satisfaction::kNotApplicable;
    decision.reason_code = Code::kOk;
    decision.reason = "informational requirements are recorded but not evaluated";
    return decision;
  }
  if (entry == nullptr) {
    decision.satisfaction = Satisfaction::kUnknown;
    decision.reason_code = Code::kEvaluationNoEvidence;
    decision.reason = "no evidence covers scope '" + requirement.scope + "'";
    return decision;
  }
  if (entry->captured_by != current) {
    // Evidence captured by another incarnation is never current, whatever its
    // freshness field says.
    decision.satisfaction = Satisfaction::kUnknown;
    decision.reason_code = Code::kRevalidationRequired;
    decision.reason = "evidence for scope '" + requirement.scope +
                      "' was captured by another coordinator incarnation";
    return decision;
  }
  if (entry->freshness == EvidenceFreshness::kRevalidationRequired) {
    decision.satisfaction = Satisfaction::kUnknown;
    decision.reason_code = Code::kRevalidationRequired;
    decision.reason = "evidence for scope '" + requirement.scope +
                      "' was captured by an earlier coordinator incarnation and must be "
                      "re-established";
    return decision;
  }
  if (entry->freshness == EvidenceFreshness::kExpired) {
    decision.satisfaction = Satisfaction::kUnknown;
    decision.reason_code = Code::kEvidenceExpired;
    decision.reason = "evidence for scope '" + requirement.scope + "' is older than the permitted age";
    return decision;
  }
  if (entry->freshness == EvidenceFreshness::kStale) {
    decision.satisfaction = Satisfaction::kUnknown;
    decision.reason_code = Code::kEvidenceStale;
    decision.reason = "evidence for scope '" + requirement.scope + "' is stale";
    return decision;
  }
  (void)now_millis;
  (void)max_age_millis;

  const Candidate& candidate = entry->candidate;
  switch (requirement.kind) {
    case RequirementKind::kMinBandwidth:
      return floor_value(candidate.min_bandwidth, requirement, "available bandwidth");
    case RequirementKind::kMaxLatency:
      return ceiling(candidate.max_latency, requirement, "latency");
    case RequirementKind::kMaxJitter:
      return ceiling(candidate.max_jitter, requirement, "jitter");
    case RequirementKind::kMaxLoss:
      return ceiling(candidate.max_loss, requirement, "loss");
    case RequirementKind::kPathDiversity:
      return floor_value(candidate.path_diversity, requirement, "path diversity");
    case RequirementKind::kFailureDomainSeparation:
      return floor_value(candidate.failure_domain_separation, requirement,
                         "failure domain separation");
    case RequirementKind::kTrafficPriority:
      return floor_value(candidate.traffic_priority, requirement, "traffic priority");
    case RequirementKind::kBurstAllowance:
      return floor_value(candidate.burst_allowance, requirement, "burst allowance");
    case RequirementKind::kLocality:
      return textual(candidate.locality, requirement, "locality", true);
    case RequirementKind::kSecurityClass:
      return textual(candidate.security_class, requirement, "security class", true);
    case RequirementKind::kDisaggregatedAffinity:
      return textual(candidate.disaggregated_affinity, requirement, "disaggregated affinity", true);
    case RequirementKind::kMaintenanceTolerance:
      return textual(candidate.maintenance_tolerance, requirement, "maintenance tolerance", true);
    case RequirementKind::kCheckpointIsolation: {
      if (!candidate.checkpoint_isolation.has_value()) {
        decision.satisfaction = Satisfaction::kUnknown;
        decision.reason_code = Code::kEvaluationMissingDimension;
        decision.reason = "checkpoint isolation was not supplied by the evidence";
        return decision;
      }
      const bool wanted = requirement.value != "none" && !requirement.value.empty();
      const bool satisfied = wanted ? *candidate.checkpoint_isolation
                                    : !*candidate.checkpoint_isolation;
      decision.satisfaction = satisfied ? Satisfaction::kSatisfied : Satisfaction::kUnsatisfied;
      decision.reason_code = Code::kOk;
      decision.reason = satisfied ? "checkpoint isolation matches the requirement"
                                  : "checkpoint isolation does not match the requirement";
      return decision;
    }
    case RequirementKind::kCollective: {
      if (!candidate.collective_supported.has_value()) {
        decision.satisfaction = Satisfaction::kUnknown;
        decision.reason_code = Code::kEvaluationMissingDimension;
        decision.reason = "collective support was not supplied by the evidence";
        return decision;
      }
      if (requirement.value == "unsupported") {
        decision.satisfaction = *candidate.collective_supported ? Satisfaction::kUnsatisfied
                                                               : Satisfaction::kSatisfied;
        decision.reason_code = Code::kOk;
        decision.reason = "collective support is required to be absent";
        return decision;
      }
      if (!*candidate.collective_supported) {
        decision.satisfaction = Satisfaction::kUnsatisfied;
        decision.reason_code = Code::kOk;
        decision.reason = "the scope does not support collective operations";
        return decision;
      }
      if (requirement.members.empty()) {
        decision.satisfaction = Satisfaction::kSatisfied;
        decision.reason_code = Code::kOk;
        decision.reason = "collective operations are supported for the scope";
        return decision;
      }
      // Member presence is reported by the evidence attribute set. A member the
      // evidence does not mention is unknown, not satisfied.
      std::size_t matched = 0;
      bool missing = false;
      for (const RequirementId& member : requirement.members) {
        const std::string* present = candidate.attribute("member." + member.str());
        if (present == nullptr) {
          missing = true;
          continue;
        }
        if (*present == "present") {
          ++matched;
        }
      }
      if (matched == requirement.members.size()) {
        decision.satisfaction = Satisfaction::kSatisfied;
        decision.reason_code = Code::kOk;
        decision.reason = "every collective member is present in the scope";
        return decision;
      }
      if (missing) {
        decision.satisfaction = Satisfaction::kUnknown;
        decision.reason_code = Code::kEvaluationMissingDimension;
        decision.reason = "evidence does not report every collective member";
        return decision;
      }
      decision.satisfaction = Satisfaction::kUnsatisfied;
      decision.reason_code = Code::kOk;
      decision.reason = "at least one collective member is absent from the scope";
      return decision;
    }
    case RequirementKind::kAttribute: {
      const std::string* value = candidate.attribute(requirement.key);
      if (value == nullptr) {
        decision.satisfaction = Satisfaction::kUnknown;
        decision.reason_code = Code::kEvaluationMissingDimension;
        decision.reason = "attribute '" + requirement.key + "' was not supplied by the evidence";
        return decision;
      }
      if (*value == requirement.value) {
        decision.satisfaction = Satisfaction::kSatisfied;
        decision.reason_code = Code::kOk;
        decision.reason = "attribute matches the requirement";
      } else {
        decision.satisfaction = Satisfaction::kUnsatisfied;
        decision.reason_code = Code::kOk;
        decision.reason = "attribute does not match the requirement";
      }
      return decision;
    }
  }
  decision.satisfaction = Satisfaction::kUnknown;
  decision.reason_code = Code::kInternalInvariant;
  decision.reason = "requirement kind has no decision rule";
  return decision;
}

const RequirementEvaluation* ContractEvaluation::find(std::string_view scope,
                                                      RequirementKind kind) const {
  for (const RequirementEvaluation& entry : requirements) {
    if (entry.scope == scope && entry.kind == kind) {
      return &entry;
    }
  }
  return nullptr;
}

Satisfaction aggregate_satisfaction(const std::vector<RequirementEvaluation>& requirements) {
  bool any_unknown_required = false;
  bool any_required = false;
  for (const RequirementEvaluation& entry : requirements) {
    if (entry.strength != RequirementStrength::kRequired) {
      continue;
    }
    any_required = true;
    if (entry.satisfaction == Satisfaction::kUnsatisfied) {
      return Satisfaction::kUnsatisfied;
    }
    if (entry.satisfaction == Satisfaction::kUnknown) {
      any_unknown_required = true;
    }
  }
  if (any_unknown_required) {
    return Satisfaction::kUnknown;
  }
  if (!any_required) {
    return Satisfaction::kNotApplicable;
  }
  return Satisfaction::kSatisfied;
}

EvaluationResult evaluate_contract(const Contract& contract, const EvidenceSet& evidence,
                                   const Incarnation& current, std::uint64_t now_millis,
                                   std::uint64_t max_age_millis) {
  EvaluationResult result;
  ContractEvaluation evaluation;
  evaluation.workload = contract.body.workload.id;
  evaluation.contract = contract.body.contract_id;
  evaluation.contract_generation = contract.body.generation;
  evaluation.contract_digest = contract.digest;
  evaluation.policy_generation = contract.body.policy_generation;
  evaluation.evidence_generation = evidence.generation;
  evaluation.evaluated_by = current;
  evaluation.epoch = evidence.epoch;
  evaluation.evaluated_at_millis = now_millis;

  // Verdicts are emitted in canonical requirement order regardless of the order
  // the body happened to arrive in.
  std::vector<const Requirement*> ordered;
  ordered.reserve(contract.body.requirements.size());
  for (const Requirement& requirement : contract.body.requirements) {
    ordered.push_back(&requirement);
  }
  std::sort(ordered.begin(), ordered.end(), [](const Requirement* a, const Requirement* b) {
    return requirement_precedes(*a, *b);
  });

  evaluation.requirements.reserve(ordered.size());
  for (const Requirement* requirement_ptr : ordered) {
    const Requirement& requirement = *requirement_ptr;
    const EvidenceEntry* entry = evidence.find(requirement.scope);
    const RequirementDecision decision =
        decide_requirement(requirement, entry, current, now_millis, max_age_millis);

    RequirementEvaluation item;
    item.requirement = requirement.id;
    item.scope = requirement.scope;
    item.kind = requirement.kind;
    item.strength = requirement.strength;
    item.satisfaction = decision.satisfaction;
    item.reason_code = decision.reason_code;
    item.reason = decision.reason;
    item.observed = decision.observed;
    if (entry != nullptr) {
      item.evidence = entry->id;
      item.evidence_generation = entry->generation;
      item.freshness = entry->freshness;
    }
    evaluation.requirements.push_back(std::move(item));

    switch (item.strength) {
      case RequirementStrength::kRequired:
        ++evaluation.summary.required_total;
        if (item.satisfaction == Satisfaction::kSatisfied) {
          ++evaluation.summary.required_satisfied;
        } else if (item.satisfaction == Satisfaction::kUnsatisfied) {
          ++evaluation.summary.required_unsatisfied;
        } else {
          ++evaluation.summary.required_unknown;
        }
        break;
      case RequirementStrength::kPreferred:
        if (item.satisfaction == Satisfaction::kSatisfied) {
          ++evaluation.summary.preferred_satisfied;
        } else if (item.satisfaction == Satisfaction::kUnsatisfied) {
          ++evaluation.summary.preferred_unsatisfied;
        } else {
          ++evaluation.summary.preferred_unknown;
        }
        break;
      case RequirementStrength::kInformational:
        ++evaluation.summary.informational;
        break;
    }
    if (item.satisfaction == Satisfaction::kNotApplicable) {
      ++evaluation.summary.not_applicable;
    }
  }
  evaluation.aggregate = aggregate_satisfaction(evaluation.requirements);

  result.ok = true;
  result.evaluation = std::move(evaluation);
  return result;
}

}  // namespace wnc
