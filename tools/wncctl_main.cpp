// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// wncctl: inspection, validation, digest, diff, and composition tooling, plus a
// thin client for a running coordinator.
//
// The tool reads canonical JSON documents and prints deterministic text. It is
// the fast way to answer "what does this contract actually say, what is its
// identity, how does it differ from that other generation, and what did the
// coordinator decide about it". Exit codes: 0 success, 1 the document was
// refused (the reason is printed), 2 usage or I/O error, 3 transport error.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "wnc/composition.hpp"
#include "wnc/contract.hpp"
#include "wnc/error.hpp"
#include "wnc/evaluation.hpp"
#include "wnc/hash.hpp"
#include "wnc/json.hpp"
#include "wnc/policy.hpp"
#include "wnc/state.hpp"
#include "wnc/wire.hpp"

using namespace wnc;

namespace {

int usage() {
  std::fprintf(stderr,
               "usage: wncctl <command> [options]\n"
               "\n"
               "  seal     --body <file>          complete a body and print the contract\n"
               "  validate --contract <file> | --body <file> | --policy <file> | --evidence <file>\n"
               "  digest   --contract <file>\n"
               "  explain  --contract <file> [--evidence <file>]\n"
               "  diff     --before <file> --after <file>\n"
               "  compose  --base <file> --layer <file> [--layer <file> ...]\n"
               "  status   --host <host> --port <port>\n"
               "  evaluate --host <host> --port <port> --workload <id>\n"
               "\n"
               "Every command prints deterministic text on stdout and a refusal\n"
               "reason on stderr. Nothing is written outside the paths named.\n");
  return 2;
}

bool read_text_file(const std::string& path, std::string& out) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    std::fprintf(stderr, "cannot open %s\n", path.c_str());
    return false;
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  out = buffer.str();
  return true;
}

std::optional<std::string> option(int argc, char** argv, const std::string& name) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (name == argv[i]) {
      return std::string(argv[i + 1]);
    }
  }
  return std::nullopt;
}

std::vector<std::string> all_options(int argc, char** argv, const std::string& name) {
  std::vector<std::string> values;
  for (int i = 1; i + 1 < argc; ++i) {
    if (name == argv[i]) {
      values.emplace_back(argv[i + 1]);
    }
  }
  return values;
}

void print_diagnostics(const DiagnosticLog& log) {
  for (const Diagnostic& diagnostic : log.entries()) {
    std::fprintf(stderr, "  %s\n", diagnostic.render().c_str());
  }
  if (log.truncated()) {
    std::fprintf(stderr, "  (further reasons omitted at the diagnostic bound)\n");
  }
}

// Reads a contract body on its own, completes it with the identity and digest
// that follow from its content, and prints the finished envelope. This is how a
// contract is created: the author writes the requirements, never the identity.
int command_seal(const std::string& path) {
  std::string text;
  if (!read_text_file(path, text)) {
    return 2;
  }
  const JsonDecodeResult document = json_decode(text);
  if (!document.ok) {
    std::fprintf(stderr, "%s is not valid JSON: %s\n", path.c_str(), document.message.c_str());
    return 1;
  }
  Json envelope;
  if (document.value.find("body") != nullptr) {
    envelope = document.value;
  } else {
    envelope.set("body", document.value);
    envelope.set("digest", std::string(kSha256HexChars, '0'));
  }
  ContractDecodeResult decoded = contract_from_json(envelope);
  if (!decoded.ok) {
    std::fprintf(stderr, "body refused: %s: %s\n", std::string(code_token(decoded.code)).c_str(),
                 decoded.message.c_str());
    return 1;
  }
  // Canonicalising derives both the digest and the contract identity from the
  // content, so the printed document is publishable as it stands.
  (void)canonicalize(decoded.contract);
  const ValidationResult validation = validate_contract(decoded.contract);
  if (!validation.ok) {
    std::fprintf(stderr, "body is not a valid contract:\n");
    print_diagnostics(validation.diagnostics);
    return 1;
  }
  std::printf("%s\n", contract_to_json(decoded.contract).dump().c_str());
  std::fprintf(stderr, "workload=%s\n", decoded.contract.body.workload.id.str().c_str());
  std::fprintf(stderr, "contract=%s\n", decoded.contract.body.contract_id.str().c_str());
  std::fprintf(stderr, "digest=%s\n", hex_encode(decoded.contract.digest).c_str());
  std::fprintf(stderr, "requirements=%zu\n", decoded.contract.body.requirements.size());
  return 0;
}

int command_validate(int argc, char** argv) {
  if (const std::optional<std::string> path = option(argc, argv, "--body")) {
    std::string text;
    if (!read_text_file(*path, text)) {
      return 2;
    }
    const JsonDecodeResult document = json_decode(text);
    if (!document.ok) {
      std::fprintf(stderr, "%s is not valid JSON: %s\n", path->c_str(),
                   document.message.c_str());
      return 1;
    }
    Json envelope;
    envelope.set("body", document.value.find("body") != nullptr ? *document.value.find("body")
                                                                : document.value);
    envelope.set("digest", std::string(kSha256HexChars, '0'));
    ContractDecodeResult decoded = contract_from_json(envelope);
    if (!decoded.ok) {
      std::fprintf(stderr, "body refused: %s: %s\n",
                   std::string(code_token(decoded.code)).c_str(), decoded.message.c_str());
      return 1;
    }
    (void)canonicalize(decoded.contract);
    const ValidationResult validation = validate_contract(decoded.contract);
    if (!validation.ok) {
      std::fprintf(stderr, "body is not a valid contract:\n");
      print_diagnostics(validation.diagnostics);
      return 1;
    }
    std::printf("body valid\n");
    std::printf("digest=%s\n", hex_encode(decoded.contract.digest).c_str());
    std::printf("contract=%s\n", decoded.contract.body.contract_id.str().c_str());
    return 0;
  }
  if (const std::optional<std::string> path = option(argc, argv, "--contract")) {
    std::string text;
    if (!read_text_file(*path, text)) {
      return 2;
    }
    const ContractDecodeResult decoded = contract_from_text(text);
    if (!decoded.ok) {
      std::fprintf(stderr, "contract refused: %s: %s\n",
                   std::string(code_token(decoded.code)).c_str(), decoded.message.c_str());
      return 1;
    }
    const ValidationResult validation = validate_contract(decoded.contract);
    if (!validation.ok) {
      std::fprintf(stderr, "contract is not valid:\n");
      print_diagnostics(validation.diagnostics);
      return 1;
    }
    std::printf("contract valid\n");
    std::printf("workload=%s\n", decoded.contract.body.workload.id.str().c_str());
    std::printf("contract=%s\n", decoded.contract.body.contract_id.str().c_str());
    std::printf("digest=%s\n", hex_encode(decoded.contract.digest).c_str());
    std::printf("generation=%llu\n",
                static_cast<unsigned long long>(decoded.contract.body.generation.value));
    std::printf("scopes=%zu\n", decoded.contract.body.scopes.size());
    std::printf("requirements=%zu\n", decoded.contract.body.requirements.size());
    return 0;
  }
  if (const std::optional<std::string> path = option(argc, argv, "--policy")) {
    std::string text;
    if (!read_text_file(*path, text)) {
      return 2;
    }
    const PolicyDecodeResult decoded = policy_from_text(text);
    if (!decoded.ok) {
      std::fprintf(stderr, "policy refused: %s: %s\n",
                   std::string(code_token(decoded.code)).c_str(), decoded.message.c_str());
      return 1;
    }
    const PolicyValidationResult validation = validate_policy(decoded.policy);
    if (!validation.ok) {
      std::fprintf(stderr, "policy is not valid:\n");
      print_diagnostics(validation.diagnostics);
      return 1;
    }
    std::printf("policy valid\n");
    std::printf("policy=%s\n", decoded.policy.policy_id.str().c_str());
    std::printf("generation=%llu\n",
                static_cast<unsigned long long>(decoded.policy.generation.value));
    std::printf("rules=%zu\n", decoded.policy.rules.size());
    return 0;
  }
  if (const std::optional<std::string> path = option(argc, argv, "--evidence")) {
    std::string text;
    if (!read_text_file(*path, text)) {
      return 2;
    }
    const EvidenceDecodeResult decoded = evidence_from_text(text);
    if (!decoded.ok) {
      std::fprintf(stderr, "evidence refused: %s: %s\n",
                   std::string(code_token(decoded.code)).c_str(), decoded.message.c_str());
      return 1;
    }
    std::printf("evidence valid\n");
    std::printf("evidence=%s\n", decoded.evidence.evidence_id.str().c_str());
    std::printf("generation=%llu\n",
                static_cast<unsigned long long>(decoded.evidence.generation.value));
    std::printf("entries=%zu\n", decoded.evidence.entries.size());
    return 0;
  }
  return usage();
}

int command_digest(int argc, char** argv) {
  const std::optional<std::string> path = option(argc, argv, "--contract");
  if (!path.has_value()) {
    return usage();
  }
  std::string text;
  if (!read_text_file(*path, text)) {
    return 2;
  }
  const ContractDecodeResult decoded = contract_from_text(text);
  if (!decoded.ok) {
    std::fprintf(stderr, "contract refused: %s: %s\n",
                 std::string(code_token(decoded.code)).c_str(), decoded.message.c_str());
    return 1;
  }
  std::printf("digest=%s\n", hex_encode(decoded.contract.digest).c_str());
  std::printf("canonical_bytes=%zu\n", contract_to_json(decoded.contract).dump().size());
  return 0;
}

int command_explain(int argc, char** argv) {
  const std::optional<std::string> path = option(argc, argv, "--contract");
  if (!path.has_value()) {
    return usage();
  }
  std::string text;
  if (!read_text_file(*path, text)) {
    return 2;
  }
  const ContractDecodeResult decoded = contract_from_text(text);
  if (!decoded.ok) {
    std::fprintf(stderr, "contract refused: %s: %s\n",
                 std::string(code_token(decoded.code)).c_str(), decoded.message.c_str());
    return 1;
  }
  const Contract& contract = decoded.contract;
  std::printf("workload %s (%s) generation %llu\n", contract.body.workload.name.c_str(),
              contract.body.workload.id.str().c_str(),
              static_cast<unsigned long long>(contract.body.workload.generation.value));
  std::printf("contract %s generation %llu policy generation %llu\n",
              contract.body.contract_id.str().c_str(),
              static_cast<unsigned long long>(contract.body.generation.value),
              static_cast<unsigned long long>(contract.body.policy_generation.value));
  std::printf("version %u.%u.%u digest %s\n", contract.body.major, contract.body.minor,
              contract.body.patch, hex_encode(contract.digest).c_str());
  if (contract.has_supersedes()) {
    std::printf("supersedes generation %llu\n",
                static_cast<unsigned long long>(contract.supersedes.value));
  }
  std::printf("scopes:");
  for (const Scope& scope : contract.body.scopes) {
    std::printf(" %s", scope.name.c_str());
  }
  std::printf("\n");
  for (const Requirement& requirement : contract.body.requirements) {
    std::printf("  %s %s %s", requirement.scope.c_str(),
                std::string(requirement_kind_token(requirement.kind)).c_str(),
                std::string(requirement_strength_token(requirement.strength)).c_str());
    if (requirement.has_numeric) {
      std::printf(" target=%g minimum=%g", requirement.target, requirement.minimum);
    }
    if (!requirement.value.empty()) {
      std::printf(" value=%s", requirement.value.c_str());
    }
    if (!requirement.preferred_value.empty()) {
      std::printf(" preferred=%s", requirement.preferred_value.c_str());
    }
    if (!requirement.key.empty()) {
      std::printf(" key=%s", requirement.key.c_str());
    }
    std::printf(" id=%s\n", requirement.id.str().c_str());
  }

  if (const std::optional<std::string> evidence_path = option(argc, argv, "--evidence")) {
    std::string evidence_text;
    if (!read_text_file(*evidence_path, evidence_text)) {
      return 2;
    }
    const EvidenceDecodeResult evidence = evidence_from_text(evidence_text);
    if (!evidence.ok) {
      std::fprintf(stderr, "evidence refused: %s: %s\n",
                   std::string(code_token(evidence.code)).c_str(), evidence.message.c_str());
      return 1;
    }
    const Incarnation incarnation = new_incarnation();
    EvidenceSet stamped = evidence.evidence;
    for (EvidenceEntry& entry : stamped.entries) {
      entry.captured_by = incarnation;
      entry.epoch = stamped.epoch;
      entry.freshness = EvidenceFreshness::kCurrent;
    }
    const EvaluationResult evaluation =
        evaluate_contract(contract, stamped, incarnation, state::wall_millis(), 0);
    if (!evaluation.ok) {
      std::fprintf(stderr, "evaluation refused: %s: %s\n",
                   std::string(code_token(evaluation.code)).c_str(), evaluation.message.c_str());
      return 1;
    }
    std::printf("aggregate %s\n",
                std::string(satisfaction_token(evaluation.evaluation.aggregate)).c_str());
    for (const RequirementEvaluation& entry : evaluation.evaluation.requirements) {
      std::printf("  %s %s %s", entry.scope.c_str(),
                  std::string(requirement_kind_token(entry.kind)).c_str(),
                  std::string(satisfaction_token(entry.satisfaction)).c_str());
      if (entry.observed.has_value()) {
        std::printf(" observed=%g", *entry.observed);
      }
      std::printf(" reason=%s", std::string(code_token(entry.reason_code)).c_str());
      std::printf(" (%s)\n", entry.reason.c_str());
    }
  }
  return 0;
}

int command_diff(int argc, char** argv) {
  const std::optional<std::string> before_path = option(argc, argv, "--before");
  const std::optional<std::string> after_path = option(argc, argv, "--after");
  if (!before_path.has_value() || !after_path.has_value()) {
    return usage();
  }
  std::string before_text;
  std::string after_text;
  if (!read_text_file(*before_path, before_text) || !read_text_file(*after_path, after_text)) {
    return 2;
  }
  const ContractDecodeResult before = contract_from_text(before_text);
  const ContractDecodeResult after = contract_from_text(after_text);
  if (!before.ok || !after.ok) {
    std::fprintf(stderr, "one of the contracts was refused: %s / %s\n",
                 before.ok ? "ok" : before.message.c_str(),
                 after.ok ? "ok" : after.message.c_str());
    return 1;
  }
  std::printf("before digest=%s generation=%llu\n", hex_encode(before.contract.digest).c_str(),
              static_cast<unsigned long long>(before.contract.body.generation.value));
  std::printf("after  digest=%s generation=%llu\n", hex_encode(after.contract.digest).c_str(),
              static_cast<unsigned long long>(after.contract.body.generation.value));
  if (hex_encode(before.contract.digest) == hex_encode(after.contract.digest)) {
    std::printf("identical\n");
    return 0;
  }

  const CompatibilityResult compatibility =
      check_compatibility(before.contract.body, after.contract.body);
  switch (compatibility.verdict) {
    case CompatibilityVerdict::kCompatible:
      std::printf("compatibility: compatible\n");
      break;
    case CompatibilityVerdict::kCompatibleWithAdditions:
      std::printf("compatibility: compatible with additions\n");
      break;
    case CompatibilityVerdict::kIncompatible:
      std::printf("compatibility: incompatible\n");
      break;
  }
  for (const std::string& reason : compatibility.reasons()) {
    std::printf("  %s\n", reason.c_str());
  }

  std::map<RequirementKey, const Requirement*> before_keys;
  for (const Requirement& requirement : before.contract.body.requirements) {
    before_keys.emplace(requirement.composite_key(), &requirement);
  }
  std::map<RequirementKey, const Requirement*> after_keys;
  for (const Requirement& requirement : after.contract.body.requirements) {
    after_keys.emplace(requirement.composite_key(), &requirement);
  }
  for (const auto& entry : before_keys) {
    const auto match = after_keys.find(entry.first);
    if (match == after_keys.end()) {
      std::printf("- %s %s\n", entry.first.scope.c_str(),
                  std::string(requirement_kind_token(entry.first.kind)).c_str());
      continue;
    }
    const Requirement& left = *entry.second;
    const Requirement& right = *match->second;
    const bool same = left.strength == right.strength && left.target == right.target &&
                      left.minimum == right.minimum && left.value == right.value &&
                      left.preferred_value == right.preferred_value;
    if (same) {
      continue;
    }
    std::printf("~ %s %s strength %s -> %s", left.scope.c_str(),
                std::string(requirement_kind_token(left.kind)).c_str(),
                std::string(requirement_strength_token(left.strength)).c_str(),
                std::string(requirement_strength_token(right.strength)).c_str());
    if (left.has_numeric || right.has_numeric) {
      std::printf(" target %g -> %g minimum %g -> %g", left.target, right.target, left.minimum,
                  right.minimum);
    }
    if (left.value != right.value) {
      std::printf(" value '%s' -> '%s'", left.value.c_str(), right.value.c_str());
    }
    std::printf("\n");
  }
  for (const auto& entry : after_keys) {
    if (before_keys.find(entry.first) == before_keys.end()) {
      std::printf("+ %s %s\n", entry.first.scope.c_str(),
                  std::string(requirement_kind_token(entry.first.kind)).c_str());
    }
  }
  return 0;
}

int command_compose(int argc, char** argv) {
  const std::optional<std::string> base_path = option(argc, argv, "--base");
  if (!base_path.has_value()) {
    return usage();
  }
  std::string base_text;
  if (!read_text_file(*base_path, base_text)) {
    return 2;
  }
  const ContractDecodeResult base = contract_from_text(base_text);
  if (!base.ok) {
    std::fprintf(stderr, "base contract refused: %s: %s\n",
                 std::string(code_token(base.code)).c_str(), base.message.c_str());
    return 1;
  }

  std::vector<OverlayLayer> layers;
  for (const std::string& layer_path : all_options(argc, argv, "--layer")) {
    std::string layer_text;
    if (!read_text_file(layer_path, layer_text)) {
      return 2;
    }
    // A layer is a fragment: it declares scopes, requirements, or both. It is read
    // through the contract body schema, but the identity fields a complete
    // contract requires are irrelevant for a fragment, so they are supplied here
    // rather than demanded of the author.
    const JsonDecodeResult decoded = json_decode(layer_text);
    if (!decoded.ok) {
      std::fprintf(stderr, "layer %s is not valid JSON: %s\n", layer_path.c_str(),
                   decoded.message.c_str());
      return 1;
    }
    if (!decoded.value.is_object()) {
      std::fprintf(stderr, "layer %s must be a JSON object\n", layer_path.c_str());
      return 1;
    }
    // A layer may be written as a bare body or as a sealed contract envelope.
    Json body_document =
        decoded.value.find("body") != nullptr && decoded.value.find("body")->is_object()
            ? *decoded.value.find("body")
            : decoded.value;
    if (body_document.find("schema_version") == nullptr) {
      body_document.set("schema_version", static_cast<std::int64_t>(kSchemaVersion));
    }
    if (body_document.find("workload") == nullptr) {
      Json workload;
      workload.set(
          "id",
          WorkloadId::from_digest(sha256(std::string_view("layer:" + layer_path))).str());
      workload.set("name", std::filesystem::path(layer_path).filename().string());
      workload.set("generation", static_cast<std::int64_t>(1));
      body_document.set("workload", std::move(workload));
    }
    if (body_document.find("contract_id") == nullptr) {
      body_document.set("contract_id", std::string(kSha256HexChars, '0'));
    }
    if (body_document.find("contract_generation") == nullptr) {
      body_document.set("contract_generation", static_cast<std::int64_t>(1));
    }
    if (body_document.find("policy_generation") == nullptr) {
      body_document.set("policy_generation", static_cast<std::int64_t>(1));
    }
    if (body_document.find("version") == nullptr) {
      Json version;
      version.set("major", static_cast<std::int64_t>(1));
      version.set("minor", static_cast<std::int64_t>(0));
      version.set("patch", static_cast<std::int64_t>(0));
      body_document.set("version", std::move(version));
    }
    if (body_document.find("description") == nullptr) {
      body_document.set("description", "");
    }
    if (body_document.find("scopes") == nullptr) {
      body_document.set("scopes", Json(JsonArray{}));
    }
    if (body_document.find("requirements") == nullptr) {
      std::fprintf(stderr, "layer %s declares no requirements\n", layer_path.c_str());
      return 1;
    }
    Json wrapper;
    wrapper.set("body", std::move(body_document));
    const ContractDecodeResult layer = contract_from_json(wrapper);
    if (!layer.ok) {
      std::fprintf(stderr, "layer %s refused: %s: %s\n", layer_path.c_str(),
                   std::string(code_token(layer.code)).c_str(), layer.message.c_str());
      return 1;
    }
    OverlayLayer overlay;
    overlay.name = std::filesystem::path(layer_path).filename().string();
    overlay.scopes = layer.contract.body.scopes;
    overlay.requirements = layer.contract.body.requirements;
    layers.push_back(std::move(overlay));
  }

  const CompositionResult composed = compose(base.contract.body, layers);
  if (!composed.ok) {
    std::fprintf(stderr, "composition refused: %s: %s\n",
                 std::string(code_token(composed.code)).c_str(), composed.message.c_str());
    print_diagnostics(composed.diagnostics);
    for (const CompositionDecision& decision : composed.decisions) {
      std::fprintf(stderr, "  decision %s layer=%s scope=%s key=%s: %s\n",
                   std::string(composition_decision_token(decision.kind)).c_str(),
                   decision.layer.c_str(), decision.scope.c_str(), decision.key.c_str(),
                   decision.reason.c_str());
    }
    return 1;
  }

  Contract contract;
  contract.body = composed.body;
  std::printf("%s", contract_to_json(contract).dump().c_str());
  std::printf("\n");
  for (const CompositionDecision& decision : composed.decisions) {
    std::fprintf(stderr, "  decision %s layer=%s scope=%s key=%s: %s\n",
                 std::string(composition_decision_token(decision.kind)).c_str(),
                 decision.layer.c_str(), decision.scope.c_str(), decision.key.c_str(),
                 decision.reason.c_str());
  }
  return 0;
}

struct Client {
  wire::Socket socket;
  std::uint64_t request_id = 0;

  bool connect(const std::string& host, std::uint16_t port) {
    Code code = Code::kOk;
    std::string message;
    if (!wire::connect_to(host, port, socket, code, message)) {
      std::fprintf(stderr, "cannot connect to %s:%u: %s\n", host.c_str(), port,
                   message.c_str());
      return false;
    }
    return true;
  }

  std::optional<Json> call(wire::MessageType type, const Json& body) {
    Code code = Code::kOk;
    std::string message;
    ++request_id;
    if (!wire::send_frame(socket, type, request_id, body.dump(), code, message)) {
      std::fprintf(stderr, "send failed: %s\n", message.c_str());
      return std::nullopt;
    }
    wire::Frame reply;
    if (!wire::read_frame(socket, reply, code, message)) {
      std::fprintf(stderr, "receive failed: %s\n", message.c_str());
      return std::nullopt;
    }
    const JsonDecodeResult decoded = json_decode(reply.body);
    if (!decoded.ok) {
      std::fprintf(stderr, "reply is not canonical JSON: %s\n", decoded.message.c_str());
      return std::nullopt;
    }
    return decoded.value;
  }
};

int command_status(int argc, char** argv) {
  const std::string host = option(argc, argv, "--host").value_or("127.0.0.1");
  const std::string port_text = option(argc, argv, "--port").value_or("0");
  Client client;
  if (!client.connect(host, static_cast<std::uint16_t>(std::strtoul(port_text.c_str(), nullptr, 10)))) {
    return 3;
  }
  Json body;
  body.set("schema", "wnc/v1/status");
  const std::optional<Json> reply = client.call(wire::MessageType::kStatus, body);
  if (!reply.has_value()) {
    return 3;
  }
  std::printf("%s\n", reply->dump().c_str());
  return 0;
}

int command_evaluate(int argc, char** argv) {
  const std::string host = option(argc, argv, "--host").value_or("127.0.0.1");
  const std::string port_text = option(argc, argv, "--port").value_or("0");
  const std::optional<std::string> workload = option(argc, argv, "--workload");
  if (!workload.has_value()) {
    return usage();
  }
  Client client;
  if (!client.connect(host, static_cast<std::uint16_t>(std::strtoul(port_text.c_str(), nullptr, 10)))) {
    return 3;
  }
  Json body;
  body.set("schema", "wnc/v1/evaluate");
  body.set("workload", *workload);
  const std::optional<Json> reply = client.call(wire::MessageType::kEvaluate, body);
  if (!reply.has_value()) {
    return 3;
  }
  std::printf("%s\n", reply->dump().c_str());
  const Json* evaluation = reply->find("evaluation");
  if (evaluation == nullptr) {
    return 1;
  }
  const Json* aggregate = evaluation->find("aggregate");
  std::fprintf(stderr, "aggregate %s\n",
               aggregate != nullptr && aggregate->is_string() ? aggregate->as_string().c_str()
                                                              : "unknown");
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    return usage();
  }
  const std::string command = argv[1];
  if (command == "validate") {
    return command_validate(argc, argv);
  }
  if (command == "seal") {
    const std::optional<std::string> path = option(argc, argv, "--body");
    if (!path.has_value()) {
      std::fprintf(stderr, "seal requires --body <file>\n");
      return 2;
    }
    return command_seal(*path);
  }
  if (command == "digest") {
    return command_digest(argc, argv);
  }
  if (command == "explain") {
    return command_explain(argc, argv);
  }
  if (command == "diff") {
    return command_diff(argc, argv);
  }
  if (command == "compose") {
    return command_compose(argc, argv);
  }
  if (command == "status") {
    return command_status(argc, argv);
  }
  if (command == "evaluate") {
    return command_evaluate(argc, argv);
  }
  return usage();
}