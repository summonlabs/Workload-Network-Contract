// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Multiprocess test harness. This single executable plays every role a real
// deployment needs, so that the multiprocess proof surfaces can spawn real
// operating system processes rather than simulating them:
//
//   keygen            derive a deterministic key pair from a seed and print it
//   coordinator       run the coordinator service against a state directory
//   publish           register or supersede a contract over the wire
//   evidence          attach an evidence set over the wire
//   evaluate          query the current evaluation over the wire
//   status            query the coordinator identity and epoch
//
// Every subcommand prints one machine readable line per result on stdout and
// exits 0 on success. A failure prints "error=<token> message=<text>" and exits
// with a stable code, so a parent test can assert on the exact refusal.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "wnc/contract.hpp"
#include "wnc/coordinator.hpp"
#include "wnc/hash.hpp"
#include "wnc/json.hpp"
#include "wnc/runtime.hpp"
#include "wnc/state.hpp"
#include "wnc/wire.hpp"

using namespace wnc;

namespace {

std::vector<std::string> arguments;

const std::string* option(const std::string& name) {
  for (std::size_t i = 0; i + 1 < arguments.size(); ++i) {
    if (arguments[i] == name) {
      return &arguments[i + 1];
    }
  }
  return nullptr;
}

std::string option_or(const std::string& name, const std::string& fallback) {
  const std::string* value = option(name);
  return value == nullptr ? fallback : *value;
}

std::uint64_t option_u64(const std::string& name, std::uint64_t fallback) {
  const std::string* value = option(name);
  if (value == nullptr) {
    return fallback;
  }
  return static_cast<std::uint64_t>(std::strtoull(value->c_str(), nullptr, 10));
}

double option_double(const std::string& name, double fallback) {
  const std::string* value = option(name);
  if (value == nullptr) {
    return fallback;
  }
  return std::strtod(value->c_str(), nullptr);
}

bool parse_hex(const std::string& text, std::uint8_t* out, std::size_t size) {
  if (text.size() != size * 2) {
    return false;
  }
  const auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
  };
  for (std::size_t i = 0; i < size; ++i) {
    const int high = digit(text[i * 2]);
    const int low = digit(text[i * 2 + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    out[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

Ed25519Seed seed_from(const std::string& hex) {
  Ed25519Seed seed{};
  if (!parse_hex(hex, seed.data(), seed.size())) {
    std::fprintf(stderr, "seed must be 64 hex characters\n");
    std::exit(2);
  }
  return seed;
}

// Results are also written to the file named by --out, so that a parent process
// can read them without capturing this process's standard output.
std::ofstream output_sink;
bool output_sink_open = false;

void emit(const std::string& line) {
  std::printf("%s\n", line.c_str());
  std::fflush(stdout);
  if (output_sink_open) {
    output_sink << line << '\n';
    output_sink.flush();
  }
}

void fail(Code code, const std::string& message) {
  emit("error=" + std::string(code_token(code)));
  emit("message=" + message);
  std::exit(3);
}

// A minimal request/response exchange over the framed transport.
struct Client {
  wire::Socket socket;
  std::uint64_t request_id = 0;
  bool connected = false;

  bool connect(const std::string& host, std::uint16_t port) {
    Code code = Code::kOk;
    std::string message;
    if (!wire::connect_to(host, port, socket, code, message)) {
      fail(code, message);
    }
    connected = true;
    return true;
  }

  Json call(wire::MessageType type, const Json& body) {
    Code code = Code::kOk;
    std::string message;
    ++request_id;
    const std::string text = body.dump();
    if (!wire::send_frame(socket, type, request_id, text, code, message)) {
      fail(code, message);
    }
    wire::Frame reply;
    if (!wire::read_frame(socket, reply, code, message)) {
      fail(code, message);
    }
    const JsonDecodeResult decoded = json_decode(reply.body);
    if (!decoded.ok) {
      fail(decoded.code, "reply is not canonical JSON: " + decoded.message);
    }
    if (reply.header.type == wire::MessageType::kError) {
      return decoded.value;
    }
    return decoded.value;
  }
};

Contract build_contract(const LocalSigner& signer, const std::string& workload_name,
                        std::uint64_t generation, double bandwidth, const std::string& scope,
                        const std::string& description) {
  Contract contract;
  contract.body.schema_version = kSchemaVersion;
  contract.body.workload.id =
      WorkloadId::from_digest(sha256(std::string_view("workload:" + workload_name)));
  contract.body.workload.name = workload_name;
  contract.body.workload.generation.value = 1;
  contract.body.generation.value = generation;
  contract.body.policy_generation.value = 1;
  contract.body.major = 1;
  contract.body.description = description;
  Scope declared;
  declared.name = scope;
  contract.body.scopes.push_back(declared);
  Requirement requirement;
  requirement.scope = scope;
  requirement.kind = RequirementKind::kMinBandwidth;
  requirement.strength = RequirementStrength::kRequired;
  requirement.has_numeric = true;
  requirement.target = bandwidth;
  requirement.minimum = bandwidth;
  contract.body.requirements.push_back(requirement);
  (void)canonicalize(contract);

  contract.envelope.publisher = signer.publisher;
  contract.envelope.algorithm = SignatureAlgorithm::kEd25519;
  contract.envelope.key_id = signer.key_id();
  contract.envelope.issued_millis = state::wall_millis();
  const std::string_view domain =
      generation == 1 ? std::string_view("wnc/v1/submission/registration")
                      : std::string_view("wnc/v1/submission/publication");
  const SignatureBytes signature =
      sign_with_local_signer(signer, domain, contract_body_to_json(contract.body).dump());
  contract.envelope.signature = signature.bytes;
  return contract;
}

Json evaluation_to_json(const ContractEvaluation& evaluation) {
  Json out;
  out.set("workload", evaluation.workload.str());
  out.set("contract", evaluation.contract.str());
  out.set("contract_generation",
          static_cast<std::int64_t>(evaluation.contract_generation.value));
  out.set("contract_digest", hex_encode(evaluation.contract_digest));
  out.set("policy_generation", static_cast<std::int64_t>(evaluation.policy_generation.value));
  out.set("evidence_generation", static_cast<std::int64_t>(evaluation.evidence_generation.value));
  out.set("evaluated_by", evaluation.evaluated_by.str());
  out.set("epoch", static_cast<std::int64_t>(evaluation.epoch));
  out.set("evaluated_at_millis", static_cast<std::int64_t>(evaluation.evaluated_at_millis));
  out.set("aggregate", std::string(satisfaction_token(evaluation.aggregate)));
  JsonArray requirements;
  for (const RequirementEvaluation& entry : evaluation.requirements) {
    Json item;
    item.set("requirement", entry.requirement.str());
    item.set("scope", entry.scope);
    item.set("kind", std::string(requirement_kind_token(entry.kind)));
    item.set("strength", std::string(requirement_strength_token(entry.strength)));
    item.set("satisfaction", std::string(satisfaction_token(entry.satisfaction)));
    item.set("reason_code", std::string(code_token(entry.reason_code)));
    item.set("reason", entry.reason);
    item.set("evidence", entry.evidence.str());
    item.set("evidence_generation", static_cast<std::int64_t>(entry.evidence_generation.value));
    item.set("freshness", std::string(freshness_token(entry.freshness)));
    if (entry.observed.has_value()) {
      item.set("observed", *entry.observed);
    }
    requirements.push_back(std::move(item));
  }
  out.set("requirements", Json(std::move(requirements)));
  return out;
}

int run_keygen() {
  const Ed25519Seed seed = seed_from(option_or("--seed", std::string(64, '1')));
  const LocalSigner signer = local_signer_from_seed(seed);
  emit("seed=" + hex_encode(std::span<const std::uint8_t>(seed.data(), seed.size())));
  emit("public_key=" + hex_encode(std::span<const std::uint8_t>(signer.public_key.data(),
                                                                signer.public_key.size())));
  emit("publisher=" + signer.publisher.str());
  emit("key_id=" + signer.key_id());
  return 0;
}

int run_coordinator() {
  const std::string state_directory = option_or("--state", "");
  if (state_directory.empty()) {
    std::fprintf(stderr, "--state is required\n");
    return 2;
  }
  const std::string seed_text = option_or("--seed", std::string(64, '1'));
  const LocalSigner tool_signer = local_signer_from_seed(seed_from(seed_text));
  TrustSet trust;
  for (std::size_t i = 0; i + 1 < arguments.size(); ++i) {
    if (arguments[i] != "--issuer") {
      continue;
    }
    const std::string& publisher_text = arguments[i + 1];
    if (i + 2 >= arguments.size()) {
      std::fprintf(stderr, "--issuer requires a publisher and a public key\n");
      return 2;
    }
    const std::string& key_text = arguments[i + 2];
    const std::optional<PublisherId> publisher = PublisherId::parse(publisher_text);
    Ed25519PublicKey key{};
    if (!publisher.has_value() || !parse_hex(key_text, key.data(), key.size())) {
      std::fprintf(stderr, "malformed --issuer pair\n");
      return 2;
    }
    trust.add_ed25519(*publisher, key);
  }
  if (trust.empty()) {
    std::fprintf(stderr, "at least one --issuer is required\n");
    return 2;
  }

  CoordinatorOptions options;
  options.bind_host = option_or("--host", "127.0.0.1");
  options.port = static_cast<std::uint16_t>(option_u64("--port", 0));

  Runtime::Options runtime_options;
  runtime_options.state_directory = state_directory;
  runtime_options.trust = trust;
  runtime_options.evidence_max_age_millis = option_u64("--evidence-max-age-ms", 0);

  Code code = Code::kOk;
  std::string message;
  std::optional<Coordinator> coordinator =
      Coordinator::start(options, runtime_options, code, message);
  if (!coordinator.has_value()) {
    fail(code, message);
  }
  emit("port=" + std::to_string(coordinator->port()));
  emit("epoch=" + std::to_string(coordinator->epoch()));
  emit("coordinator=" + coordinator->coordinator_id().str());
  coordinator->run();
  coordinator->stop();
  return 0;
}

int run_publish() {
  const LocalSigner signer = local_signer_from_seed(seed_from(option_or("--seed", "")));
  const std::string workload = option_or("--workload", "trainer");
  const std::uint64_t generation = option_u64("--generation", 1);
  const double bandwidth = option_double("--bandwidth", 1000000000.0);
  const std::string scope = option_or("--scope", "fabric");
  const std::string description = option_or("--description", "");

  Contract contract = build_contract(signer, workload, generation, bandwidth, scope, description);
  if (generation > 1) {
    const std::string supersedes = option_or("--supersedes", "");
    const std::string supersedes_digest = option_or("--supersedes-digest", "");
    const std::optional<Digest> digest = hex_decode_digest(supersedes_digest);
    if (supersedes.empty() || !digest.has_value()) {
      std::fprintf(stderr, "--supersedes and --supersedes-digest are required above generation 1\n");
      return 2;
    }
    contract.supersedes.value = std::strtoull(supersedes.c_str(), nullptr, 10);
    contract.supersedes_digest = *digest;
    (void)canonicalize(contract);
    contract.envelope.signature.clear();
    const SignatureBytes signature = sign_with_local_signer(
        signer, std::string_view("wnc/v1/submission/publication"),
        contract_body_to_json(contract.body).dump());
    contract.envelope.signature = signature.bytes;
  }

  Json body;
  body.set("schema", "wnc/v1/register_workload");
  body.set("contract", contract_to_json(contract));

  Client client;
  client.connect(option_or("--host", "127.0.0.1"),
                 static_cast<std::uint16_t>(option_u64("--port", 0)));
  const Json reply = client.call(wire::MessageType::kRegisterWorkload, body);
  const Json* ok = reply.find("ok");
  if (ok == nullptr || !ok->is_bool() || !ok->as_bool()) {
    const Json* error_code = reply.find("code");
    const Json* error_message = reply.find("message");
    emit("error=" + std::string(error_code != nullptr && error_code->is_string()
                                    ? error_code->as_string()
                                    : "unknown"));
    emit("message=" + std::string(error_message != nullptr && error_message->is_string()
                                      ? error_message->as_string()
                                      : ""));
    return 3;
  }
  emit("digest=" + hex_encode(contract.digest));
  emit("contract=" + contract.body.contract_id.str());
  emit("workload=" + contract.body.workload.id.str());
  const Json* sequence = reply.find("sequence");
  emit("sequence=" + std::to_string(sequence != nullptr && sequence->is_int()
                                         ? sequence->as_int()
                                         : -1));
  const Json* contract_generation = reply.find("contract_generation");
  emit("contract_generation=" +
       std::to_string(contract_generation != nullptr && contract_generation->is_int()
                          ? contract_generation->as_int()
                          : -1));
  return 0;
}

int run_evidence() {
  const LocalSigner signer = local_signer_from_seed(seed_from(option_or("--seed", "")));
  EvidenceSet evidence;
  evidence.generation.value = option_u64("--generation", 1);
  evidence.publisher = signer.publisher;
  EvidenceEntry entry;
  entry.scope = option_or("--scope", "fabric");
  entry.publisher = signer.publisher;
  entry.generation = evidence.generation;
  entry.candidate.min_bandwidth = option_double("--bandwidth", 1000000000.0);
  if (const std::string* latency = option("--latency"); latency != nullptr) {
    entry.candidate.max_latency = std::strtod(latency->c_str(), nullptr);
  }
  if (const std::string* locality = option("--locality"); locality != nullptr) {
    entry.candidate.locality = *locality;
  }
  evidence.entries.push_back(std::move(entry));

  Json body;
  body.set("schema", "wnc/v1/attach_evidence");
  body.set("evidence", evidence_to_json(evidence));

  Client client;
  client.connect(option_or("--host", "127.0.0.1"),
                 static_cast<std::uint16_t>(option_u64("--port", 0)));
  const Json reply = client.call(wire::MessageType::kAttachEvidence, body);
  const Json* ok = reply.find("ok");
  if (ok == nullptr || !ok->is_bool() || !ok->as_bool()) {
    const Json* error_code = reply.find("code");
    emit("error=" + std::string(error_code != nullptr && error_code->is_string()
                                    ? error_code->as_string()
                                    : "unknown"));
    return 3;
  }
  const Json* generation = reply.find("evidence_generation");
  emit("evidence_generation=" + std::to_string(generation != nullptr && generation->is_int()
                                                   ? generation->as_int()
                                                   : -1));
  return 0;
}

int run_evaluate() {
  Json body;
  body.set("schema", "wnc/v1/evaluate");
  body.set("workload", option_or("--workload-id", ""));

  Client client;
  client.connect(option_or("--host", "127.0.0.1"),
                 static_cast<std::uint16_t>(option_u64("--port", 0)));
  const Json reply = client.call(wire::MessageType::kEvaluate, body);
  const Json* evaluation = reply.find("evaluation");
  if (evaluation == nullptr || !evaluation->is_object()) {
    const Json* error_code = reply.find("code");
    emit("error=" + std::string(error_code != nullptr && error_code->is_string()
                                    ? error_code->as_string()
                                    : "unknown"));
    return 3;
  }
  const Json* aggregate = evaluation->find("aggregate");
  emit("aggregate=" + std::string(aggregate != nullptr && aggregate->is_string()
                                      ? aggregate->as_string()
                                      : "unknown"));
  const Json* requirements = evaluation->find("requirements");
  if (requirements != nullptr && requirements->is_array()) {
    emit("requirements=" + std::to_string(requirements->size()));
    for (std::size_t i = 0; i < requirements->size(); ++i) {
      const Json* item = requirements->at(i);
      if (item == nullptr) {
        continue;
      }
      const Json* satisfaction = item->find("satisfaction");
      const Json* reason = item->find("reason_code");
      emit("requirement=" + std::to_string(i) + " satisfaction=" +
           std::string(satisfaction != nullptr && satisfaction->is_string()
                           ? satisfaction->as_string()
                           : "unknown") +
           " reason=" + std::string(reason != nullptr && reason->is_string()
                                        ? reason->as_string()
                                        : "unknown"));
    }
  }
  return 0;
}

int run_status() {
  Json body;
  body.set("schema", "wnc/v1/status");
  Client client;
  client.connect(option_or("--host", "127.0.0.1"),
                 static_cast<std::uint16_t>(option_u64("--port", 0)));
  const Json reply = client.call(wire::MessageType::kStatus, body);
  const Json* epoch = reply.find("epoch");
  const Json* incarnation = reply.find("incarnation");
  const Json* coordinator = reply.find("coordinator");
  emit("epoch=" + std::to_string(epoch != nullptr && epoch->is_int() ? epoch->as_int() : -1));
  emit("incarnation=" + std::string(incarnation != nullptr && incarnation->is_string()
                                        ? incarnation->as_string()
                                        : ""));
  emit("coordinator=" + std::string(coordinator != nullptr && coordinator->is_string()
                                        ? coordinator->as_string()
                                        : ""));
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    arguments.emplace_back(argv[i]);
  }
  if (arguments.empty()) {
    std::fprintf(stderr, "usage: wnc_test_tool <keygen|coordinator|publish|evidence|evaluate|status> [options]\n");
    return 2;
  }
  if (const std::string* out = option("--out"); out != nullptr) {
    output_sink.open(*out, std::ios::binary | std::ios::trunc);
    if (!output_sink) {
      std::fprintf(stderr, "cannot open --out file\n");
      return 2;
    }
    output_sink_open = true;
  }
  const std::string command = arguments.front();
  if (command == "keygen") {
    return run_keygen();
  }
  if (command == "coordinator") {
    return run_coordinator();
  }
  if (command == "publish") {
    return run_publish();
  }
  if (command == "evidence") {
    return run_evidence();
  }
  if (command == "evaluate") {
    return run_evaluate();
  }
  if (command == "status") {
    return run_status();
  }
  std::fprintf(stderr, "unknown command '%s'\n", command.c_str());
  return 2;
}