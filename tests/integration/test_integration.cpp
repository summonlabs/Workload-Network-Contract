// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// In-process integration surface: a real Coordinator serving a real loopback
// socket, driven by a real client, with the durable runtime behind it inspected
// directly so that every reply can be checked against what was actually
// committed.

#include "wnc_test.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "wnc/contract.hpp"
#include "wnc/coordinator.hpp"
#include "wnc/hash.hpp"
#include "wnc/json.hpp"
#include "wnc/state.hpp"
#include "wnc/wire.hpp"

using namespace wnc;

namespace {

std::filesystem::path integration_directory(const std::string& name) {
  const std::filesystem::path base =
      std::filesystem::temp_directory_path() /
      ("wnc-integration-" + name + "-" + std::to_string(state::wall_millis()) + "-" +
       std::to_string(reinterpret_cast<std::uintptr_t>(&name)));
  std::error_code error;
  std::filesystem::remove_all(base, error);
  std::filesystem::create_directories(base, error);
  return base;
}

struct Guard {
  std::filesystem::path path;
  explicit Guard(std::string name) : path(integration_directory(name)) {}
  Guard(const Guard&) = delete;
  Guard& operator=(const Guard&) = delete;
  ~Guard() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

struct Service {
  std::optional<Coordinator> coordinator;
  std::thread loop;

  bool start(const std::filesystem::path& directory, const TrustSet& trust, Code& code,
             std::string& message) {
    CoordinatorOptions options;
    options.bind_host = "127.0.0.1";
    options.port = 0;
    Runtime::Options runtime_options;
    runtime_options.state_directory = directory;
    runtime_options.trust = trust;
    coordinator = Coordinator::start(options, runtime_options, code, message);
    if (!coordinator.has_value()) {
      return false;
    }
    loop = std::thread([this] { coordinator->run(); });
    return true;
  }

  void stop() {
    if (coordinator.has_value()) {
      coordinator->request_stop();
    }
    if (loop.joinable()) {
      loop.join();
    }
    if (coordinator.has_value()) {
      coordinator->stop();
    }
  }

  Service() = default;
  Service(const Service&) = delete;
  Service& operator=(const Service&) = delete;
  // Destruction stops the loop: a joinable thread destroyed during unwinding
  // would abort the process and hide the failing expectation.
  ~Service() { stop(); }
};

class Client {
 public:
  // The socket is exposed so that a test can observe how the service reacts to a
  // frame the framed API would refuse to build.
  wire::Socket socket;

  bool connect(std::uint16_t port, Code& code, std::string& message) {
    return wire::connect_to("127.0.0.1", port, socket, code, message);
  }

  Json call(wire::MessageType type, const Json& body, Code& code, std::string& message) {
    ++request_id_;
    if (!wire::send_frame(socket, type, request_id_, body.dump(), code, message)) {
      return Json(nullptr);
    }
    wire::Frame reply;
    if (!wire::read_frame(socket, reply, code, message)) {
      return Json(nullptr);
    }
    const JsonDecodeResult decoded = json_decode(reply.body);
    if (!decoded.ok) {
      code = decoded.code;
      message = decoded.message;
      return Json(nullptr);
    }
    last_type_ = reply.header.type;
    return decoded.value;
  }

  [[nodiscard]] wire::MessageType last_type() const noexcept { return last_type_; }

  bool send_raw(std::string_view bytes, Code& code, std::string& message) {
    return wire::write_all(socket, bytes, code, message);
  }

  void close() { socket.close(); }

 private:
  std::uint64_t request_id_ = 0;
  wire::MessageType last_type_ = wire::MessageType::kUnknown;
};

Contract build_contract(const LocalSigner& signer, const std::string& workload,
                        std::uint64_t generation, double bandwidth) {
  Contract contract;
  contract.body.schema_version = kSchemaVersion;
  contract.body.workload.id =
      WorkloadId::from_digest(sha256(std::string_view("integration:" + workload)));
  contract.body.workload.name = workload;
  contract.body.workload.generation.value = 1;
  contract.body.generation.value = generation;
  contract.body.policy_generation.value = 1;
  contract.body.major = 1;
  Scope scope;
  scope.name = "fabric";
  contract.body.scopes.push_back(scope);
  Requirement requirement;
  requirement.scope = "fabric";
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
  const std::string_view domain =
      generation == 1 ? std::string_view("wnc/v1/submission/registration")
                      : std::string_view("wnc/v1/submission/publication");
  const SignatureBytes signature =
      sign_with_local_signer(signer, domain, contract_body_to_json(contract.body).dump());
  contract.envelope.signature = signature.bytes;
  return contract;
}

Json hello_body() {
  Json body;
  body.set("schema", "wnc/v1/hello");
  return body;
}

}  // namespace

WNC_TEST(integration, hello_reports_identity_epoch_and_incarnation) {
  Guard guard("hello");
  const LocalSigner signer = local_signer_from_seed(Ed25519Seed{1, 1, 1, 1});
  TrustSet trust;
  trust.add_ed25519(signer.publisher, signer.public_key);

  Service service;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(service.start(guard.path, trust, code, message), message);
  WNC_CHECK(service.coordinator->port() != 0);

  Client client;
  WNC_CHECK_MSG(client.connect(service.coordinator->port(), code, message), message);
  const Json reply = client.call(wire::MessageType::kHello, hello_body(), code, message);
  WNC_CHECK_MSG(reply.is_object(), message);
  const Json* incarnation = reply.find("incarnation");
  const Json* epoch = reply.find("epoch");
  WNC_CHECK(incarnation != nullptr && incarnation->is_string());
  WNC_CHECK(epoch != nullptr && epoch->is_int());
  const std::optional<Incarnation> parsed = Incarnation::parse(incarnation->as_string());
  WNC_CHECK(parsed.has_value());
  WNC_CHECK_EQ(parsed->str(), service.coordinator->runtime().info().incarnation.str());
  WNC_CHECK_EQ(static_cast<std::uint64_t>(epoch->as_int()), service.coordinator->runtime().info().epoch);

  client.close();
  service.stop();
  WNC_CHECK(!service.coordinator->healthy());
}

WNC_TEST(integration, registration_over_the_wire_matches_committed_state) {
  Guard guard("register");
  const LocalSigner signer = local_signer_from_seed(Ed25519Seed{2, 2, 2, 2});
  TrustSet trust;
  trust.add_ed25519(signer.publisher, signer.public_key);

  Service service;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(service.start(guard.path, trust, code, message), message);

  Client client;
  WNC_CHECK_MSG(client.connect(service.coordinator->port(), code, message), message);

  const Contract contract = build_contract(signer, "trainer", 1, 5000.0);
  Json body;
  body.set("schema", "wnc/v1/register_workload");
  body.set("contract", contract_to_json(contract));
  const Json reply = client.call(wire::MessageType::kRegisterWorkload, body, code, message);
  const Json* ok = reply.find("ok");
  WNC_CHECK_MSG(ok != nullptr && ok->is_bool() && ok->as_bool(), reply.dump());

  // What the service said must equal what it committed.
  const Runtime& runtime = service.coordinator->runtime();
  const std::optional<WorkloadSnapshot> snapshot = runtime.snapshot(contract.body.workload.id);
  WNC_CHECK(snapshot.has_value());
  WNC_CHECK_EQ(hex_encode(snapshot->digest), hex_encode(contract.digest));
  const Json* digest = reply.find("digest");
  WNC_CHECK(digest != nullptr && digest->is_string());
  WNC_CHECK_EQ(digest->as_string(), hex_encode(contract.digest));
  WNC_CHECK(service.coordinator->served_requests() >= 1);

  // A registration for an unknown workload identity cannot be evaluated.
  Json evaluate_body;
  evaluate_body.set("schema", "wnc/v1/evaluate");
  evaluate_body.set("workload", WorkloadId{}.str());
  const Json unknown = client.call(wire::MessageType::kEvaluate, evaluate_body, code, message);
  const Json* error_code = unknown.find("code");
  WNC_CHECK(error_code != nullptr && error_code->is_string());
  WNC_CHECK_EQ(error_code->as_string(), std::string("unknown_workload"));

  client.close();
  service.stop();
}

WNC_TEST(integration, evaluation_reports_unknown_until_evidence_is_attached) {
  Guard guard("evaluate");
  const LocalSigner signer = local_signer_from_seed(Ed25519Seed{3, 3, 3, 3});
  TrustSet trust;
  trust.add_ed25519(signer.publisher, signer.public_key);

  Service service;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(service.start(guard.path, trust, code, message), message);

  Client client;
  WNC_CHECK_MSG(client.connect(service.coordinator->port(), code, message), message);

  const Contract contract = build_contract(signer, "trainer", 1, 5000.0);
  {
    Json body;
    body.set("schema", "wnc/v1/register_workload");
    body.set("contract", contract_to_json(contract));
    const Json reply = client.call(wire::MessageType::kRegisterWorkload, body, code, message);
    const Json* ok = reply.find("ok");
    WNC_CHECK(ok != nullptr && ok->is_bool() && ok->as_bool());
  }

  const std::string workload_id = contract.body.workload.id.str();

  // With no evidence at all, the verdict must be unknown.
  {
    Json body;
    body.set("schema", "wnc/v1/evaluate");
    body.set("workload", workload_id);
    const Json reply = client.call(wire::MessageType::kEvaluate, body, code, message);
    const Json* evaluation = reply.find("evaluation");
    WNC_CHECK(evaluation != nullptr && evaluation->is_object());
    const Json* aggregate = evaluation->find("aggregate");
    WNC_CHECK(aggregate != nullptr && aggregate->is_string());
    WNC_CHECK_EQ(aggregate->as_string(), std::string("unknown"));
  }

  // Supplying evidence that supports the requirement flips it to satisfied.
  {
    EvidenceSet evidence;
    evidence.generation.value = 1;
    evidence.publisher = signer.publisher;
    EvidenceEntry entry;
    entry.scope = "fabric";
    entry.publisher = signer.publisher;
    entry.generation.value = 1;
    entry.candidate.min_bandwidth = 9000.0;
    evidence.entries.push_back(std::move(entry));

    Json body;
    body.set("schema", "wnc/v1/attach_evidence");
    body.set("evidence", evidence_to_json(evidence));
    const Json reply = client.call(wire::MessageType::kAttachEvidence, body, code, message);
    const Json* ok = reply.find("ok");
    WNC_CHECK_MSG(ok != nullptr && ok->is_bool() && ok->as_bool(), reply.dump());
  }
  {
    Json body;
    body.set("schema", "wnc/v1/evaluate");
    body.set("workload", workload_id);
    const Json reply = client.call(wire::MessageType::kEvaluate, body, code, message);
    const Json* evaluation = reply.find("evaluation");
    WNC_CHECK(evaluation != nullptr && evaluation->is_object());
    const Json* aggregate = evaluation->find("aggregate");
    WNC_CHECK(aggregate != nullptr && aggregate->is_string());
    WNC_CHECK_MSG(aggregate->as_string() == std::string("satisfied"), reply.dump());
    Runtime& runtime = service.coordinator->runtime();
    const EvaluationResult direct = runtime.evaluate(contract.body.workload.id);
    WNC_CHECK(direct.ok);
    WNC_CHECK_EQ(direct.evaluation.aggregate, Satisfaction::kSatisfied);
  }

  client.close();
  service.stop();
}

WNC_TEST(integration, hostile_frames_are_refused_and_the_service_keeps_serving) {
  Guard guard("hostile");
  const LocalSigner signer = local_signer_from_seed(Ed25519Seed{4, 4, 4, 4});
  TrustSet trust;
  trust.add_ed25519(signer.publisher, signer.public_key);

  Service service;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(service.start(guard.path, trust, code, message), message);

  // A frame with a bad CRC is refused: the session is closed by the service,
  // and the next connection is still served.
  {
    Client client;
    WNC_CHECK(client.connect(service.coordinator->port(), code, message));
    std::string frame;
    WNC_CHECK(wire::encode_frame(wire::MessageType::kStatus, 1, hello_body().dump(), frame, code,
                                 message));
    frame[6] = static_cast<char>(frame[6] ^ 0x01);
    WNC_CHECK(client.send_raw(frame, code, message));
    Code read_code = Code::kOk;
    std::string read_message;
    wire::Frame ignored;
    WNC_CHECK(!wire::read_frame(client.socket, ignored, read_code, read_message));
    client.close();
  }

  // A well formed frame whose body is not a JSON object is refused with a code.
  {
    Client client;
    WNC_CHECK(client.connect(service.coordinator->port(), code, message));
    Json body;
    body.set("schema", "wnc/v1/this_schema_does_not_exist");
    const Json reply = client.call(wire::MessageType::kRegisterWorkload, body, code, message);
    const Json* error_code = reply.find("code");
    WNC_CHECK(error_code != nullptr && error_code->is_string());
    WNC_CHECK_EQ(client.last_type(), wire::MessageType::kError);
    client.close();
  }

  // A frame declaring an absurd body length is refused before allocation and the
  // session is closed.
  {
    Client client;
    WNC_CHECK(client.connect(service.coordinator->port(), code, message));
    std::string frame;
    WNC_CHECK(wire::encode_frame(wire::MessageType::kStatus, 1, "", frame, code, message));
    const std::uint32_t huge = 0xFFFFFF00u;
    for (int i = 0; i < 4; ++i) {
      frame[12 + i] = static_cast<char>((huge >> (8 * i)) & 0xFFu);
    }
    const std::uint32_t crc = crc32(std::string_view(frame.data(), 24));
    for (int i = 0; i < 4; ++i) {
      frame[24 + i] = static_cast<char>((crc >> (8 * i)) & 0xFFu);
    }
    WNC_CHECK(client.send_raw(frame, code, message));
    Code read_code = Code::kOk;
    std::string read_message;
    wire::Frame ignored;
    WNC_CHECK(!wire::read_frame(client.socket, ignored, read_code, read_message));
    client.close();
  }

  // The service is still alive and answers a fresh hello.
  {
    Client client;
    WNC_CHECK(client.connect(service.coordinator->port(), code, message));
    const Json reply = client.call(wire::MessageType::kHello, hello_body(), code, message);
    WNC_CHECK(reply.is_object());
    WNC_CHECK(reply.find("incarnation") != nullptr);
    client.close();
  }
  WNC_CHECK(service.coordinator->rejected_requests() >= 1);
  service.stop();
}

WNC_TEST(integration, repeated_start_and_stop_cycles_release_every_socket) {
  Guard guard("cycles");
  const LocalSigner signer = local_signer_from_seed(Ed25519Seed{5, 5, 5, 5});
  TrustSet trust;
  trust.add_ed25519(signer.publisher, signer.public_key);

  for (int cycle = 0; cycle < 10; ++cycle) {
    Service service;
    Code code = Code::kOk;
    std::string message;
    WNC_CHECK_MSG(service.start(guard.path, trust, code, message), message);
    const std::uint16_t port = service.coordinator->port();
    WNC_CHECK(port != 0);
    Client client;
    WNC_CHECK_MSG(client.connect(port, code, message), message);
    const Json reply = client.call(wire::MessageType::kHello, hello_body(), code, message);
    WNC_CHECK(reply.is_object());
    client.close();
    service.stop();
  }
  // Every cycle advanced the epoch.
  Code code = Code::kOk;
  std::string message;
  Service final_service;
  WNC_CHECK_MSG(final_service.start(guard.path, trust, code, message), message);
  WNC_CHECK(final_service.coordinator->runtime().info().epoch >= 10);
  final_service.stop();
}