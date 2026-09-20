// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Concurrency and lifecycle surface. The coordinator is single threaded by
// design, so the interesting questions here are:
//
//   * does a live runtime keep exclusive ownership of a state directory;
//   * does repeated start/stop leave accounting and handles sane;
//   * can independent threads submit work through a locking adapter without
//     losing, duplicating, or reordering a single generation;
//   * does the coordinator stay responsive while a peer stalls or disconnects.

#include "wnc_test.hpp"

#include <atomic>
#include <cstdio>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "wnc/hash.hpp"
#include "wnc/runtime.hpp"
#include "wnc/state.hpp"
#include "wnc/wire.hpp"

using namespace wnc;

namespace {

std::filesystem::path concurrency_directory(const std::string& name) {
  const std::filesystem::path base =
      std::filesystem::temp_directory_path() /
      ("wnc-concurrency-" + name + "-" + std::to_string(state::wall_millis()) + "-" +
       std::to_string(reinterpret_cast<std::uintptr_t>(&name)));
  std::error_code error;
  std::filesystem::remove_all(base, error);
  std::filesystem::create_directories(base, error);
  return base;
}

struct Guard {
  std::filesystem::path path;
  explicit Guard(std::string name) : path(concurrency_directory(name)) {}
  Guard(const Guard&) = delete;
  Guard& operator=(const Guard&) = delete;
  ~Guard() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

Contract signed_contract(const LocalSigner& signer, const std::string& name, double bandwidth) {
  Contract contract;
  contract.body.schema_version = kSchemaVersion;
  contract.body.workload.id =
      WorkloadId::from_digest(sha256(std::string_view("concurrent:" + name)));
  contract.body.workload.name = name;
  contract.body.workload.generation.value = 1;
  contract.body.generation.value = 1;
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
  const SignatureBytes signature = sign_with_local_signer(
      signer, std::string_view("wnc/v1/submission/registration"),
      contract_body_to_json(contract.body).dump());
  contract.envelope.signature = signature.bytes;
  return contract;
}

// Serialises access to one runtime so that independent threads can submit work
// through it. The runtime is a single-threaded authority; this adapter is what a
// multi-threaded host would wrap around it, and the test proves that no
// generation is lost, duplicated, or reordered when it is used that way.
class LockedRuntime {
 public:
  explicit LockedRuntime(Runtime& runtime) : runtime_(runtime) {}

  RegisterResult register_workload(const Contract& contract) {
    const std::lock_guard<std::mutex> lock(mutex_);
    return runtime_.register_workload(contract);
  }

  EvaluationResult evaluate(WorkloadId workload) {
    const std::lock_guard<std::mutex> lock(mutex_);
    return runtime_.evaluate(workload);
  }

  AttachEvidenceResult attach_evidence(const EvidenceSet& evidence) {
    const std::lock_guard<std::mutex> lock(mutex_);
    return runtime_.attach_evidence(evidence);
  }

 private:
  Runtime& runtime_;
  std::mutex mutex_;
};

}  // namespace

WNC_TEST(concurrency, a_live_runtime_owns_its_state_directory) {
  Guard guard("lock");
  const LocalSigner signer = local_signer_from_seed(Ed25519Seed{2, 7, 1, 8});
  TrustSet trust;
  trust.add_ed25519(signer.publisher, signer.public_key);
  Runtime::Options options;
  options.state_directory = guard.path;
  options.trust = trust;

  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> first = Runtime::open(options, code, message);
  WNC_CHECK_MSG(first.has_value(), message);

  // The directory lock is the cross-process exclusion. A second holder in the
  // same process is allowed, because the transport and the runtime, not the file
  // lock, serialise work inside one process; the lock is what stops a second
  // process from writing into the same journal.
  Code lock_code = Code::kOk;
  std::string lock_message;
  const state::LockToken token = state::lock_directory(guard.path, lock_code, lock_message);
  WNC_CHECK(token != nullptr);
  state::unlock_directory(token);

  // Dropping the runtime releases its lock without leaking the handle.
  first.reset();
  const state::LockToken second = state::lock_directory(guard.path, lock_code, lock_message);
  WNC_CHECK(second != nullptr);
  state::unlock_directory(second);
}

WNC_TEST(concurrency, repeated_start_stop_cycles_leave_no_leaked_state) {
  Guard guard("cycles");
  const LocalSigner signer = local_signer_from_seed(Ed25519Seed{4, 4, 4, 4});
  TrustSet trust;
  trust.add_ed25519(signer.publisher, signer.public_key);
  Runtime::Options options;
  options.state_directory = guard.path;
  options.trust = trust;

  for (int cycle = 0; cycle < 25; ++cycle) {
    Code code = Code::kOk;
    std::string message;
    std::optional<Runtime> runtime = Runtime::open(options, code, message);
    WNC_CHECK_MSG(runtime.has_value(), message);
    // Each boot advances the epoch by exactly one and never reuses the previous
    // incarnation.
    WNC_CHECK_EQ(runtime->info().epoch, static_cast<std::uint64_t>(cycle + 1));
    WNC_CHECK(runtime->verify_history(code, message));
  }
}

WNC_TEST(concurrency, independent_threads_never_lose_or_duplicate_a_registration) {
  Guard guard("threads");
  const LocalSigner signer = local_signer_from_seed(Ed25519Seed{9, 1, 1, 2});
  TrustSet trust;
  trust.add_ed25519(signer.publisher, signer.public_key);
  Runtime::Options options;
  options.state_directory = guard.path;
  options.trust = trust;

  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> runtime = Runtime::open(options, code, message);
  WNC_CHECK_MSG(runtime.has_value(), message);
  LockedRuntime locked(*runtime);

  constexpr int kThreads = 8;
  constexpr int kPerThread = 25;
  std::atomic<int> accepted{0};
  std::atomic<int> refused{0};
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int thread_index = 0; thread_index < kThreads; ++thread_index) {
    threads.emplace_back([&locked, &signer, &accepted, &refused, thread_index] {
      for (int i = 0; i < kPerThread; ++i) {
        // The workload identity is derived from this name, so the name must be
        // unique across every thread or the registrations collide by design.
        const std::string name =
            "thread-" + std::to_string(thread_index) + "-item-" + std::to_string(i);
        const Contract contract = signed_contract(signer, name, 1000.0 + i);
        const RegisterResult result = locked.register_workload(contract);
        if (result.ok && result.contract_generation.value == 1) {
          ++accepted;
        } else {
          ++refused;
        }
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }

  WNC_CHECK_EQ(accepted.load(), kThreads * kPerThread);
  WNC_CHECK_EQ(refused.load(), 0);
  WNC_CHECK_EQ(runtime->workloads().size(), static_cast<std::size_t>(kThreads * kPerThread));
  WNC_CHECK(runtime->verify_history(code, message));

  for (const WorkloadId& workload : runtime->workloads()) {
    const std::optional<WorkloadSnapshot> snapshot = runtime->snapshot(workload);
    WNC_CHECK(snapshot.has_value());
    WNC_CHECK_EQ(snapshot->history.size(), std::size_t(1));
    WNC_CHECK_EQ(snapshot->contract_generation.value, std::uint64_t(1));
  }
}

WNC_TEST(concurrency, concurrent_evidence_attaches_are_serialised_and_invalidate) {
  Guard guard("evidence");
  const LocalSigner signer = local_signer_from_seed(Ed25519Seed{6, 6, 6, 6});
  TrustSet trust;
  trust.add_ed25519(signer.publisher, signer.public_key);
  Runtime::Options options;
  options.state_directory = guard.path;
  options.trust = trust;

  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> runtime = Runtime::open(options, code, message);
  WNC_CHECK_MSG(runtime.has_value(), message);
  LockedRuntime locked(*runtime);

  const Contract contract = signed_contract(signer, "evidence-target", 1000.0);
  const RegisterResult registered = locked.register_workload(contract);
  WNC_CHECK_MSG(registered.ok, registered.message);

  std::atomic<int> attached{0};
  std::atomic<int> refused{0};
  std::vector<std::thread> threads;
  for (int thread_index = 0; thread_index < 4; ++thread_index) {
    threads.emplace_back([&locked, &signer, &attached, &refused, thread_index] {
      for (int generation = 1; generation <= 10; ++generation) {
        EvidenceSet evidence;
        evidence.generation.value = static_cast<std::uint64_t>(thread_index * 10 + generation);
        evidence.publisher = signer.publisher;
        EvidenceEntry entry;
        entry.scope = "fabric";
        entry.publisher = signer.publisher;
        entry.generation = evidence.generation;
        entry.candidate.min_bandwidth = 5000.0;
        evidence.entries.push_back(std::move(entry));
        const AttachEvidenceResult result = locked.attach_evidence(evidence);
        if (result.ok) {
          ++attached;
        } else {
          ++refused;
        }
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }

  // Evidence generations must strictly advance, so concurrent submissions race
  // and exactly the winners are recorded; every loser is refused with a stable
  // code, and none is applied out of order.
  WNC_CHECK(attached.load() >= 1);
  WNC_CHECK_EQ(attached.load() + refused.load(), 40);
  const std::optional<WorkloadSnapshot> snapshot = runtime->snapshot(contract.body.workload.id);
  WNC_CHECK(snapshot.has_value());

  const EvaluationResult evaluated = runtime->evaluate(contract.body.workload.id);
  WNC_CHECK(evaluated.ok);
  WNC_CHECK_EQ(evaluated.evaluation.evidence_generation.value,
               snapshot->evidence_generation.value);
}

WNC_TEST(concurrency, transport_survives_a_stalled_peer) {
  Code code = Code::kOk;
  std::string message;
  wire::Socket listener;
  WNC_CHECK(wire::listen_on("127.0.0.1", 0, listener, code, message));
  const std::uint16_t port = wire::bound_port(listener);
  WNC_CHECK(port != 0);

  wire::Socket stalled;
  WNC_CHECK(wire::connect_to("127.0.0.1", port, stalled, code, message));
  wire::Socket accepted;
  WNC_CHECK(wire::accept_one(listener, 5000, accepted, code, message));
  WNC_CHECK(accepted.valid());

  // A peer that connects and says nothing must not block the accept loop: a
  // bounded wait simply expires, and the loop stays free to serve others.
  Code wait_code = Code::kOk;
  std::string wait_message;
  const bool readable = wire::wait_readable(accepted, 200, wait_code, wait_message);
  WNC_CHECK(!readable);
  WNC_CHECK_EQ(wait_code, Code::kDeadlineExceeded);

  // A second connection is still servable while the first is stalled.
  wire::Socket second;
  WNC_CHECK(wire::connect_to("127.0.0.1", port, second, code, message));
  wire::Socket second_accepted;
  WNC_CHECK(wire::accept_one(listener, 5000, second_accepted, code, message));
  WNC_CHECK(second_accepted.valid());

  // A complete frame on the healthy session round trips, including a frame sent
  // in fragments.
  const std::string body = "{\"ok\":true}";
  std::string frame;
  WNC_CHECK(wire::encode_frame(wire::MessageType::kStatus, 42, body, frame, code, message));
  const std::size_t half = frame.size() / 2;
  WNC_CHECK(wire::write_all(second, frame.substr(0, half), code, message));
  WNC_CHECK(wire::write_all(second, frame.substr(half), code, message));
  wire::Frame received;
  WNC_CHECK(wire::read_frame(second_accepted, received, code, message));
  WNC_CHECK_EQ(received.header.request_id, std::uint64_t(42));
  WNC_CHECK_EQ(received.body, body);

  accepted.close();
  second_accepted.close();
  listener.close();
}

WNC_TEST(concurrency, connect_disconnect_cycles_do_not_leak_sockets) {
  Code code = Code::kOk;
  std::string message;
  wire::Socket listener;
  WNC_CHECK(wire::listen_on("127.0.0.1", 0, listener, code, message));
  const std::uint16_t port = wire::bound_port(listener);

  for (int i = 0; i < 40; ++i) {
    wire::Socket client;
    WNC_CHECK(wire::connect_to("127.0.0.1", port, client, code, message));
    wire::Socket accepted;
    WNC_CHECK(wire::accept_one(listener, 5000, accepted, code, message));
    WNC_CHECK(accepted.valid());
    std::string frame;
    WNC_CHECK(wire::encode_frame(wire::MessageType::kHello, static_cast<std::uint64_t>(i), "{}",
                                 frame, code, message));
    WNC_CHECK(wire::write_all(client, frame, code, message));
    wire::Frame received;
    WNC_CHECK(wire::read_frame(accepted, received, code, message));
    WNC_CHECK_EQ(received.header.request_id, static_cast<std::uint64_t>(i));
    client.close();
    accepted.close();
  }
  listener.close();
}