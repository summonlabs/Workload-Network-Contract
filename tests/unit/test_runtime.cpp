// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Coordinator authority, durability, and recovery proof surface.

#include "wnc_test.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

#include "wnc/hash.hpp"
#include "wnc/runtime.hpp"
#include "wnc/state.hpp"

using namespace wnc;

namespace {

std::string hex_of_digest(const Digest& digest) { return hex_encode(digest); }

std::filesystem::path make_temp_dir(const std::string& prefix) {
  const std::filesystem::path base =
      std::filesystem::temp_directory_path() /
      ("wnc-test-" + prefix + "-" + std::to_string(state::wall_millis()) + "-" +
       std::to_string(reinterpret_cast<std::uintptr_t>(&prefix)));
  std::error_code error;
  std::filesystem::remove_all(base, error);
  std::filesystem::create_directories(base, error);
  return base;
}

struct Fixture {
  LocalSigner signer = local_signer_from_seed(Ed25519Seed{1, 2, 3, 4});
  TrustSet trust;
  std::filesystem::path directory;

  explicit Fixture(const std::string& prefix) : directory(make_temp_dir(prefix)) {
    trust.add_ed25519(signer.publisher, signer.public_key);
  }

  Fixture(const Fixture&) = delete;
  Fixture& operator=(const Fixture&) = delete;

  ~Fixture() {
    std::error_code error;
    std::filesystem::remove_all(directory, error);
  }

  [[nodiscard]] Runtime::Options options() const {
    Runtime::Options options;
    options.state_directory = directory;
    options.trust = trust;
    options.evidence_max_age_millis = 0;
    return options;
  }
};

Contract make_contract(const LocalSigner& signer, const std::string& workload_name,
                       std::uint64_t generation, double bandwidth) {
  Contract contract;
  contract.body.schema_version = kSchemaVersion;
  contract.body.workload.id =
      WorkloadId::from_digest(sha256(std::string_view("workload:" + workload_name)));
  contract.body.workload.name = workload_name;
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
  contract.envelope.issued_millis = state::wall_millis();
  const std::string_view domain =
      generation == 1 ? std::string_view("wnc/v1/submission/registration")
                      : std::string_view("wnc/v1/submission/publication");
  const SignatureBytes signature =
      sign_with_local_signer(signer, domain, contract_body_to_json(contract.body).dump());
  contract.envelope.signature = signature.bytes;
  return contract;
}

// Produces the next generation of an existing contract, signed for publication.
Contract next_generation(const LocalSigner& signer, const Contract& previous, double bandwidth) {
  Contract contract = make_contract(signer, previous.body.workload.name,
                                    previous.body.generation.value + 1, bandwidth);
  contract.supersedes = previous.body.generation;
  contract.supersedes_digest = previous.digest;
  (void)canonicalize(contract);
  contract.envelope.signature.clear();
  const SignatureBytes signature = sign_with_local_signer(
      signer, std::string_view("wnc/v1/submission/publication"),
      contract_body_to_json(contract.body).dump());
  contract.envelope.signature = signature.bytes;
  return contract;
}

EvidenceSet make_evidence(PublisherId publisher, std::uint64_t generation, double bandwidth) {
  EvidenceSet evidence;
  evidence.generation.value = generation;
  evidence.publisher = publisher;
  EvidenceEntry entry;
  entry.scope = "fabric";
  entry.publisher = publisher;
  entry.generation.value = generation;
  entry.candidate.min_bandwidth = bandwidth;
  evidence.entries.push_back(std::move(entry));
  return evidence;
}

}  // namespace

WNC_TEST(runtime, registration_assigns_generation_and_persists) {
  Fixture fixture("register");
  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
  WNC_CHECK_MSG(runtime.has_value(), message);
  WNC_CHECK(!runtime->info().incarnation.is_zero());
  WNC_CHECK(runtime->info().epoch >= 1);

  const Contract contract = make_contract(fixture.signer, "trainer", 1, 25000000000.0);
  const RegisterResult result = runtime->register_workload(contract);
  WNC_CHECK_MSG(result.ok, result.message);
  WNC_CHECK_EQ(result.contract_generation.value, std::uint64_t(1));
  WNC_CHECK(result.sequence >= 1);

  const std::optional<WorkloadSnapshot> snapshot = runtime->snapshot(contract.body.workload.id);
  WNC_CHECK(snapshot.has_value());
  WNC_CHECK_EQ(snapshot->contract_generation.value, std::uint64_t(1));
  WNC_CHECK_EQ(snapshot->history.size(), std::size_t(1));
  WNC_CHECK_EQ(hex_of_digest(snapshot->digest), hex_of_digest(contract.digest));

  const RegisterResult duplicate = runtime->register_workload(contract);
  WNC_CHECK(!duplicate.ok);
  WNC_CHECK_EQ(duplicate.code, Code::kDuplicateWorkload);
}

WNC_TEST(runtime, unsigned_submission_is_refused) {
  Fixture fixture("unsigned");
  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
  WNC_CHECK_MSG(runtime.has_value(), message);

  Contract contract = make_contract(fixture.signer, "trainer", 1, 1000.0);
  contract.envelope.signature.clear();
  const RegisterResult result = runtime->register_workload(contract);
  WNC_CHECK(!result.ok);
  WNC_CHECK_EQ(result.code, Code::kSignatureMissing);
}

WNC_TEST(runtime, untrusted_publisher_is_refused) {
  Fixture fixture("untrusted");
  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
  WNC_CHECK_MSG(runtime.has_value(), message);

  const LocalSigner stranger = local_signer_from_seed(Ed25519Seed{9, 9, 9, 9});
  const Contract contract = make_contract(stranger, "trainer", 1, 1000.0);
  const RegisterResult result = runtime->register_workload(contract);
  WNC_CHECK(!result.ok);
  WNC_CHECK_EQ(result.code, Code::kPublisherNotTrusted);
}

WNC_TEST(runtime, replayed_publication_is_refused) {
  Fixture fixture("replay");
  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
  WNC_CHECK_MSG(runtime.has_value(), message);

  const Contract first = make_contract(fixture.signer, "trainer", 1, 1000.0);
  WNC_CHECK(runtime->register_workload(first).ok);
  const Contract second = next_generation(fixture.signer, first, 2000.0);
  const PublishResult published = runtime->publish(second);
  WNC_CHECK_MSG(published.ok, published.message);
  WNC_CHECK_EQ(published.generation.value, std::uint64_t(2));

  const PublishResult replay = runtime->publish(second);
  WNC_CHECK(!replay.ok);
  WNC_CHECK_EQ(replay.code, Code::kReplayRejected);

  Contract fourth = make_contract(fixture.signer, "trainer", 4, 3000.0);
  fourth.supersedes = second.body.generation;
  fourth.supersedes_digest = second.digest;
  (void)canonicalize(fourth);
  fourth.envelope.signature.clear();
  const SignatureBytes signature = sign_with_local_signer(
      fixture.signer, std::string_view("wnc/v1/submission/publication"),
      contract_body_to_json(fourth.body).dump());
  fourth.envelope.signature = signature.bytes;
  const PublishResult gap = runtime->publish(fourth);
  WNC_CHECK(!gap.ok);
  WNC_CHECK(gap.code == Code::kGenerationGap || gap.code == Code::kStaleGeneration);
}

WNC_TEST(runtime, weakening_a_required_requirement_is_refused) {
  Fixture fixture("weaken");
  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
  WNC_CHECK_MSG(runtime.has_value(), message);

  const Contract first = make_contract(fixture.signer, "trainer", 1, 5000.0);
  WNC_CHECK(runtime->register_workload(first).ok);
  const Contract weaker = next_generation(fixture.signer, first, 100.0);
  const PublishResult result = runtime->publish(weaker);
  WNC_CHECK(!result.ok);
  WNC_CHECK_EQ(result.code, Code::kIncompatibleRequirementWeakened);
}

WNC_TEST(runtime, evidence_from_another_incarnation_is_not_current_after_restart) {
  Fixture fixture("restart-evidence");
  const Contract contract = make_contract(fixture.signer, "trainer", 1, 1000.0);
  {
    Code code = Code::kOk;
    std::string message;
    std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
    WNC_CHECK_MSG(runtime.has_value(), message);
    WNC_CHECK(runtime->register_workload(contract).ok);
    const AttachEvidenceResult attached =
        runtime->attach_evidence(make_evidence(fixture.signer.publisher, 1, 5000.0));
    WNC_CHECK_MSG(attached.ok, attached.message);
    const EvaluationResult evaluated = runtime->evaluate(contract.body.workload.id);
    WNC_CHECK(evaluated.ok);
    WNC_CHECK_EQ(evaluated.evaluation.aggregate, Satisfaction::kSatisfied);
  }
  {
    Code code = Code::kOk;
    std::string message;
    std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
    WNC_CHECK_MSG(runtime.has_value(), message);
    const EvaluationResult evaluated = runtime->evaluate(contract.body.workload.id);
    WNC_CHECK(evaluated.ok);
    WNC_CHECK_EQ(evaluated.evaluation.aggregate, Satisfaction::kUnknown);
    const RequirementEvaluation& entry = evaluated.evaluation.requirements.front();
    WNC_CHECK(entry.reason_code == Code::kRevalidationRequired ||
              entry.reason_code == Code::kEvaluationNoEvidence);
    WNC_CHECK_NE(entry.satisfaction, Satisfaction::kSatisfied);
  }
}

WNC_TEST(runtime, durable_history_survives_restart_without_restoring_liveness) {
  Fixture fixture("history");
  const Contract first = make_contract(fixture.signer, "trainer", 1, 1000.0);
  Contract second;
  {
    Code code = Code::kOk;
    std::string message;
    std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
    WNC_CHECK_MSG(runtime.has_value(), message);
    WNC_CHECK(runtime->register_workload(first).ok);
    second = next_generation(fixture.signer, first, 2000.0);
    WNC_CHECK(runtime->publish(second).ok);
    WNC_CHECK(runtime->verify_history(code, message));
  }
  {
    Code code = Code::kOk;
    std::string message;
    std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
    WNC_CHECK_MSG(runtime.has_value(), message);
    const std::optional<WorkloadSnapshot> snapshot = runtime->snapshot(first.body.workload.id);
    WNC_CHECK(snapshot.has_value());
    WNC_CHECK_EQ(snapshot->contract_generation.value, std::uint64_t(2));
    WNC_CHECK_EQ(snapshot->history.size(), std::size_t(2));
    WNC_CHECK(snapshot->history.front().superseded);
    WNC_CHECK(!snapshot->history.back().superseded);
    WNC_CHECK_EQ(hex_of_digest(snapshot->digest), hex_of_digest(second.digest));
    const std::optional<Contract> first_generation =
        runtime->contract_at(first.body.workload.id, ContractGeneration{1});
    WNC_CHECK(first_generation.has_value());
    WNC_CHECK_EQ(hex_of_digest(first_generation->digest), hex_of_digest(first.digest));
    WNC_CHECK(runtime->verify_history(code, message));
    WNC_CHECK(runtime->info().epoch >= 2);
  }
}

WNC_TEST(runtime, restarting_advances_the_epoch_and_never_reuses_an_incarnation) {
  Fixture fixture("epoch");
  Incarnation first_incarnation;
  std::uint64_t first_epoch = 0;
  {
    Code code = Code::kOk;
    std::string message;
    std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
    WNC_CHECK_MSG(runtime.has_value(), message);
    first_incarnation = runtime->info().incarnation;
    first_epoch = runtime->info().epoch;
  }
  {
    Code code = Code::kOk;
    std::string message;
    std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
    WNC_CHECK_MSG(runtime.has_value(), message);
    WNC_CHECK(runtime->info().epoch > first_epoch);
    WNC_CHECK(runtime->info().incarnation != first_incarnation);
  }
}

WNC_TEST(runtime, torn_tail_is_reported_and_earlier_history_remains_authoritative) {
  Fixture fixture("torn");
  const Contract contract = make_contract(fixture.signer, "trainer", 1, 1000.0);
  {
    Code code = Code::kOk;
    std::string message;
    std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
    WNC_CHECK_MSG(runtime.has_value(), message);
    WNC_CHECK(runtime->register_workload(contract).ok);
  }
  {
    const std::filesystem::path segment = fixture.directory / "journal-00001.log";
    bool opened = false;
    std::FILE* file = ::wnc::test::open_file(segment.string(), "ab", opened);
    WNC_CHECK(opened);
    const char garbage[12] = {'W', 'N', 'L', '1', 1, 0, 2, 0, 9, 0, 0, 0};
    WNC_CHECK_EQ(std::fwrite(garbage, 1, sizeof(garbage), file), sizeof(garbage));
    std::fclose(file);
  }
  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
  WNC_CHECK_MSG(runtime.has_value(), message);
  WNC_CHECK(runtime->info().recovered);
  WNC_CHECK(runtime->info().truncated_bytes > 0);
  const std::optional<WorkloadSnapshot> snapshot = runtime->snapshot(contract.body.workload.id);
  WNC_CHECK(snapshot.has_value());
  WNC_CHECK_EQ(hex_of_digest(snapshot->digest), hex_of_digest(contract.digest));
}

WNC_TEST(runtime, state_directory_is_bound_to_one_trust_set) {
  Fixture fixture("trust");
  {
    Code code = Code::kOk;
    std::string message;
    std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
    WNC_CHECK_MSG(runtime.has_value(), message);
  }
  const LocalSigner extra = local_signer_from_seed(Ed25519Seed{5, 5, 5, 5});
  Runtime::Options options = fixture.options();
  options.trust.add_ed25519(extra.publisher, extra.public_key);
  Code code = Code::kOk;
  std::string message;
  const std::optional<Runtime> runtime = Runtime::open(options, code, message);
  WNC_CHECK(!runtime.has_value());
  WNC_CHECK(code == Code::kPublisherNotTrusted || code == Code::kIndexMismatch);
}

WNC_TEST(runtime, policy_is_applied_to_future_generations) {
  Fixture fixture("policy");
  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
  WNC_CHECK_MSG(runtime.has_value(), message);

  Policy policy;
  policy.schema_version = kSchemaVersion;
  policy.generation.value = 1;
  PolicyRule rule;
  rule.kind = RequirementKind::kMinBandwidth;
  rule.scope = "fabric";
  rule.min_minimum = 100.0;
  rule.max_minimum = 4000.0;
  rule.min_target = 100.0;
  rule.max_target = 4000.0;
  policy.rules.push_back(rule);
  policy.policy_id = derive_policy_id(policy_digest(policy));
  const RuntimePolicyResult installed = runtime->install_policy(policy);
  WNC_CHECK_MSG(installed.ok, installed.message);

  const Contract too_big = make_contract(fixture.signer, "trainer", 1, 9000.0);
  const RegisterResult refused = runtime->register_workload(too_big);
  WNC_CHECK(!refused.ok);
  WNC_CHECK_EQ(refused.code, Code::kPolicyDenied);

  const Contract allowed = make_contract(fixture.signer, "trainer", 1, 2000.0);
  WNC_CHECK(runtime->register_workload(allowed).ok);

  Contract stale_policy = make_contract(fixture.signer, "other", 1, 2000.0);
  stale_policy.body.policy_generation.value = 2;
  (void)canonicalize(stale_policy);
  stale_policy.envelope.signature.clear();
  const SignatureBytes signature = sign_with_local_signer(
      fixture.signer, std::string_view("wnc/v1/submission/registration"),
      contract_body_to_json(stale_policy.body).dump());
  stale_policy.envelope.signature = signature.bytes;
  const RegisterResult unknown_policy = runtime->register_workload(stale_policy);
  WNC_CHECK(!unknown_policy.ok);
  WNC_CHECK_EQ(unknown_policy.code, Code::kUnknownPolicy);
}

WNC_TEST(runtime, retirement_stops_new_generations_but_keeps_history) {
  Fixture fixture("retire");
  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
  WNC_CHECK_MSG(runtime.has_value(), message);
  const Contract first = make_contract(fixture.signer, "trainer", 1, 1000.0);
  WNC_CHECK(runtime->register_workload(first).ok);
  const RetireResult retired = runtime->retire(first.body.workload.id);
  WNC_CHECK_MSG(retired.ok, retired.message);

  const Contract next = next_generation(fixture.signer, first, 2000.0);
  const PublishResult result = runtime->publish(next);
  WNC_CHECK(!result.ok);
  WNC_CHECK_EQ(result.code, Code::kContractRetired);
  const std::optional<WorkloadSnapshot> snapshot = runtime->snapshot(first.body.workload.id);
  WNC_CHECK(snapshot.has_value());
  WNC_CHECK(snapshot->retired);
  WNC_CHECK_EQ(snapshot->history.size(), std::size_t(1));
}

WNC_TEST(runtime, verify_history_accepts_a_consistent_index) {
  Fixture fixture("verify");
  Code code = Code::kOk;
  std::string message;
  std::optional<Runtime> runtime = Runtime::open(fixture.options(), code, message);
  WNC_CHECK_MSG(runtime.has_value(), message);
  const Contract first = make_contract(fixture.signer, "trainer", 1, 1000.0);
  WNC_CHECK(runtime->register_workload(first).ok);
  WNC_CHECK(runtime->verify_history(code, message));
  WNC_CHECK_EQ(code, Code::kOk);
}