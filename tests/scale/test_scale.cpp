// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Scale proof surface. Every measurement here is a count of operations that
// actually completed against a real runtime with a real durable journal, not a
// submission latency. The point of the suite is to catch accidental O(N^2)
// behaviour and unbounded memory growth before they reach a release, so every
// measurement is a per-operation cost compared between two scales of the same
// operation: a cost that is flat in N is a cost that scales.
//
// Scale is fixed rather than configurable so that a run on one machine is
// comparable with a run on another, and so that the Debug and Release
// configurations measure the same work.

#include "wnc_test.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>

#include <psapi.h>
#endif

#include "wnc/composition.hpp"
#include "wnc/hash.hpp"
#include "wnc/runtime.hpp"
#include "wnc/state.hpp"

using namespace wnc;

namespace {

// ---------------------------------------------------------------------------
// Scales
// ---------------------------------------------------------------------------

constexpr std::size_t kRegistrationSmall = 1000;
constexpr std::size_t kRegistrationLarge = 10000;
constexpr std::size_t kLookupsSmall = 2000;
constexpr std::size_t kLookupsLarge = 2000;
constexpr std::size_t kEvidenceAttaches = 100;
constexpr std::size_t kLargeRequirementCount = 512;
constexpr std::size_t kLargeScopeCount = 16;
// The composition boundary's own layer bound, so the suite exercises the
// largest composition the runtime is willing to accept rather than a smaller one.
constexpr std::size_t kCompositionLayers = kMaxCompositionLayers;
constexpr std::size_t kRequirementsPerLayer = 16;

// A ratio above this between the large and the small scale of the same
// operation means the per-operation cost grows with N. Linear behaviour leaves
// the ratio near 1; an O(N^2) path multiplies it by the scale factor (10 here),
// so the bound is generous enough for cache effects and still decisive.
constexpr double kMaxScaleRatio = 4.0;

// Absolute ceilings. These catch a catastrophe rather than a trend, so they are
// far above any measured cost, including in the unoptimised configuration.
constexpr std::uint64_t kMaxMicrosPerRegistration = 200000;
constexpr std::uint64_t kMaxMicrosPerLookup = 50000;
constexpr std::uint64_t kMaxMicrosPerEvidenceAttach = 1000000;
constexpr std::uint64_t kMaxMicrosPerEvaluation = 200000;
constexpr std::uint64_t kMaxMicrosPerRecoveryRecord = 20000;
constexpr std::uint64_t kMaxJournalBytesPerRecord = 8192;

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

std::uint64_t now_micros() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

struct Timing {
  std::uint64_t micros = 0;
  std::size_t operations = 0;

  [[nodiscard]] std::uint64_t per_operation() const {
    return operations == 0 ? 0 : micros / static_cast<std::uint64_t>(operations);
  }
  [[nodiscard]] double operations_per_second() const {
    return micros == 0 ? 0.0
                       : static_cast<double>(operations) * 1000000.0 /
                             static_cast<double>(micros);
  }
};

// Compares a large-scale cost with the same cost at a small scale. Both sides
// are floored at one microsecond so that a measurement that rounds to zero
// cannot manufacture a ratio.
double scale_ratio(std::uint64_t large_per_operation, std::uint64_t small_per_operation) {
  const double small = static_cast<double>(std::max<std::uint64_t>(small_per_operation, 1));
  const double large = static_cast<double>(std::max<std::uint64_t>(large_per_operation, 1));
  return large / small;
}

std::string describe_timing(const char* label, const Timing& timing) {
  char buffer[192];
  std::snprintf(buffer, sizeof(buffer), "%s: %llu operations in %llu us (%llu us each, %.0f/s)",
                label, static_cast<unsigned long long>(timing.operations),
                static_cast<unsigned long long>(timing.micros),
                static_cast<unsigned long long>(timing.per_operation()),
                timing.operations_per_second());
  return std::string(buffer);
}

// ---------------------------------------------------------------------------
// Footprint
// ---------------------------------------------------------------------------

// The process working set is the only footprint signal available without
// instrumenting the allocator. It is read before and after a registration run
// with every input already resident, so the difference is the runtime's state
// rather than the test's own input list.
std::size_t working_set_bytes() {
#if defined(_WIN32)
  PROCESS_MEMORY_COUNTERS counters{};
  if (::GetProcessMemoryInfo(::GetCurrentProcess(), &counters, sizeof(counters)) != 0) {
    return static_cast<std::size_t>(counters.WorkingSetSize);
  }
#endif
  return 0;
}

std::uint64_t journal_bytes(const std::filesystem::path& directory) {
  std::uint64_t total = 0;
  std::error_code error;
  for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
    const std::string name = entry.path().filename().string();
    if (name.rfind("journal-", 0) == 0) {
      total += entry.file_size(error);
    }
  }
  return total;
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

std::filesystem::path make_temp_dir(const std::string& prefix) {
  const std::filesystem::path base =
      std::filesystem::temp_directory_path() /
      ("wnc-scale-" + prefix + "-" + std::to_string(state::wall_millis()) + "-" +
       std::to_string(reinterpret_cast<std::uintptr_t>(&prefix)));
  std::error_code error;
  std::filesystem::remove_all(base, error);
  std::filesystem::create_directories(base, error);
  return base;
}

Contract build_registration(const LocalSigner& signer, const std::string& name, double bandwidth) {
  Contract contract;
  contract.body.schema_version = kSchemaVersion;
  contract.body.workload.id =
      WorkloadId::from_digest(sha256(std::string_view("scale:" + name)));
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
  contract.envelope.issued_millis = state::wall_millis();
  const SignatureBytes signature = sign_with_local_signer(
      signer, std::string_view("wnc/v1/submission/registration"),
      contract_body_to_json(contract.body).dump());
  contract.envelope.signature = signature.bytes;
  return contract;
}

EvidenceSet build_evidence(PublisherId publisher, std::uint64_t generation, double bandwidth) {
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

// ---------------------------------------------------------------------------
// Shared state
//
// Signing is the dominant cost of this suite, so ten thousand signed contracts
// are built once and reused by every measurement. The two runtimes are opened
// once and are ready for the tests that follow; each test reports the shared
// failure rather than measuring against a runtime that was never created.
// ---------------------------------------------------------------------------

struct ScaleState {
  std::string failure;

  LocalSigner signer = local_signer_from_seed(Ed25519Seed{7, 7, 7, 7});
  TrustSet trust;
  std::vector<Contract> contracts;
  Timing signing;

  std::filesystem::path small_directory;
  std::filesystem::path large_directory;
  std::unique_ptr<Runtime> small;
  std::unique_ptr<Runtime> large;

  Timing small_registration;
  Timing large_registration;
  std::size_t small_state_bytes = 0;
  std::size_t large_state_bytes = 0;
  std::uint64_t small_journal_bytes = 0;
  std::uint64_t large_journal_bytes = 0;

  bool ready = false;

  ScaleState() {
    trust.add_ed25519(signer.publisher, signer.public_key);
    build_inputs();
  }

  ~ScaleState() {
    small.reset();
    large.reset();
    std::error_code error;
    std::filesystem::remove_all(small_directory, error);
    std::filesystem::remove_all(large_directory, error);
  }

  ScaleState(const ScaleState&) = delete;
  ScaleState& operator=(const ScaleState&) = delete;

  void build_inputs();
  void register_into(Runtime& runtime, std::size_t count, Timing& timing, std::size_t& state_bytes,
                     std::uint64_t& durable_bytes, const std::filesystem::path& directory);
};

Runtime::Options options_for(const TrustSet& trust, const std::filesystem::path& directory) {
  Runtime::Options options;
  options.state_directory = directory;
  options.trust = trust;
  options.evidence_max_age_millis = 0;
  return options;
}

void ScaleState::build_inputs() {
  const std::uint64_t start = now_micros();
  contracts.reserve(kRegistrationLarge);
  for (std::size_t i = 0; i < kRegistrationLarge; ++i) {
    contracts.push_back(
        build_registration(signer, "workload-" + std::to_string(i), 1000.0 + static_cast<double>(i)));
  }
  signing.micros = now_micros() - start;
  signing.operations = contracts.size();
}

void ScaleState::register_into(Runtime& runtime, std::size_t count, Timing& timing,
                               std::size_t& state_bytes, std::uint64_t& durable_bytes,
                               const std::filesystem::path& directory) {
  // The input list is already resident, so the working-set delta across the run
  // is the runtime's own state and nothing else.
  const std::size_t before = working_set_bytes();
  const std::uint64_t start = now_micros();
  std::size_t completed = 0;
  for (std::size_t i = 0; i < count; ++i) {
    const RegisterResult result = runtime.register_workload(contracts[i]);
    if (!result.ok) {
      failure = "registration " + std::to_string(i) + " of " + std::to_string(count) +
                " was refused: " + std::string(code_token(result.code)) + ": " + result.message;
      break;
    }
    ++completed;
  }
  timing.micros = now_micros() - start;
  timing.operations = completed;
  const std::size_t after = working_set_bytes();
  state_bytes = after > before ? after - before : 0;
  durable_bytes = journal_bytes(directory);
}

ScaleState& scale_state() {
  static ScaleState state;
  return state;
}

// Opens both runtimes and performs both registration runs exactly once.
ScaleState& prepare() {
  ScaleState& state = scale_state();
  if (state.ready || !state.failure.empty()) {
    return state;
  }

  Code code = Code::kOk;
  std::string message;
  state.small_directory = make_temp_dir("small");
  state.large_directory = make_temp_dir("large");

  std::optional<Runtime> small =
      Runtime::open(options_for(state.trust, state.small_directory), code, message);
  if (!small.has_value()) {
    state.failure = "cannot open the small runtime: " + message;
    return state;
  }
  state.register_into(*small, kRegistrationSmall, state.small_registration, state.small_state_bytes,
                      state.small_journal_bytes, state.small_directory);

  std::optional<Runtime> large =
      Runtime::open(options_for(state.trust, state.large_directory), code, message);
  if (!large.has_value()) {
    state.failure = "cannot open the large runtime: " + message;
    return state;
  }
  state.register_into(*large, kRegistrationLarge, state.large_registration, state.large_state_bytes,
                      state.large_journal_bytes, state.large_directory);

  if (state.failure.empty()) {
    state.small = std::make_unique<Runtime>(std::move(*small));
    state.large = std::make_unique<Runtime>(std::move(*large));
    state.ready = true;
  }
  return state;
}

}  // namespace

// ---------------------------------------------------------------------------
// Contract registration at 1k and 10k
// ---------------------------------------------------------------------------

WNC_TEST(scale, registration_completes_at_one_thousand_and_ten_thousand) {
  ScaleState& state = prepare();
  WNC_CHECK_MSG(state.failure.empty(), state.failure);
  WNC_CHECK(state.ready);

  std::printf("  %s\n", describe_timing("sign 10000 contracts", state.signing).c_str());
  std::printf("  %s\n",
              describe_timing("register 1000", state.small_registration).c_str());
  std::printf("  %s\n",
              describe_timing("register 10000", state.large_registration).c_str());

  // Every submission completed. A partial run would make the comparison below
  // meaningless, so it is checked first.
  WNC_CHECK_EQ(state.small_registration.operations, kRegistrationSmall);
  WNC_CHECK_EQ(state.large_registration.operations, kRegistrationLarge);

  // The runtime holds exactly the workloads that were registered, and lookup by
  // identity finds them.
  WNC_CHECK_EQ(state.large->workloads().size(), kRegistrationLarge);

  const double ratio = scale_ratio(state.large_registration.per_operation(),
                                   state.small_registration.per_operation());
  std::printf("  registration cost ratio 10k/1k = %.2f (bound %.1f)\n", ratio, kMaxScaleRatio);
  WNC_CHECK_MSG(ratio <= kMaxScaleRatio,
                "registration per-operation cost grew " + std::to_string(ratio) +
                    "x between 1000 and 10000 workloads, which is superlinear");
  WNC_CHECK_MSG(state.large_registration.per_operation() <= kMaxMicrosPerRegistration,
                describe_timing("register 10000", state.large_registration));
  WNC_CHECK_MSG(state.small_registration.per_operation() <= kMaxMicrosPerRegistration,
                describe_timing("register 1000", state.small_registration));

  // Durable growth is linear in records and bounded per record.
  const std::uint64_t small_per_record =
      state.small_journal_bytes / static_cast<std::uint64_t>(kRegistrationSmall);
  const std::uint64_t large_per_record =
      state.large_journal_bytes / static_cast<std::uint64_t>(kRegistrationLarge);
  std::printf("  journal bytes per record: 1k=%llu 10k=%llu\n",
              static_cast<unsigned long long>(small_per_record),
              static_cast<unsigned long long>(large_per_record));
  WNC_CHECK(large_per_record <= kMaxJournalBytesPerRecord);
  WNC_CHECK(small_per_record <= kMaxJournalBytesPerRecord);
  // A record does not grow because the journal is long.
  WNC_CHECK_MSG(scale_ratio(large_per_record, small_per_record) <= kMaxScaleRatio,
                "the durable record grew with the length of the journal");

  // In-memory state is bounded per workload and does not grow with the number
  // of workloads already registered.
  if (state.small_state_bytes > 0 && state.large_state_bytes > 0) {
    const std::size_t small_per_workload = state.small_state_bytes / kRegistrationSmall;
    const std::size_t large_per_workload = state.large_state_bytes / kRegistrationLarge;
    std::printf("  resident bytes per workload: 1k=%zu 10k=%zu\n", small_per_workload,
                large_per_workload);
    WNC_CHECK_MSG(scale_ratio(large_per_workload, small_per_workload) <= kMaxScaleRatio,
                  "resident memory per workload grew with the number of workloads");
  }
}

// ---------------------------------------------------------------------------
// Indexed lookup
// ---------------------------------------------------------------------------

WNC_TEST(scale, indexed_lookup_stays_sublinear_at_ten_thousand_workloads) {
  ScaleState& state = prepare();
  WNC_CHECK_MSG(state.failure.empty(), state.failure);
  WNC_CHECK(state.ready);

  const std::vector<WorkloadId> small_ids = state.small->workloads();
  const std::vector<WorkloadId> large_ids = state.large->workloads();
  WNC_CHECK_EQ(small_ids.size(), kRegistrationSmall);
  WNC_CHECK_EQ(large_ids.size(), kRegistrationLarge);

  const auto measure_lookup = [](Runtime& runtime, const std::vector<WorkloadId>& ids,
                                 std::size_t count, std::uint64_t& micros) {
    std::size_t completed = 0;
    const std::uint64_t start = now_micros();
    for (std::size_t i = 0; i < count; ++i) {
      // Spread the probes across the whole key space rather than walking it in
      // order, so the measurement is a lookup and not a cache-friendly scan.
      const WorkloadId& id = ids[(i * 7919u) % ids.size()];
      if (runtime.contract_at(id, ContractGeneration{1}).has_value() &&
          runtime.snapshot(id).has_value()) {
        ++completed;
      }
    }
    micros = now_micros() - start;
    return completed;
  };

  std::uint64_t small_micros = 0;
  std::uint64_t large_micros = 0;
  const std::size_t small_completed = measure_lookup(*state.small, small_ids, kLookupsSmall, small_micros);
  const std::size_t large_completed = measure_lookup(*state.large, large_ids, kLookupsLarge, large_micros);
  WNC_CHECK_EQ(small_completed, kLookupsSmall);
  WNC_CHECK_EQ(large_completed, kLookupsLarge);

  const std::uint64_t small_per = small_micros / kLookupsSmall;
  const std::uint64_t large_per = large_micros / kLookupsLarge;
  std::printf("  indexed lookup (contract_at + snapshot): 1k=%llu us 10k=%llu us\n",
              static_cast<unsigned long long>(small_per),
              static_cast<unsigned long long>(large_per));

  const double ratio = scale_ratio(large_per, small_per);
  std::printf("  lookup cost ratio 10k/1k = %.2f (bound %.1f)\n", ratio, kMaxScaleRatio);
  WNC_CHECK_MSG(ratio <= kMaxScaleRatio,
                "indexed lookup cost grew " + std::to_string(ratio) + "x with the state size");
  WNC_CHECK(large_per <= kMaxMicrosPerLookup);
}

// ---------------------------------------------------------------------------
// Evidence attachment
// ---------------------------------------------------------------------------

WNC_TEST(scale, evidence_attachment_does_not_grow_with_history) {
  ScaleState& state = prepare();
  WNC_CHECK_MSG(state.failure.empty(), state.failure);
  WNC_CHECK(state.ready);

  // Every attach covers the scope every workload declares, so each one touches
  // the whole state. That is the intended cost: proportional to the state, and
  // independent of how many attaches came before it.
  const std::size_t quarter = kEvidenceAttaches / 4;
  std::uint64_t first_quarter_micros = 0;
  std::uint64_t last_quarter_micros = 0;
  std::size_t completed = 0;
  std::uint64_t invalidated = 0;

  const std::uint64_t start = now_micros();
  for (std::size_t i = 0; i < kEvidenceAttaches; ++i) {
    const std::uint64_t mark = now_micros();
    const AttachEvidenceResult attached = state.large->attach_evidence(
        build_evidence(state.signer.publisher, static_cast<std::uint64_t>(i) + 1,
                       9000.0 + static_cast<double>(i)));
    const std::uint64_t elapsed = now_micros() - mark;
    if (!attached.ok) {
      WNC_CHECK_MSG(attached.ok, std::string(code_token(attached.code)) + ": " + attached.message);
      break;
    }
    ++completed;
    invalidated += attached.invalidated_evaluations;
    if (i < quarter) {
      first_quarter_micros += elapsed;
    } else if (i >= kEvidenceAttaches - quarter) {
      last_quarter_micros += elapsed;
    }
  }
  const std::uint64_t total = now_micros() - start;

  WNC_CHECK_EQ(completed, kEvidenceAttaches);
  std::printf("  evidence: %zu attaches in %llu us (%llu us each), invalidated=%llu\n", completed,
              static_cast<unsigned long long>(total),
              static_cast<unsigned long long>(total / completed),
              static_cast<unsigned long long>(invalidated));

  const std::uint64_t first_per = first_quarter_micros / quarter;
  const std::uint64_t last_per = last_quarter_micros / quarter;
  const double ratio = scale_ratio(last_per, first_per);
  std::printf("  attach cost drift across the run = %.2f (bound %.1f), first=%llu us last=%llu us\n",
              ratio, kMaxScaleRatio, static_cast<unsigned long long>(first_per),
              static_cast<unsigned long long>(last_per));
  WNC_CHECK_MSG(ratio <= kMaxScaleRatio,
                "attach cost grew with the number of attaches, which is the history scan "
                "becoming quadratic");
  WNC_CHECK(total / completed <= kMaxMicrosPerEvidenceAttach);
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

WNC_TEST(scale, evaluation_completes_for_every_workload_at_scale) {
  ScaleState& state = prepare();
  WNC_CHECK_MSG(state.failure.empty(), state.failure);
  WNC_CHECK(state.ready);

  const std::vector<WorkloadId> ids = state.large->workloads();
  WNC_CHECK_EQ(ids.size(), kRegistrationLarge);

  std::size_t satisfied = 0;
  std::size_t unsatisfied = 0;
  std::size_t unknown = 0;
  std::size_t other = 0;
  std::size_t completed = 0;
  const std::uint64_t start = now_micros();
  for (const WorkloadId& id : ids) {
    const EvaluationResult evaluated = state.large->evaluate(id);
    if (!evaluated.ok) {
      WNC_CHECK_MSG(evaluated.ok, std::string(code_token(evaluated.code)) + ": " + evaluated.message);
      break;
    }
    ++completed;
    switch (evaluated.evaluation.aggregate) {
      case Satisfaction::kSatisfied:
        ++satisfied;
        break;
      case Satisfaction::kUnknown:
        ++unknown;
        break;
      case Satisfaction::kUnsatisfied:
        ++unsatisfied;
        break;
      default:
        ++other;
        break;
    }
  }
  const std::uint64_t total = now_micros() - start;
  WNC_CHECK_EQ(completed, kRegistrationLarge);
  std::printf("  evaluate %zu workloads in %llu us (%llu us each): satisfied=%zu unsatisfied=%zu "
              "unknown=%zu other=%zu\n",
              completed, static_cast<unsigned long long>(total),
              static_cast<unsigned long long>(total / completed), satisfied, unsatisfied, unknown,
              other);
  WNC_CHECK(total / completed <= kMaxMicrosPerEvaluation);

  // The last evidence attached to the suite observed this bandwidth, and every
  // workload declares a required floor of 1000.0 + index. The verdicts are
  // therefore fully determined by the data, and the expected count is derived
  // from it rather than assumed: a floor that the observation meets must be
  // SATISFIED, and a floor it does not meet must not be.
  const double observed = 9000.0 + static_cast<double>(kEvidenceAttaches - 1);
  std::size_t expected_satisfied = 0;
  std::size_t expected_unsatisfied = 0;
  for (std::size_t i = 0; i < kRegistrationLarge; ++i) {
    if (1000.0 + static_cast<double>(i) <= observed) {
      ++expected_satisfied;
    } else {
      ++expected_unsatisfied;
    }
  }
  std::printf("  expected from the data: satisfied=%zu unsatisfied=%zu (observed %.1f)\n",
              expected_satisfied, expected_unsatisfied, observed);
  WNC_CHECK_MSG(satisfied == expected_satisfied,
                "expected " + std::to_string(expected_satisfied) + " satisfied verdicts but got " +
                    std::to_string(satisfied));
  WNC_CHECK_MSG(unsatisfied == expected_unsatisfied,
                "expected " + std::to_string(expected_unsatisfied) +
                    " unsatisfied verdicts but got " + std::to_string(unsatisfied));
  // Current evidence was attached to every workload, so no verdict may fall back
  // to UNKNOWN: an unknown here would mean a supplied observation was ignored.
  WNC_CHECK_MSG(unknown == 0,
                std::to_string(unknown) +
                    " workloads reported UNKNOWN while current evidence covered them");
  WNC_CHECK_EQ(other, std::size_t(0));

  // A repeated evaluation must not become more expensive than the first pass:
  // the decision is cached against the evidence generation it was made from.
  const std::uint64_t cached_start = now_micros();
  std::size_t cached_completed = 0;
  for (const WorkloadId& id : ids) {
    if (state.large->evaluate(id).ok) {
      ++cached_completed;
    }
  }
  const std::uint64_t cached_total = now_micros() - cached_start;
  WNC_CHECK_EQ(cached_completed, kRegistrationLarge);
  const double ratio = scale_ratio(cached_total / cached_completed, total / completed);
  std::printf("  re-evaluation cost ratio = %.2f (bound %.1f)\n", ratio, kMaxScaleRatio);
  WNC_CHECK_MSG(ratio <= kMaxScaleRatio, "re-evaluation was slower than the first evaluation");
}

// ---------------------------------------------------------------------------
// Composition and diff
// ---------------------------------------------------------------------------

WNC_TEST(scale, composition_and_diff_stay_linear_in_requirements) {
  ContractBody base;
  base.schema_version = kSchemaVersion;
  base.workload.id = WorkloadId::from_digest(sha256(std::string_view("scale:composition")));
  base.workload.name = "composition";
  base.workload.generation.value = 1;
  base.generation.value = 1;
  base.policy_generation.value = 1;
  base.major = 1;
  for (std::size_t i = 0; i < kLargeScopeCount; ++i) {
    Scope scope;
    scope.name = "scope-" + std::to_string(i);
    base.scopes.push_back(scope);
  }
  for (std::size_t i = 0; i < kLargeRequirementCount; ++i) {
    Requirement requirement;
    requirement.scope = "scope-" + std::to_string(i % kLargeScopeCount);
    requirement.kind = RequirementKind::kMinBandwidth;
    requirement.strength = RequirementStrength::kRequired;
    requirement.has_numeric = true;
    requirement.target = 1000.0;
    requirement.minimum = 1000.0;
    requirement.key = "k" + std::to_string(i);
    base.requirements.push_back(requirement);
  }
  // Requirement identity is derived by canonicalisation, so the composition
  // input is canonicalised exactly as a published contract would be.
  {
    Contract canonical;
    canonical.body = base;
    (void)canonicalize(canonical);
    base = canonical.body;
  }
  WNC_CHECK_EQ(base.requirements.size(), kLargeRequirementCount);

  std::vector<OverlayLayer> layers;
  layers.reserve(kCompositionLayers);
  for (std::size_t layer = 0; layer < kCompositionLayers; ++layer) {
    OverlayLayer overlay;
    overlay.name = "layer-" + std::to_string(layer);
    for (std::size_t j = 0; j < kRequirementsPerLayer; ++j) {
      // Half the layer strengthens an existing requirement and half adds a new
      // one, so the accumulated set grows while the same keys are revisited.
      const std::size_t index = (layer * kRequirementsPerLayer + j) % kLargeRequirementCount;
      Requirement requirement;
      requirement.scope = "scope-" + std::to_string(index % kLargeScopeCount);
      requirement.kind = RequirementKind::kMinBandwidth;
      requirement.strength = RequirementStrength::kRequired;
      requirement.has_numeric = true;
      requirement.target = j < kRequirementsPerLayer / 2
                               ? 1000.0 + static_cast<double>(layer + 1) * 10.0
                               : 1000.0;
      requirement.minimum = requirement.target;
      requirement.key = j < kRequirementsPerLayer / 2
                            ? "k" + std::to_string(index)
                            : "L" + std::to_string(layer) + "-" + std::to_string(j);
      overlay.requirements.push_back(requirement);
    }
    layers.push_back(std::move(overlay));
  }

  const std::uint64_t start = now_micros();
  const CompositionResult composed = compose(base, layers);
  const std::uint64_t compose_micros = now_micros() - start;
  std::string detail = composed.message;
  for (const std::string& reason : composed.reasons()) {
    detail.append("; ").append(reason);
  }
  WNC_CHECK_MSG(composed.ok, detail);

  const std::size_t expected =
      kLargeRequirementCount + kCompositionLayers * (kRequirementsPerLayer / 2);
  std::printf("  compose %zu layers over %zu requirements in %llu us: result=%zu requirements, "
              "%zu decisions\n",
              kCompositionLayers, kLargeRequirementCount,
              static_cast<unsigned long long>(compose_micros), composed.body.requirements.size(),
              composed.decisions.size());
  WNC_CHECK_EQ(composed.body.requirements.size(), expected);
  WNC_CHECK(!composed.decisions.empty());

  // Per-requirement cost is a stable function of the work, not of the length of
  // the accumulated set. Composing the same layers again over the same base must
  // cost the same as the first time.
  const std::uint64_t repeat_start = now_micros();
  const CompositionResult repeated = compose(base, layers);
  const std::uint64_t repeat_micros = now_micros() - repeat_start;
  WNC_CHECK(repeated.ok);
  const double repeat_ratio = scale_ratio(repeat_micros, compose_micros);
  std::printf("  composition repeat cost ratio = %.2f (bound %.1f)\n", repeat_ratio,
              kMaxScaleRatio);
  WNC_CHECK_MSG(repeat_ratio <= kMaxScaleRatio, "composition cost is not stable across runs");

  // Diffing two bodies of this size is a linear comparison. The composed body
  // carries the base's generation because a composition is not itself a
  // published generation, so it is advanced here exactly as a publication would
  // advance it before compatibility is asked about it.
  ContractBody successor = composed.body;
  successor.generation.value = base.generation.value + 1;
  const std::uint64_t diff_start = now_micros();
  const CompatibilityResult compatibility = check_compatibility(base, successor);
  const std::uint64_t diff_micros = now_micros() - diff_start;
  std::printf("  diff %zu -> %zu requirements in %llu us: compatible=%d\n",
              base.requirements.size(), composed.body.requirements.size(),
              static_cast<unsigned long long>(diff_micros), compatibility.compatible() ? 1 : 0);
  for (const std::string& reason : compatibility.reasons()) {
    std::printf("    compatibility reason: %s\n", reason.c_str());
  }
  WNC_CHECK(compatibility.compatible());
  WNC_CHECK(diff_micros <= compose_micros * 4 + 1000);
}

// ---------------------------------------------------------------------------
// Journal reopen and recovery
// ---------------------------------------------------------------------------

WNC_TEST(scale, journal_recovery_rebuilds_ten_thousand_records) {
  ScaleState& state = prepare();
  WNC_CHECK_MSG(state.failure.empty(), state.failure);
  WNC_CHECK(state.ready);

  // Close the large runtime, which is the state a killed coordinator leaves, and
  // reopen it. Recovery has to read every record and rebuild the index.
  state.large.reset();

  Code code = Code::kOk;
  std::string message;
  const std::uint64_t start = now_micros();
  std::optional<Runtime> reopened =
      Runtime::open(options_for(state.trust, state.large_directory), code, message);
  const std::uint64_t recovery_micros = now_micros() - start;
  WNC_CHECK_MSG(reopened.has_value(), message);
  WNC_CHECK_EQ(reopened->workloads().size(), kRegistrationLarge);

  std::printf("  reopen with %zu workloads in %llu us (%llu us per record)\n",
              reopened->workloads().size(), static_cast<unsigned long long>(recovery_micros),
              static_cast<unsigned long long>(recovery_micros / kRegistrationLarge));
  WNC_CHECK(recovery_micros / kRegistrationLarge <= kMaxMicrosPerRecoveryRecord);

  // The recovered index has to agree with the journal it was rebuilt from.
  Code history_code = Code::kOk;
  std::string history_message;
  const std::uint64_t verify_start = now_micros();
  const bool verified = reopened->verify_history(history_code, history_message);
  const std::uint64_t verify_micros = now_micros() - verify_start;
  WNC_CHECK_MSG(verified, std::string(code_token(history_code)) + ": " + history_message);
  std::printf("  verify_history over %zu workloads in %llu us\n", reopened->workloads().size(),
              static_cast<unsigned long long>(verify_micros));

  // Durable history survived, and the restart did not restore liveness: the
  // evaluations restored from the journal are history, not current decisions.
  const std::vector<WorkloadId> ids = reopened->workloads();
  const EvaluationResult restored = reopened->evaluate(ids.front());
  WNC_CHECK(restored.ok);
  WNC_CHECK_MSG(restored.evaluation.aggregate != Satisfaction::kSatisfied ||
                    restored.evaluation.requirements.empty(),
                "a restarted coordinator served a durable evaluation as currently satisfied "
                "without revalidating its evidence");
  std::printf("  first workload aggregate after restart = %s\n",
              std::string(satisfaction_token(restored.evaluation.aggregate)).c_str());

  state.large = std::make_unique<Runtime>(std::move(*reopened));
}
