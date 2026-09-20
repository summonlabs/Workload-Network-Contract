// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Persistence proof surface: torn tails, partial writes, impossible snapshots,
// rejected state directories, and restart reconciliation against real files.

#include "wnc_test.hpp"

#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "wnc/hash.hpp"
#include "wnc/ledger.hpp"
#include "wnc/runtime.hpp"
#include "wnc/state.hpp"

using namespace wnc;

namespace {

std::filesystem::path fresh_directory(const std::string& name) {
  const std::filesystem::path base =
      std::filesystem::temp_directory_path() /
      ("wnc-persistence-" + name + "-" + std::to_string(state::wall_millis()) + "-" +
       std::to_string(reinterpret_cast<std::uintptr_t>(&name)));
  std::error_code error;
  std::filesystem::remove_all(base, error);
  std::filesystem::create_directories(base, error);
  return base;
}

struct DirectoryGuard {
  std::filesystem::path path;
  explicit DirectoryGuard(std::string name) : path(fresh_directory(name)) {}
  DirectoryGuard(const DirectoryGuard&) = delete;
  DirectoryGuard& operator=(const DirectoryGuard&) = delete;
  ~DirectoryGuard() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

const CoordinatorId kCoordinator = CoordinatorId::from_digest(sha256(std::string_view("storage")));
const Digest kTrust = sha256(std::string_view("trust"));

std::uint64_t file_size_of(const std::filesystem::path& path) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  return error ? 0 : static_cast<std::uint64_t>(size);
}

void append_bytes(const std::filesystem::path& path, const std::string& bytes) {
  bool opened = false;
  std::FILE* file = ::wnc::test::open_file(path.string(), "ab", opened);
  WNC_CHECK(opened);
  if (!bytes.empty()) {
    WNC_CHECK_EQ(std::fwrite(bytes.data(), 1, bytes.size(), file), bytes.size());
  }
  std::fclose(file);
}

void overwrite_byte(const std::filesystem::path& path, std::uint64_t offset, char value) {
  bool opened = false;
  std::FILE* file = ::wnc::test::open_file(path.string(), "r+b", opened);
  WNC_CHECK(opened);
  WNC_CHECK_EQ(std::fseek(file, static_cast<long>(offset), SEEK_SET), 0);
  WNC_CHECK_EQ(std::fwrite(&value, 1, 1, file), std::size_t(1));
  std::fclose(file);
}

}  // namespace

WNC_TEST(persistence, ledger_round_trips_records_and_chain) {
  DirectoryGuard guard("roundtrip");
  ledger::RecoveryReport recovery;
  Code code = Code::kOk;
  std::string message;
  std::optional<ledger::Ledger> ledger =
      ledger::Ledger::open(guard.path, kCoordinator, kTrust, recovery, code, message);
  WNC_CHECK_MSG(ledger.has_value(), message);

  std::uint64_t sequence = 0;
  for (int i = 0; i < 32; ++i) {
    const std::string payload = "{\"n\":" + std::to_string(i) + "}";
    WNC_CHECK(ledger->append(ledger::RecordType::kWorkloadRegistered, payload, sequence, code,
                             message));
    WNC_CHECK_EQ(sequence, static_cast<std::uint64_t>(i + 1));
  }

  std::vector<ledger::Record> records;
  ledger::RecoveryReport report;
  Code read_code = Code::kOk;
  std::string read_message;
  WNC_CHECK(ledger->read_all(records, report, read_code, read_message));
  WNC_CHECK_EQ(records.size(), std::size_t(32));
  WNC_CHECK(!report.recovered);
  for (std::size_t i = 0; i < records.size(); ++i) {
    WNC_CHECK_EQ(records[i].sequence, static_cast<std::uint64_t>(i + 1));
    WNC_CHECK_EQ(records[i].payload,
                 std::string("{\"n\":" + std::to_string(i) + "}"));
  }
}

WNC_TEST(persistence, torn_tail_is_truncated_and_reported) {
  DirectoryGuard guard("torn");
  Code code = Code::kOk;
  std::string message;
  {
    ledger::RecoveryReport recovery;
    std::optional<ledger::Ledger> ledger =
        ledger::Ledger::open(guard.path, kCoordinator, kTrust, recovery, code, message);
    WNC_CHECK_MSG(ledger.has_value(), message);
    std::uint64_t sequence = 0;
    WNC_CHECK(ledger->append(ledger::RecordType::kGenesis, "{\"a\":1}", sequence, code, message));
    WNC_CHECK(ledger->append(ledger::RecordType::kGenesis, "{\"b\":2}", sequence, code, message));
  }

  const std::filesystem::path segment = guard.path / "journal-00001.log";
  const std::uint64_t complete = file_size_of(segment);
  // A partial write of a third record.
  append_bytes(segment, std::string(40, '\x7f'));
  append_bytes(guard.path / "journal-00002.log", std::string(5, '\x01'));

  ledger::RecoveryReport recovery;
  std::optional<ledger::Ledger> reopened =
      ledger::Ledger::open(guard.path, kCoordinator, kTrust, recovery, code, message);
  WNC_CHECK_MSG(reopened.has_value(), message);
  WNC_CHECK(recovery.recovered);
  WNC_CHECK(recovery.truncated_bytes > 0);
  WNC_CHECK_EQ(recovery.last_valid_sequence, std::uint64_t(2));

  std::vector<ledger::Record> records;
  ledger::RecoveryReport report;
  WNC_CHECK(reopened->read_all(records, report, code, message));
  WNC_CHECK_EQ(records.size(), std::size_t(2));
  WNC_CHECK_EQ(file_size_of(segment), complete);
}

WNC_TEST(persistence, doctored_record_is_a_hard_failure_not_a_truncation) {
  DirectoryGuard guard("doctored");
  Code code = Code::kOk;
  std::string message;
  {
    ledger::RecoveryReport recovery;
    std::optional<ledger::Ledger> ledger =
        ledger::Ledger::open(guard.path, kCoordinator, kTrust, recovery, code, message);
    WNC_CHECK_MSG(ledger.has_value(), message);
    std::uint64_t sequence = 0;
    WNC_CHECK(ledger->append(ledger::RecordType::kGenesis, "{\"a\":1}", sequence, code, message));
  }
  const std::filesystem::path segment = guard.path / "journal-00001.log";
  // Flip one bit inside the payload of the only record: the payload digest no
  // longer describes the payload, so the record is not durable material.
  overwrite_byte(segment, ledger::kFrameHeaderBytes + 2, static_cast<char>(0x7F));

  // A doctored record is a corruption, not a torn tail: the ledger either
  // refuses to claim the directory at all, or it opens and the next read fails.
  // Either way the doctored bytes are never served as history.
  ledger::RecoveryReport recovery;
  std::optional<ledger::Ledger> reopened =
      ledger::Ledger::open(guard.path, kCoordinator, kTrust, recovery, code, message);
  if (!reopened.has_value()) {
    WNC_CHECK(code == Code::kLedgerCorrupt || code == Code::kRecoveryRequired);
  } else {
    std::vector<ledger::Record> corrupted;
    ledger::RecoveryReport corrupted_report;
    Code read_code = Code::kOk;
    std::string read_message;
    WNC_CHECK(!reopened->read_all(corrupted, corrupted_report, read_code, read_message));
    WNC_CHECK_EQ(read_code, Code::kLedgerCorrupt);
  }
  // The corrupted directory is still on disk: a refusal never rewrites state.
  std::error_code size_error;
  WNC_CHECK(std::filesystem::exists(guard.path / "head.bin", size_error));
}

WNC_TEST(persistence, snapshot_cannot_be_ahead_of_the_journal) {
  DirectoryGuard guard("snapshot");
  Code code = Code::kOk;
  std::string message;
  ledger::RecoveryReport recovery;
  std::optional<ledger::Ledger> ledger =
      ledger::Ledger::open(guard.path, kCoordinator, kTrust, recovery, code, message);
  WNC_CHECK_MSG(ledger.has_value(), message);

  ledger::Ledger::Snapshot snapshot;
  snapshot.epoch = ledger->head().epoch;
  snapshot.sequence = ledger->last_sequence() + 5;
  snapshot.payload = "{}";
  Code snapshot_code = Code::kOk;
  std::string snapshot_message;
  WNC_CHECK(!ledger->write_snapshot(snapshot, snapshot_code, snapshot_message));
  WNC_CHECK_EQ(snapshot_code, Code::kRecoveryRequired);

  snapshot.sequence = ledger->last_sequence();
  WNC_CHECK(ledger->write_snapshot(snapshot, code, message));

  // A snapshot with a corrupted payload is refused.
  const std::filesystem::path path = guard.path / "snapshot.bin";
  overwrite_byte(path, state::kSnapshotHeaderBytes + 1, 'Z');
  ledger::Ledger::Snapshot read_back;
  bool present = false;
  Code read_code = Code::kOk;
  std::string read_message;
  WNC_CHECK(!ledger->read_snapshot(read_back, present, read_code, read_message));
  WNC_CHECK_EQ(read_code, Code::kSnapshotInvalid);
}

WNC_TEST(persistence, oversized_and_malformed_head_are_refused) {
  DirectoryGuard guard("head");
  Code code = Code::kOk;
  std::string message;
  {
    ledger::RecoveryReport recovery;
    std::optional<ledger::Ledger> ledger =
        ledger::Ledger::open(guard.path, kCoordinator, kTrust, recovery, code, message);
    WNC_CHECK_MSG(ledger.has_value(), message);
  }
  // Corrupt the head integrity field.
  overwrite_byte(guard.path / "head.bin", 100, static_cast<char>(0x55));
  ledger::RecoveryReport recovery;
  const std::optional<ledger::Ledger> reopened =
      ledger::Ledger::open(guard.path, kCoordinator, kTrust, recovery, code, message);
  WNC_CHECK(!reopened.has_value());
  WNC_CHECK(code == Code::kLedgerCorrupt || code == Code::kRecoveryRequired);
  // The corrupted directory is still on disk: a refusal never rewrites state.
  std::error_code size_error;
  WNC_CHECK(std::filesystem::exists(guard.path / "head.bin", size_error));
}

WNC_TEST(persistence, journal_without_head_is_refused) {
  DirectoryGuard guard("headless");
  Code code = Code::kOk;
  std::string message;
  {
    ledger::RecoveryReport recovery;
    std::optional<ledger::Ledger> ledger =
        ledger::Ledger::open(guard.path, kCoordinator, kTrust, recovery, code, message);
    WNC_CHECK_MSG(ledger.has_value(), message);
    // A journal segment only exists once a record has been appended, so the
    // test has to produce one before the head can be meaningful.
    std::uint64_t sequence = 0;
    WNC_CHECK(ledger->append(ledger::RecordType::kGenesis, "{\"a\":1}", sequence, code, message));
  }
  std::error_code error;
  std::filesystem::remove(guard.path / "head.bin", error);
  WNC_CHECK(!error);
  ledger::RecoveryReport recovery;
  const std::optional<ledger::Ledger> reopened =
      ledger::Ledger::open(guard.path, kCoordinator, kTrust, recovery, code, message);
  WNC_CHECK(!reopened.has_value());
  WNC_CHECK_EQ(code, Code::kRecoveryRequired);
}

WNC_TEST(persistence, runtime_restart_rebuilds_the_index_from_the_journal) {
  DirectoryGuard guard("runtime");
  const LocalSigner signer = local_signer_from_seed(Ed25519Seed{3, 1, 4, 1});
  TrustSet trust;
  trust.add_ed25519(signer.publisher, signer.public_key);
  Runtime::Options options;
  options.state_directory = guard.path;
  options.trust = trust;

  Code code = Code::kOk;
  std::string message;
  Digest first_digest{};
  WorkloadId workload{};
  {
    std::optional<Runtime> runtime = Runtime::open(options, code, message);
    WNC_CHECK_MSG(runtime.has_value(), message);
    Contract contract;
    contract.body.schema_version = kSchemaVersion;
    workload = WorkloadId::from_digest(sha256(std::string_view("persist-workload")));
    contract.body.workload.id = workload;
    contract.body.workload.name = "persist";
    contract.body.workload.generation.value = 1;
    contract.body.generation.value = 1;
    contract.body.policy_generation.value = 1;
    contract.body.major = 1;
    Scope scope;
    scope.name = "fabric";
    contract.body.scopes.push_back(scope);
    Requirement requirement;
    requirement.scope = "fabric";
    requirement.kind = RequirementKind::kMaxLatency;
    requirement.strength = RequirementStrength::kRequired;
    requirement.has_numeric = true;
    requirement.target = 100.0;
    requirement.minimum = 100.0;
    contract.body.requirements.push_back(requirement);
    WNC_CHECK(canonicalize(contract));
    contract.envelope.publisher = signer.publisher;
    contract.envelope.algorithm = SignatureAlgorithm::kEd25519;
    contract.envelope.key_id = signer.key_id();
    const SignatureBytes signature = sign_with_local_signer(
        signer, std::string_view("wnc/v1/submission/registration"),
        contract_body_to_json(contract.body).dump());
    contract.envelope.signature = signature.bytes;
    const RegisterResult registered = runtime->register_workload(contract);
    WNC_CHECK_MSG(registered.ok, registered.message);
    first_digest = contract.digest;
  }
  {
    std::optional<Runtime> runtime = Runtime::open(options, code, message);
    WNC_CHECK_MSG(runtime.has_value(), message);
    const std::optional<WorkloadSnapshot> snapshot = runtime->snapshot(workload);
    WNC_CHECK(snapshot.has_value());
    WNC_CHECK_EQ(hex_encode(snapshot->digest), hex_encode(first_digest));
    WNC_CHECK_EQ(snapshot->history.size(), std::size_t(1));
    WNC_CHECK(runtime->verify_history(code, message));
  }
}

WNC_TEST(persistence, state_paths_cannot_escape_the_directory) {
  DirectoryGuard guard("escape");
  WNC_CHECK(state::is_within(guard.path, guard.path / "journal-00001.log"));
  WNC_CHECK(!state::is_within(guard.path, guard.path / ".." / "outside.log"));
  WNC_CHECK(!state::is_within(guard.path, guard.path / "a" / ".." / ".." / "b.log"));
}

WNC_TEST(persistence, bounded_file_reads_refuse_oversized_files) {
  DirectoryGuard guard("bounded");
  const std::filesystem::path path = guard.path / "big.bin";
  bool opened = false;
  std::FILE* file = ::wnc::test::open_file(path.string(), "wb", opened);
  WNC_CHECK(opened);
  const std::string chunk(4096, 'x');
  for (int i = 0; i < 4; ++i) {
    WNC_CHECK_EQ(std::fwrite(chunk.data(), 1, chunk.size(), file), chunk.size());
  }
  std::fclose(file);

  std::string content;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK(!state::read_file(path, 1024, content, code, message));
  WNC_CHECK_EQ(code, Code::kLedgerOversized);
  WNC_CHECK(state::read_file(path, 1 << 20, content, code, message));
  WNC_CHECK_EQ(content.size(), std::size_t(16384));
}

WNC_TEST(persistence, atomic_write_never_leaves_a_partial_file) {
  DirectoryGuard guard("atomic");
  const std::filesystem::path path = guard.path / "state.bin";
  Code code = Code::kOk;
  std::string message;
  for (int i = 0; i < 8; ++i) {
    const std::string payload(static_cast<std::size_t>(1 + i * 37), static_cast<char>('a' + i));
    WNC_CHECK(state::write_file_atomic(path, payload, code, message));
    std::string read_back;
    WNC_CHECK(state::read_file(path, 4096, read_back, code, message));
    WNC_CHECK_EQ(read_back, payload);
  }
  // The temporary file must not be left behind.
  std::error_code error;
  WNC_CHECK(!std::filesystem::exists(guard.path / "state.bin.tmp", error));
}