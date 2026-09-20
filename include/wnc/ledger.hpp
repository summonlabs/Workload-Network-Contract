// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Durable append-only history with an explicit durability point.
//
// Journal layout inside one state directory:
//
//   head.bin      fixed size boot record: format version, reserved fields, the
//                 coordinator identity, the trust digest, the epoch of the most
//                 recent boot, and the sequence of the last durable record;
//   journal.log   framed records, appended and flushed before any
//                 acknowledgement is returned;
//   snapshot.bin  the derived state at a sequence, written whole with an atomic
//                 replace. It is a materialised index, never an authority: a
//                 snapshot whose sequence is ahead of the journal is refused.
//
// Framing (all integers little-endian):
//
//   offset  size  field
//   0       4     magic "WNL1"
//   4       2     format version
//   6       2     record type
//   8       8     sequence, strictly increasing from 1
//   16      8     payload length in bytes
//   24      32    sha256 of the payload bytes
//   56      32    sha256 of the previous record's chain value
//   88      4     crc32 of bytes 0..87 of this header
//   92      ...   payload
//
// The chain value of record n is sha256 of its header prefix (bytes 0..87) and
// its payload. Any edit, removal, or reordering breaks the chain, and a torn
// tail is detectable because a frame that cannot be read completely is not a
// frame. Recovery truncates a torn tail, records that it did so, and never
// reports the truncated records as durable.

#ifndef WNC_LEDGER_HPP
#define WNC_LEDGER_HPP

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "wnc/error.hpp"
#include "wnc/hash.hpp"
#include "wnc/identity.hpp"
#include "wnc/json.hpp"

namespace wnc::ledger {

inline constexpr std::uint32_t kRecordMagic = 0x314C4E57u;  // "WNL1" little-endian
inline constexpr std::size_t kFrameHeaderBytes = 92;

enum class RecordType : std::uint16_t {
  kUnknown = 0,
  kGenesis = 1,
  kWorkloadRegistered = 2,
  kContractPublished = 3,
  kWorkloadRetired = 4,
  kEvidenceAttached = 5,
  kPolicyInstalled = 6,
  kEvaluationRecorded = 7,
  kRecoveryMarker = 8,
};

std::string_view record_type_token(RecordType type) noexcept;
std::optional<RecordType> parse_record_type(std::string_view token) noexcept;

struct Record {
  std::uint64_t sequence = 0;
  RecordType type = RecordType::kUnknown;
  std::string payload;
  // SHA-256 of the payload bytes, as stored in the record header.
  Digest payload_digest{};
  // The chain value of the record before this one, as stored in the header. It
  // is the link that makes a removed, duplicated, or reordered record visible.
  Digest previous_chain{};
  // This record's own chain value: the digest of the first 88 header bytes with
  // the link field zeroed, followed by the payload. A reader recomputes it from
  // the bytes on disk rather than trusting the file.
  Digest chain{};
};

struct RecordView {
  const Record* record = nullptr;
  Json payload;
  bool decoded = false;
};

struct RecoveryReport {
  bool recovered = false;
  std::uint64_t valid_records = 0;
  std::uint64_t truncated_bytes = 0;
  std::uint64_t last_valid_sequence = 0;
  // Bytes of the last segment that belong to complete records. Everything after
  // this offset is a torn tail and is removed by recovery.
  std::uint64_t valid_bytes = 0;
  // Segments above the one that holds the last valid record, which recovery
  // removes.
  std::uint64_t excess_segments = 0;
  bool chain_break = false;
  std::string detail;
};

struct HeadRecord {
  std::uint32_t format_version = 0;
  CoordinatorId coordinator{};
  Digest trust_digest{};
  std::uint64_t epoch = 0;
  Incarnation incarnation{};
  std::uint64_t last_sequence = 0;
  std::uint64_t boot_count = 0;
};

// The payload of a kGenesis record, which binds a journal to its coordinator,
// its trust set, and the boot that created it.
struct GenesisPayload {
  std::uint32_t format_version = 0;
  CoordinatorId coordinator{};
  Digest trust_digest{};
  std::uint64_t epoch = 0;
  Incarnation incarnation{};
};

class Ledger {
 public:
  Ledger() = default;
  Ledger(Ledger&&) noexcept = default;
  Ledger& operator=(Ledger&&) noexcept = default;
  Ledger(const Ledger&) = delete;
  Ledger& operator=(const Ledger&) = delete;
  ~Ledger();

  // Opens or creates a state directory. Assigns a new epoch and incarnation.
  // When recovery truncated a torn tail it is reported; it is never silent.
  static std::optional<Ledger> open(const std::filesystem::path& directory, const CoordinatorId& coordinator,
                                    const Digest& trust_digest, RecoveryReport& recovery, Code& code,
                                    std::string& message);

  [[nodiscard]] bool is_open() const noexcept { return open_; }
  [[nodiscard]] const HeadRecord& head() const noexcept { return head_; }
  [[nodiscard]] std::uint64_t last_sequence() const noexcept { return head_.last_sequence; }
  [[nodiscard]] const std::filesystem::path& directory() const noexcept { return directory_; }
  [[nodiscard]] std::uint64_t segment_count() const noexcept { return segment_count_; }
  // Total journal bytes retained across every segment.
  [[nodiscard]] std::uint64_t retained_bytes() const noexcept { return retained_bytes_; }

  // Appends a record and flushes it to the operating system. Returns false and
  // leaves no partial frame at the durability point on failure.
  bool append(RecordType type, std::string_view payload, std::uint64_t& sequence, Code& code,
              std::string& message);

  // Reads every valid record in order. Stops at the first frame that is not
  // completely readable, and reports where it stopped.
  bool read_all(std::vector<Record>& records, RecoveryReport& report, Code& code,
                std::string& message) const;

  // Reads every valid record, discarding the recovery report. Intended for
  // inspection and diagnostics, never for a durability decision.
  [[nodiscard]] std::vector<Record> read_all() const;

  // Reads records with a sequence above the given value.
  bool read_after(std::uint64_t sequence, std::vector<Record>& records, RecoveryReport& report,
                  Code& code, std::string& message) const;

  // Snapshot support. The snapshot is a derived index; it is never authority.
  // A snapshot carries the epoch it was materialised in. It is a derived index:
  // it may only be used when its sequence is at or behind the journal's durable
  // sequence, and it is discarded (with a full journal replay) when the epoch
  // differs, because a new boot must not inherit decisions from an old one.
  struct Snapshot {
    std::uint64_t sequence = 0;
    std::uint64_t epoch = 0;
    std::string payload;
  };

  bool write_snapshot(const Snapshot& snapshot, Code& code, std::string& message);
  bool read_snapshot(Snapshot& snapshot, bool& present, Code& code, std::string& message) const;

  // Truncates the journal to a sequence boundary. Used only by recovery.
  bool truncate_to(std::uint64_t sequence, Code& code, std::string& message);

  // Rewrites the head with the current epoch, incarnation, and sequence.
  bool write_head(Code& code, std::string& message);

 private:
  bool load_head(Code& code, std::string& message);
  bool append_raw(std::string_view frame, Code& code, std::string& message);
  bool rotate_segment(Code& code, std::string& message);
  bool read_frames(std::vector<Record>& records, RecoveryReport& report, bool stop_at_torn,
                   Code& code, std::string& message) const;
  [[nodiscard]] std::filesystem::path segment_path(std::uint64_t segment) const;

  std::filesystem::path directory_;
  std::filesystem::path head_path_;
  std::filesystem::path snapshot_path_;
  HeadRecord head_{};
  Digest chain_{};
  std::uint64_t segment_ = 0;
  std::uint64_t segment_bytes_ = 0;
  std::uint64_t segment_count_ = 0;
  std::uint64_t retained_bytes_ = 0;
  bool open_ = false;
};

// Builds the byte string for one frame. Exposed for adversarial tests.
std::string build_frame(RecordType type, std::uint64_t sequence, std::string_view payload,
                        const Digest& previous_chain, Digest& chain_out, Digest& payload_out);

// Parses one frame starting at the given offset. Returns false when the frame is
// incomplete or inconsistent, and reports how many bytes were consumed.
bool parse_frame(std::string_view bytes, std::size_t offset, Record& record, std::size_t& consumed,
                 Code& code, std::string& message);

}  // namespace wnc::ledger

#endif  // WNC_LEDGER_HPP
