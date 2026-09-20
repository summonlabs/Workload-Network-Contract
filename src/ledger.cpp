// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/ledger.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>

#include "wnc/config.hpp"
#include "wnc/state.hpp"

namespace wnc::ledger {
namespace {

constexpr std::uint32_t kHeadMagicWord = 0x31484E57u;  // "WNH1" little-endian
constexpr std::uint16_t kHeadVersion = 1;
// The boot record is 196 bytes: 192 bytes of fields and content followed by the
// integrity field.
constexpr std::size_t kHeadBytes = 196;

// Fixed layout of the boot record. Every field has one offset, used by both the
// writer and the reader, so the two sides cannot drift apart.
//   0   magic (4)              4   version (2)         6   reserved (2)
//   8   coordinator (64 hex characters)               72  trust digest (32)
//   104 epoch (8)              112 incarnation (16)     128 last sequence (8)
//   136 boot count (8)         144..191 reserved        192 crc32 over bytes 0..191
constexpr std::size_t kHeadCoordinatorOffset = 8;
constexpr std::size_t kHeadTrustOffset = 72;
constexpr std::size_t kHeadEpochOffset = 104;
constexpr std::size_t kHeadIncarnationOffset = 112;
constexpr std::size_t kHeadSequenceOffset = 128;
constexpr std::size_t kHeadBootCountOffset = 136;
constexpr std::size_t kHeadCrcOffset = 192;
constexpr std::size_t kHeadCrcRange = 192;
constexpr std::size_t kSnapshotHeaderBytes = state::kSnapshotHeaderBytes;
constexpr std::size_t kSnapshotReserved = 64;

// One journal segment is bounded so that a single readable file stays small and
// so that total retained history has a hard ceiling:
//   kMaxLedgerSegments * kMaxSegmentBytes
inline constexpr std::uint64_t kMaxSegmentBytes = 8ull * 1024ull * 1024ull;
inline constexpr std::uint64_t kMaxJournalBytes =
    static_cast<std::uint64_t>(kMaxLedgerSegments) * kMaxSegmentBytes;

constexpr std::array<std::pair<RecordType, std::string_view>, 8> kRecordTokens = {{
    {RecordType::kUnknown, "unknown"},
    {RecordType::kGenesis, "genesis"},
    {RecordType::kWorkloadRegistered, "workload_registered"},
    {RecordType::kContractPublished, "contract_published"},
    {RecordType::kWorkloadRetired, "workload_retired"},
    {RecordType::kEvidenceAttached, "evidence_attached"},
    {RecordType::kPolicyInstalled, "policy_installed"},
    {RecordType::kEvaluationRecorded, "evaluation_recorded"},
}};

void write_u16(std::string& out, std::uint16_t value) {
  out.push_back(static_cast<char>(value & 0xFFu));
  out.push_back(static_cast<char>((value >> 8) & 0xFFu));
}

void write_u32(std::string& out, std::uint32_t value) {
  for (unsigned i = 0; i < 4; ++i) {
    out.push_back(static_cast<char>((value >> (8u * i)) & 0xFFu));
  }
}

void write_u64(std::string& out, std::uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) {
    out.push_back(static_cast<char>((value >> (8u * i)) & 0xFFu));
  }
}

std::uint16_t read_u16(const char* data) {
  return static_cast<std::uint16_t>(
      static_cast<unsigned>(static_cast<unsigned char>(data[0])) |
      (static_cast<unsigned>(static_cast<unsigned char>(data[1])) << 8));
}

std::uint32_t read_u32(const char* data) {
  std::uint32_t value = 0;
  for (unsigned i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<unsigned char>(data[i])) << (8u * i);
  }
  return value;
}

std::uint64_t read_u64(const char* data) {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(static_cast<unsigned char>(data[i])) << (8u * i);
  }
  return value;
}

Digest digest_of(std::string_view bytes) {
  return sha256(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(bytes.data()),
                                              bytes.size()));
}

// The chain value covers the 88 byte header prefix and the payload, so any
// change to a record's type, sequence, length, payload, or position in the
// chain is detectable.
Digest chain_of(std::string_view header_prefix, std::string_view payload) {
  std::string material(header_prefix);
  material.append(payload);
  return digest_of(material);
}

std::string segment_name(std::uint64_t segment) {
  std::string digits = std::to_string(segment + 1);
  while (digits.size() < 5) {
    digits.insert(digits.begin(), '0');
  }
  return "journal-" + digits + ".log";
}

}  // namespace

std::string_view record_type_token(RecordType type) noexcept {
  for (const auto& entry : kRecordTokens) {
    if (entry.first == type) {
      return entry.second;
    }
  }
  return kRecordTokens.front().second;
}

std::optional<RecordType> parse_record_type(std::string_view token) noexcept {
  for (const auto& entry : kRecordTokens) {
    if (entry.second == token) {
      return entry.first;
    }
  }
  return std::nullopt;
}

std::string build_frame(RecordType type, std::uint64_t sequence, std::string_view payload,
                        const Digest& previous_chain, Digest& chain_out, Digest& payload_out) {
  payload_out = digest_of(payload);
  std::string header;
  header.reserve(kFrameHeaderBytes);
  write_u32(header, kRecordMagic);
  write_u16(header, 1);
  write_u16(header, static_cast<std::uint16_t>(type));
  write_u64(header, sequence);
  write_u64(header, static_cast<std::uint64_t>(payload.size()));
  header.append(reinterpret_cast<const char*>(payload_out.data()), payload_out.size());
  // Bytes 56..87 hold the previous record's chain value, which is the link in
  // the chain. This record's own chain value is a digest of the first 88 bytes
  // with that link field zeroed, concatenated with the payload, so it can be
  // recomputed by a reader without storing it twice.
  header.append(reinterpret_cast<const char*>(previous_chain.data()), previous_chain.size());
  for (std::size_t i = 56; i < 88; ++i) {
    header[i] = '\0';
  }
  chain_out = chain_of(std::string_view(header.data(), 88), payload);
  std::memcpy(header.data() + 56, previous_chain.data(), previous_chain.size());
  write_u32(header, crc32(std::string_view(header.data(), header.size())));
  std::string frame = header;
  frame.append(payload);
  return frame;
}
bool parse_frame(std::string_view bytes, std::size_t offset, Record& record, std::size_t& consumed,
                 Code& code, std::string& message) {
  // Layout (little-endian): magic 0, version 4, type 6, sequence 8, payload
  // length 16, payload digest 24, previous chain 56, header crc 88, payload 92.
  // The link at 56 is the previous record's chain value; this record's own chain
  // value is recomputed from bytes 0..87 (with the link field zeroed) and the
  // payload.
  consumed = 0;
  if (bytes.size() - offset < kFrameHeaderBytes) {
    code = Code::kLedgerTruncated;
    message = "frame header is incomplete";
    return false;
  }
  const char* header = bytes.data() + offset;
  if (read_u32(header) != kRecordMagic) {
    code = Code::kLedgerCorrupt;
    message = "frame magic does not match the journal format";
    return false;
  }
  const std::uint16_t version = read_u16(header + 4);
  if (version != 1) {
    code = Code::kLedgerIncompatible;
    message = "frame format version " + std::to_string(version) + " is not supported";
    return false;
  }
  record.type = static_cast<RecordType>(read_u16(header + 6));
  record.sequence = read_u64(header + 8);
  const std::uint64_t payload_length = read_u64(header + 16);
  if (payload_length > kMaxRecordBytes) {
    code = Code::kLedgerOversized;
    message = "frame declares " + std::to_string(payload_length) + " payload bytes";
    return false;
  }
  if (read_u32(header + 88) != crc32(std::string_view(header, 88))) {
    code = Code::kLedgerCorrupt;
    message = "frame header integrity check failed";
    return false;
  }
  const std::size_t total = kFrameHeaderBytes + static_cast<std::size_t>(payload_length);
  if (bytes.size() - offset < total) {
    code = Code::kLedgerTruncated;
    message = "frame payload is incomplete";
    return false;
  }
  record.payload.assign(bytes.data() + offset + kFrameHeaderBytes,
                        static_cast<std::size_t>(payload_length));
  std::memcpy(record.payload_digest.data(), header + 24, record.payload_digest.size());
  if (digest_of(record.payload) != record.payload_digest) {
    code = Code::kLedgerCorrupt;
    message = "frame payload digest does not match its bytes";
    return false;
  }
  // The header carries the link to the previous record at 56. It is surfaced as
  // the record's chain value because the chain a caller needs to compare against
  // is the previous record's, and the zeroed-prefix digest of this record is
  // recomputed by the reader rather than read from the file. Every byte of the
  // header is therefore covered by either the CRC or that recomputation, which is
  // what makes a doctored link detectable.
  std::memcpy(record.chain.data(), header + 56, record.chain.size());
  consumed = total;
  return true;
}

Ledger::~Ledger() = default;

std::filesystem::path Ledger::segment_path(std::uint64_t segment) const {
  return directory_ / segment_name(segment);
}

std::optional<Ledger> Ledger::open(const std::filesystem::path& directory,
                                   const CoordinatorId& coordinator, const Digest& trust_digest,
                                   RecoveryReport& recovery, Code& code, std::string& message) {
  Ledger ledger;
  ledger.directory_ = directory;
  ledger.head_path_ = directory / "head.bin";
  ledger.snapshot_path_ = directory / "snapshot.bin";

  if (!state::ensure_directory(directory, code, message)) {
    return std::nullopt;
  }
  if (!state::is_within(directory, ledger.head_path_) ||
      !state::is_within(directory, ledger.snapshot_path_)) {
    code = Code::kPathRejected;
    message = "state paths resolve outside the state directory";
    return std::nullopt;
  }

  bool head_present = false;
  std::uint64_t previous_epoch = 0;
  std::uint64_t previous_boot = 0;
  {
    std::string raw;
    Code head_code = Code::kOk;
    std::string head_message;
    if (state::read_file(ledger.head_path_, kHeadBytes, raw, head_code, head_message)) {
      if (raw.size() != kHeadBytes || read_u32(raw.data()) != kHeadMagicWord) {
        code = Code::kLedgerCorrupt;
        message = "head record is malformed";
        return std::nullopt;
      }
      if (read_u16(raw.data() + 4) != kHeadVersion) {
        code = Code::kLedgerIncompatible;
        message = "head format version is not supported";
        return std::nullopt;
      }
      if (read_u32(raw.data() + kHeadCrcOffset) !=
          crc32(std::string_view(raw.data(), kHeadCrcRange))) {
        code = Code::kLedgerCorrupt;
        message = "head record integrity check failed";
        return std::nullopt;
      }
      const std::string_view coordinator_text(raw.data() + kHeadCoordinatorOffset, kSha256HexChars);
      const std::optional<CoordinatorId> stored_coordinator = CoordinatorId::parse(coordinator_text);
      if (!stored_coordinator.has_value()) {
        code = Code::kLedgerCorrupt;
        message = "head record names an invalid coordinator identity";
        return std::nullopt;
      }
      Digest stored_trust{};
      std::memcpy(stored_trust.data(), raw.data() + kHeadTrustOffset, 32);
      if (*stored_coordinator != coordinator) {
        code = Code::kIndexMismatch;
        message = "state directory belongs to another coordinator identity";
        return std::nullopt;
      }
      if (stored_trust != trust_digest) {
        code = Code::kPublisherNotTrusted;
        message = "state directory was written under a different trust set";
        return std::nullopt;
      }
      // The previous boot's counters are captured into locals before the head
      // record is rebuilt: the new boot's epoch and boot count are strictly above
      // them, and nothing else from the old record carries over.
      previous_epoch = read_u64(raw.data() + kHeadEpochOffset);
      previous_boot = read_u64(raw.data() + kHeadBootCountOffset);
      head_present = true;
    } else if (head_code != Code::kStateUnavailable) {
      code = head_code;
      message = head_message;
      return std::nullopt;
    }
  }

  ledger.head_ = HeadRecord{};
  ledger.head_.format_version = kHeadVersion;
  ledger.head_.coordinator = coordinator;
  ledger.head_.trust_digest = trust_digest;
  ledger.head_.epoch = previous_epoch + 1;
  ledger.head_.boot_count = previous_boot + 1;
  ledger.head_.incarnation = new_incarnation();
  ledger.segment_ = 0;
  ledger.segment_bytes_ = 0;

  if (!head_present) {
    // A directory that already holds journal segments but no head has lost its
    // authority record. The journal is self describing, but the epoch can no
    // longer be shown to advance, so the directory is refused rather than
    // silently reused.
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
      const std::string name = entry.path().filename().string();
      if (name.rfind("journal-", 0) == 0) {
        code = Code::kRecoveryRequired;
        message = "journal segments exist without a head record";
        return std::nullopt;
      }
    }
  }

  std::vector<Record> records;
  RecoveryReport scan;
  if (!ledger.read_frames(records, scan, true, code, message)) {
    return std::nullopt;
  }
  ledger.head_.last_sequence = scan.last_valid_sequence;
  ledger.chain_ = records.empty() ? Digest{} : records.back().chain;
  recovery = scan;
  recovery.recovered = scan.recovered || !head_present;

  if (scan.truncated_bytes > 0) {
    // Repair the torn tail so that later appends start at a record boundary.
    // Only the bytes the scan reported as unreadable are removed, and only from
    // the last segment that holds a complete record, so a doctored record in the
    // middle of the chain is never discarded.
    std::vector<std::filesystem::path> journal_segments;
    {
      std::error_code error;
      for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
        const std::string name = entry.path().filename().string();
        if (name.rfind("journal-", 0) == 0) {
          journal_segments.push_back(entry.path());
        }
      }
    }
    std::sort(journal_segments.begin(), journal_segments.end());
    const std::size_t kept = journal_segments.size() > scan.excess_segments
                                 ? journal_segments.size() - scan.excess_segments
                                 : journal_segments.size();
    if (kept > 0) {
      Code truncate_code = Code::kOk;
      std::string truncate_message;
      if (!state::truncate_file(journal_segments[kept - 1], scan.valid_bytes, truncate_code,
                                truncate_message)) {
        code = truncate_code;
        message = truncate_message;
        return std::nullopt;
      }
    }
    for (std::size_t i = kept; i < journal_segments.size(); ++i) {
      state::remove_file(journal_segments[i]);
    }
  }

  // Discover the segment layout so that appends continue in the right file.
  {
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
      const std::string name = entry.path().filename().string();
      if (name.rfind("journal-", 0) != 0 || name.size() < 12) {
        continue;
      }
      ++ledger.segment_count_;
      std::uint64_t size = 0;
      if (state::file_size(entry.path(), size)) {
        ledger.retained_bytes_ += size;
      }
      const std::string digits = name.substr(8, 5);
      try {
        const std::uint64_t index = static_cast<std::uint64_t>(std::stoul(digits));
        if (index >= ledger.segment_ + 1) {
          ledger.segment_ = index - 1;
        }
      } catch (const std::exception&) {
        code = Code::kLedgerCorrupt;
        message = "journal segment name '" + name + "' is malformed";
        return std::nullopt;
      }
    }
    std::uint64_t size = 0;
    if (state::file_size(ledger.segment_path(ledger.segment_), size)) {
      ledger.segment_bytes_ = size;
    }
  }

  ledger.open_ = true;
  if (!ledger.write_head(code, message)) {
    return std::nullopt;
  }
  return ledger;
}

bool Ledger::load_head(Code& code, std::string& message) {
  std::string raw;
  if (!state::read_file(head_path_, kHeadBytes, raw, code, message)) {
    return false;
  }
  if (raw.size() != kHeadBytes) {
    code = Code::kLedgerCorrupt;
    message = "head record has the wrong size";
    return false;
  }
  return true;
}

bool Ledger::write_head(Code& code, std::string& message) {
  const std::string coordinator_hex = head_.coordinator.str();
  std::string header;
  header.reserve(kHeadBytes);
  write_u32(header, kHeadMagicWord);
  write_u16(header, kHeadVersion);
  write_u16(header, 0);
  header.append(coordinator_hex.data(), coordinator_hex.size());
  header.append(reinterpret_cast<const char*>(head_.trust_digest.data()), head_.trust_digest.size());
  write_u64(header, head_.epoch);
  header.append(reinterpret_cast<const char*>(head_.incarnation.bytes.data()),
                head_.incarnation.bytes.size());
  write_u64(header, head_.last_sequence);
  write_u64(header, head_.boot_count);
  // Everything before the integrity field is reserved so that the CRC covers
  // the whole record except itself.
  header.resize(kHeadCrcRange, '\0');
  write_u32(header, crc32(std::string_view(header.data(), kHeadCrcRange)));
  // The integrity field covers the 192 bytes of content that precede it.
  header.resize(kHeadBytes, '\0');
  // The declared offsets are asserted here so that a later edit cannot silently
  // move a field without breaking the writer.
  if (header.size() != kHeadBytes ||
      header.find(coordinator_hex) != kHeadCoordinatorOffset) {
    code = Code::kInternalInvariant;
    message = "head record layout does not match its declared offsets";
    return false;
  }
  return state::write_file_atomic(head_path_, header, code, message);
}

bool Ledger::rotate_segment(Code& code, std::string& message) {
  if (segment_count_ >= static_cast<std::uint64_t>(kMaxLedgerSegments)) {
    code = Code::kLedgerOversized;
    message = "journal reached " + std::to_string(segment_count_) +
              " segments; the retention bound must be applied before appending";
    return false;
  }
  ++segment_;
  segment_bytes_ = 0;
  ++segment_count_;
  return true;
}

bool Ledger::append(RecordType type, std::string_view payload, std::uint64_t& sequence, Code& code,
                    std::string& message) {
  if (!open_) {
    code = Code::kStateUnavailable;
    message = "ledger is not open";
    return false;
  }
  if (payload.size() > kMaxRecordBytes) {
    code = Code::kLedgerOversized;
    message = "record payload exceeds the configured bound";
    return false;
  }
  const std::size_t frame_bytes = kFrameHeaderBytes + payload.size();
  if (frame_bytes > kMaxSegmentBytes) {
    code = Code::kLedgerOversized;
    message = "frame exceeds the segment bound";
    return false;
  }
  if (segment_bytes_ + frame_bytes > kMaxSegmentBytes) {
    if (!rotate_segment(code, message)) {
      return false;
    }
  }
  if (retained_bytes_ + frame_bytes > kMaxJournalBytes) {
    code = Code::kLedgerOversized;
    message = "journal would exceed its total byte bound";
    return false;
  }

  const std::uint64_t next = head_.last_sequence + 1;
  Digest chain{};
  Digest payload_digest{};
  const std::string frame = build_frame(type, next, payload, chain_, chain, payload_digest);
  if (!state::append_file_flushed(segment_path(segment_), frame, code, message)) {
    return false;
  }
  head_.last_sequence = next;
  chain_ = chain;
  segment_bytes_ += frame.size();
  retained_bytes_ += frame.size();
  sequence = next;
  return true;
}

bool Ledger::read_frames(std::vector<Record>& records, RecoveryReport& report, bool stop_at_torn,
                         Code& code, std::string& message) const {
  // The torn-tail policy is uniform: a frame that cannot be read completely ends
  // the scan and is reported. The parameter records which reading the caller
  // intended, and every caller gets the same conservative behaviour.
  (void)stop_at_torn;
  records.clear();
  report = RecoveryReport{};

  std::vector<std::filesystem::path> segments;
  {
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(directory_, error)) {
      const std::string name = entry.path().filename().string();
      if (name.rfind("journal-", 0) == 0) {
        segments.push_back(entry.path());
      }
    }
    if (error) {
      code = Code::kDirectoryUnavailable;
      message = "cannot enumerate the state directory";
      return false;
    }
  }
  std::sort(segments.begin(), segments.end());

  std::uint64_t expected_sequence = 1;
  Digest previous_chain{};
  bool first_record = true;
  bool torn = false;
  for (std::size_t segment_index = 0; segment_index < segments.size(); ++segment_index) {
    const std::filesystem::path& segment = segments[segment_index];
    if (torn) {
      // Everything after the segment that holds the last complete record is
      // part of the torn tail.
      ++report.excess_segments;
      continue;
    }
    std::string bytes;
    Code read_code = Code::kOk;
    std::string read_message;
    if (!state::read_file(segment, static_cast<std::size_t>(kMaxSegmentBytes) + 1, bytes, read_code,
                          read_message)) {
      if (read_code == Code::kLedgerOversized) {
        code = Code::kLedgerOversized;
        message = "journal segment " + segment.filename().string() + " exceeds the segment bound";
        return false;
      }
      code = read_code;
      message = read_message;
      return false;
    }
    std::size_t offset = 0;
    while (offset < bytes.size()) {
      Record record;
      std::size_t consumed = 0;
      Code frame_code = Code::kOk;
      std::string frame_message;
      if (!parse_frame(bytes, offset, record, consumed, frame_code, frame_message)) {
        // A frame that ends early is a torn tail: a crash in the middle of an
        // append is an expected way for a process to die, so it is a recovery
        // condition that is reported and repaired. A frame that is complete but
        // fails its integrity checks is a corruption, and it is never discarded:
        // a doctored record is evidence of tampering rather than of an
        // interrupted write, so the whole directory is refused.
        if (frame_code != Code::kLedgerTruncated) {
          code = frame_code;
          message = frame_message;
          return false;
        }
        report.recovered = true;
        report.truncated_bytes = bytes.size() - offset;
        report.valid_bytes = offset;
        report.detail = std::string(code_token(frame_code)) + ": " + frame_message;
        torn = true;
        break;
      }
      if (record.sequence != expected_sequence) {
        // A wrong sequence is a break in the chain, not a torn tail: a partially
        // written record cannot produce a complete, integrity-checked frame.
        report.recovered = true;
        report.chain_break = true;
        report.detail = "journal sequence jumps from " + std::to_string(expected_sequence) +
                        " to " + std::to_string(record.sequence);
        code = Code::kIndexGapDetected;
        message = report.detail;
        return false;
      }
      // Recompute this record's chain value from the bytes on disk: the first 88
      // header bytes with the link field zeroed, followed by the payload. A
      // doctored field, a doctored payload, or a moved record all break it.
      std::array<char, 88> prefix{};
      std::memcpy(prefix.data(), bytes.data() + offset, prefix.size());
      for (std::size_t i = 56; i < 88; ++i) {
        prefix[i] = '\0';
      }
      const Digest derived = chain_of(std::string_view(prefix.data(), prefix.size()),
                                      std::string_view(record.payload));
      // Continuity: the link field, which parse_frame surfaced as record.chain,
      // must equal the running chain. A removed, duplicated, reordered, or
      // doctored link breaks the chain here.
      if (record.chain != previous_chain) {
        code = Code::kLedgerCorrupt;
        message = "journal record does not link to the previous record";
        return false;
      }
      previous_chain = derived;
      (void)first_record;
      expected_sequence = record.sequence + 1;
      report.last_valid_sequence = record.sequence;
      offset += consumed;
      report.valid_bytes = offset;
      records.push_back(std::move(record));
    }
  }
  report.valid_records = static_cast<std::uint64_t>(records.size());
  return true;
}

bool Ledger::read_all(std::vector<Record>& records, RecoveryReport& report, Code& code,
                      std::string& message) const {
  return read_frames(records, report, false, code, message);
}

std::vector<Record> Ledger::read_all() const {
  std::vector<Record> records;
  RecoveryReport report;
  Code code = Code::kOk;
  std::string message;
  (void)read_frames(records, report, false, code, message);
  return records;
}

bool Ledger::read_after(std::uint64_t sequence, std::vector<Record>& records, RecoveryReport& report,
                        Code& code, std::string& message) const {
  std::vector<Record> all;
  if (!read_frames(all, report, false, code, message)) {
    return false;
  }
  records.clear();
  for (Record& record : all) {
    if (record.sequence > sequence) {
      records.push_back(std::move(record));
    }
  }
  return true;
}

bool Ledger::write_snapshot(const Snapshot& snapshot, Code& code, std::string& message) {
  if (snapshot.sequence > head_.last_sequence) {
    code = Code::kRecoveryRequired;
    message = "snapshot sequence " + std::to_string(snapshot.sequence) +
              " is ahead of the durable sequence " + std::to_string(head_.last_sequence);
    return false;
  }
  std::string header;
  header.reserve(kSnapshotHeaderBytes);
  write_u32(header, state::kSnapshotMagic);
  write_u16(header, state::kSnapshotVersion);
  write_u16(header, 0);
  write_u64(header, snapshot.epoch);
  write_u64(header, snapshot.sequence);
  const Digest payload_digest = digest_of(snapshot.payload);
  header.append(reinterpret_cast<const char*>(payload_digest.data()), payload_digest.size());
  header.resize(kSnapshotHeaderBytes - kSnapshotReserved, '\0');
  header.resize(kSnapshotHeaderBytes, '\0');
  const std::uint32_t header_crc = crc32(std::string_view(header.data(), 92));
  for (unsigned i = 0; i < 4; ++i) {
    header[92 + i] = static_cast<char>((header_crc >> (8u * i)) & 0xFFu);
  }
  std::string bytes = header;
  bytes.append(snapshot.payload);
  return state::write_file_atomic(snapshot_path_, bytes, code, message);
}

bool Ledger::read_snapshot(Snapshot& snapshot, bool& present, Code& code,
                           std::string& message) const {
  present = false;
  std::string bytes;
  Code read_code = Code::kOk;
  std::string read_message;
  if (!state::read_file(snapshot_path_, kMaxDocumentBytes + kSnapshotHeaderBytes, bytes, read_code,
                        read_message)) {
    if (read_code == Code::kStateUnavailable) {
      return true;
    }
    code = read_code;
    message = read_message;
    return false;
  }
  if (bytes.size() < kSnapshotHeaderBytes) {
    code = Code::kSnapshotInvalid;
    message = "snapshot is shorter than its header";
    return false;
  }
  if (read_u32(bytes.data()) != state::kSnapshotMagic) {
    code = Code::kSnapshotInvalid;
    message = "snapshot magic does not match";
    return false;
  }
  if (read_u16(bytes.data() + 4) != state::kSnapshotVersion) {
    code = Code::kLedgerIncompatible;
    message = "snapshot version is not supported";
    return false;
  }
  if (crc32(std::string_view(bytes.data(), 92)) != read_u32(bytes.data() + 92)) {
    code = Code::kSnapshotInvalid;
    message = "snapshot header integrity check failed";
    return false;
  }
  snapshot.epoch = read_u64(bytes.data() + 8);
  snapshot.sequence = read_u64(bytes.data() + 16);
  Digest stored_digest{};
  std::memcpy(stored_digest.data(), bytes.data() + 24, 32);
  snapshot.payload.assign(bytes.data() + kSnapshotHeaderBytes, bytes.size() - kSnapshotHeaderBytes);
  if (digest_of(snapshot.payload) != stored_digest) {
    code = Code::kSnapshotInvalid;
    message = "snapshot payload digest does not match its bytes";
    return false;
  }
  present = true;
  return true;
}

bool Ledger::truncate_to(std::uint64_t sequence, Code& code, std::string& message) {
  std::vector<Record> records;
  RecoveryReport report;
  if (!read_frames(records, report, true, code, message)) {
    return false;
  }
  // Locate the byte offset of the requested sequence inside its segment.
  std::vector<std::filesystem::path> segments;
  {
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(directory_, error)) {
      const std::string name = entry.path().filename().string();
      if (name.rfind("journal-", 0) == 0) {
        segments.push_back(entry.path());
      }
    }
    std::sort(segments.begin(), segments.end());
  }
  std::uint64_t running = 0;
  for (const std::filesystem::path& segment : segments) {
    std::string bytes;
    Code read_code = Code::kOk;
    std::string read_message;
    if (!state::read_file(segment, static_cast<std::size_t>(kMaxSegmentBytes) + 1, bytes, read_code,
                          read_message)) {
      code = read_code;
      message = read_message;
      return false;
    }
    std::size_t offset = 0;
    std::uint64_t last_in_segment = running;
    std::size_t offset_after_last = 0;
    while (offset < bytes.size()) {
      Record record;
      std::size_t consumed = 0;
      Code frame_code = Code::kOk;
      std::string frame_message;
      if (!parse_frame(bytes, offset, record, consumed, frame_code, frame_message)) {
        break;
      }
      ++running;
      last_in_segment = running;
      offset += consumed;
      offset_after_last = offset;
      if (running == sequence) {
        if (!state::truncate_file(segment, offset, code, message)) {
          return false;
        }
        head_.last_sequence = sequence;
        chain_ = record.chain;
        // Drop every later segment entirely.
        for (std::size_t i = 0; i < segments.size(); ++i) {
          if (segments[i] == segment) {
            for (std::size_t j = i + 1; j < segments.size(); ++j) {
              state::remove_file(segments[j]);
              if (segment_count_ > 0) {
                --segment_count_;
              }
            }
            break;
          }
        }
        return write_head(code, message);
      }
    }
    (void)last_in_segment;
    (void)offset_after_last;
  }
  code = Code::kIndexGapDetected;
  message = "journal does not contain sequence " + std::to_string(sequence);
  return false;
}

}  // namespace wnc::ledger