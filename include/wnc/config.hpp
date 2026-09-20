// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Hard bounds for every externally influenced resource in this boundary.
// These limits are enforced before allocation: no externally supplied size
// may reach an allocator without first being checked against them.

#ifndef WNC_CONFIG_HPP
#define WNC_CONFIG_HPP

#include <cstdint>
#include <cstddef>

namespace wnc {

// ---------------------------------------------------------------------------
// Wire and payload bounds
// ---------------------------------------------------------------------------

// Total serialized frame (header + body) accepted on any transport.
inline constexpr std::size_t kMaxFrameBytes = 1024 * 1024;

// Bytes of canonical JSON accepted for a single decoded document.
inline constexpr std::size_t kMaxDocumentBytes = 512 * 1024;

// Maximum JSON nesting depth. Bounds parser stack use to a known constant.
inline constexpr std::size_t kMaxJsonDepth = 32;

// Maximum bytes in a single JSON string literal.
inline constexpr std::size_t kMaxStringBytes = 4096;

// ---------------------------------------------------------------------------
// Contract model bounds
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMaxScopesPerContract = 1024;
inline constexpr std::size_t kMaxRequirementsPerContract = 4096;
inline constexpr std::size_t kMaxRequirementsPerScope = 256;
inline constexpr std::size_t kMaxRankedScopesPerContract = 256;
inline constexpr std::size_t kMaxAttributesPerRequirement = 32;
inline constexpr std::size_t kMaxDistinctKindsPerScope = 32;
inline constexpr std::size_t kMaxCompositionLayers = 16;

// ---------------------------------------------------------------------------
// Persistence bounds
// ---------------------------------------------------------------------------

// Bytes of a single journal record payload. A record is recovered by the same
// runtime that wrote it, so the bound it is written under is the bound it is
// read back under: if the write bound were larger than the decode bound, a
// payload between the two would be accepted, acknowledged, and then make the
// whole history unreadable. This is one symbol for exactly that reason.
inline constexpr std::size_t kMaxRecordBytes = kMaxDocumentBytes;
// Journal records retained in one chain file before rotation.
inline constexpr std::size_t kMaxRecordsPerSegment = 4096;
// Journal segment files retained in a ledger directory.
inline constexpr std::size_t kMaxLedgerSegments = 256;
// Contract generation files retained per workload.
inline constexpr std::size_t kMaxRetainedGenerations = 4096;
// Total contract generation files retained across all workloads.
inline constexpr std::size_t kMaxRetainedContractFiles = 16384;
// Bytes of a single contract generation file.
inline constexpr std::size_t kMaxContractFileBytes = 1024 * 1024;

// ---------------------------------------------------------------------------
// Runtime bounds
// ---------------------------------------------------------------------------

// Concurrent transport sessions accepted by one coordinator.
inline constexpr std::size_t kMaxSessions = 64;
// Requests accepted but not yet completed.
inline constexpr std::size_t kMaxPendingRequests = 256;
// Accept backlog for the listening socket.
inline constexpr int kListenBacklog = 16;
// Bounded wait for a clean session shutdown, in milliseconds.
inline constexpr std::uint64_t kSessionDrainMillis = 2000;

// ---------------------------------------------------------------------------
// Protocol identifiers
// ---------------------------------------------------------------------------

inline constexpr std::uint32_t kWireMagic = 0x574E4331u;  // "WNC1"
inline constexpr std::uint16_t kWireVersion = 1;
inline constexpr std::uint32_t kSchemaVersion = 1;
inline constexpr char kLedgerMagic[4] = {'W', 'N', 'L', '1'};
inline constexpr char kSnapshotMagic[4] = {'W', 'N', 'S', '1'};

// ---------------------------------------------------------------------------
// Policy defaults
// ---------------------------------------------------------------------------

// Default maximum age of evidence before it is considered stale.
inline constexpr std::uint64_t kDefaultEvidenceMaxAgeMillis = 30000;
// Default ledger segments retained when compacting.
inline constexpr std::uint64_t kDefaultRetentionSegments = 8;

}  // namespace wnc

#endif  // WNC_CONFIG_HPP
