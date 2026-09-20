// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Durable file primitives. Every durable mutation in this boundary is written
// to a temporary file in the destination directory, flushed to the operating
// system, and then moved over the destination in one step. A reader therefore
// observes either the previous bytes or the new bytes, never a mixture.
//
// Durability here means durability against process death: FlushFileBuffers on
// Windows and fsync on POSIX both push the bytes out of the process. No claim is
// made about media failure or about power loss that defeats the storage
// controller's own cache.

#ifndef WNC_STATE_HPP
#define WNC_STATE_HPP

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "wnc/error.hpp"

namespace wnc::state {

inline constexpr std::size_t kSnapshotHeaderBytes = 128;
inline constexpr std::uint32_t kSnapshotMagic = 0x31534E57u;  // "WNS1" little-endian
inline constexpr std::uint16_t kSnapshotVersion = 1;

// Flushes a file handle's buffers to the operating system.
bool flush_file(void* handle, Code& code, std::string& message);

// Reads a whole file. Refuses files larger than max_bytes before allocating.
bool read_file(const std::filesystem::path& path, std::size_t max_bytes, std::string& out, Code& code,
               std::string& message);

// Writes bytes to path through a temporary file and an atomic replace.
bool write_file_atomic(const std::filesystem::path& path, std::string_view bytes, Code& code,
                       std::string& message);

// Appends bytes and flushes them. Creates the file when absent.
bool append_file_flushed(const std::filesystem::path& path, std::string_view bytes, Code& code,
                         std::string& message);

bool file_size(const std::filesystem::path& path, std::uint64_t& size);

// Truncates a file to the given byte count.
bool truncate_file(const std::filesystem::path& path, std::uint64_t size, Code& code,
                   std::string& message);

bool ensure_directory(const std::filesystem::path& path, Code& code, std::string& message);

// Removes a file, tolerating its absence.
bool remove_file(const std::filesystem::path& path);

// Rejects a path that escapes a root directory. Every file this boundary writes
// lives under its state directory, and a name that resolves outside it is
// refused rather than normalised.
bool is_within(const std::filesystem::path& root, const std::filesystem::path& candidate);

// Process wide, cross process lock on a state directory. Returns a token that
// must be released by unlock_directory.
using LockToken = void*;

LockToken lock_directory(const std::filesystem::path& directory, Code& code, std::string& message);
void unlock_directory(LockToken token);

std::uint64_t monotonic_millis() noexcept;
std::uint64_t wall_millis() noexcept;

}  // namespace wnc::state

#endif  // WNC_STATE_HPP
