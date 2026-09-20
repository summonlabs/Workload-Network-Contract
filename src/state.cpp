// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/state.hpp"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <system_error>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace wnc::state {
namespace {

constexpr std::size_t kReadChunk = 64 * 1024;

std::string describe_error(const std::error_code& error) {
  return error.message() + " (" + std::to_string(error.value()) + ")";
}

}  // namespace

#if defined(_WIN32)

bool flush_file(void* handle, Code& code, std::string& message) {
  if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
    code = Code::kAtomicReplaceFailed;
    message = "no file handle to flush";
    return false;
  }
  if (::FlushFileBuffers(static_cast<HANDLE>(handle)) == 0) {
    code = Code::kAtomicReplaceFailed;
    message = "FlushFileBuffers failed with error " + std::to_string(::GetLastError());
    return false;
  }
  return true;
}

namespace {

bool flush_handle(HANDLE handle, Code& code, std::string& message) {
  return flush_file(static_cast<void*>(handle), code, message);
}

}  // namespace

bool read_file(const std::filesystem::path& path, std::size_t max_bytes, std::string& out, Code& code,
               std::string& message) {
  HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    code = Code::kStateUnavailable;
    message = "cannot open " + path.string() + " for reading (error " +
              std::to_string(::GetLastError()) + ")";
    return false;
  }
  LARGE_INTEGER size{};
  if (::GetFileSizeEx(handle, &size) == 0) {
    ::CloseHandle(handle);
    code = Code::kStateUnavailable;
    message = "cannot size " + path.string();
    return false;
  }
  if (size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > max_bytes) {
    ::CloseHandle(handle);
    code = Code::kLedgerOversized;
    message = path.string() + " exceeds the " + std::to_string(max_bytes) + " byte bound";
    return false;
  }
  out.clear();
  out.resize(static_cast<std::size_t>(size.QuadPart));
  std::size_t offset = 0;
  while (offset < out.size()) {
    const DWORD want = static_cast<DWORD>(
        (out.size() - offset) < kReadChunk ? (out.size() - offset) : kReadChunk);
    DWORD read = 0;
    if (::ReadFile(handle, out.data() + offset, want, &read, nullptr) == 0) {
      ::CloseHandle(handle);
      code = Code::kIoFailed;
      message = "ReadFile failed for " + path.string();
      return false;
    }
    if (read == 0) {
      break;
    }
    offset += read;
  }
  out.resize(offset);
  ::CloseHandle(handle);
  return true;
}

bool write_file_atomic(const std::filesystem::path& path, std::string_view bytes, Code& code,
                       std::string& message) {
  std::filesystem::path temporary = path;
  temporary += ".tmp";
  {
    HANDLE handle = ::CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
      code = Code::kStateUnavailable;
      message = "cannot create " + temporary.string();
      return false;
    }
    std::size_t offset = 0;
    while (offset < bytes.size()) {
      const DWORD want = static_cast<DWORD>(
          (bytes.size() - offset) < kReadChunk ? (bytes.size() - offset) : kReadChunk);
      DWORD written = 0;
      if (::WriteFile(handle, bytes.data() + offset, want, &written, nullptr) == 0) {
        ::CloseHandle(handle);
        code = Code::kIoFailed;
        message = "WriteFile failed for " + temporary.string();
        return false;
      }
      offset += written;
    }
    if (!flush_handle(handle, code, message)) {
      ::CloseHandle(handle);
      return false;
    }
    ::CloseHandle(handle);
  }
  if (::MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    code = Code::kAtomicReplaceFailed;
    message = "cannot replace " + path.string() + " (error " + std::to_string(::GetLastError()) + ")";
    return false;
  }
  return true;
}

bool append_file_flushed(const std::filesystem::path& path, std::string_view bytes, Code& code,
                         std::string& message) {
  HANDLE handle = ::CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    code = Code::kStateUnavailable;
    message = "cannot open " + path.string() + " for append";
    return false;
  }
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const DWORD want = static_cast<DWORD>(
        (bytes.size() - offset) < kReadChunk ? (bytes.size() - offset) : kReadChunk);
    DWORD written = 0;
    if (::WriteFile(handle, bytes.data() + offset, want, &written, nullptr) == 0) {
      ::CloseHandle(handle);
      code = Code::kIoFailed;
      message = "WriteFile failed for " + path.string();
      return false;
    }
    offset += written;
  }
  const bool flushed = flush_handle(handle, code, message);
  ::CloseHandle(handle);
  return flushed;
}

bool file_size(const std::filesystem::path& path, std::uint64_t& size) {
  WIN32_FILE_ATTRIBUTE_DATA data{};
  if (::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data) == 0) {
    return false;
  }
  size = (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
  return true;
}

bool truncate_file(const std::filesystem::path& path, std::uint64_t size, Code& code,
                   std::string& message) {
  HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    code = Code::kStateUnavailable;
    message = "cannot open " + path.string() + " to truncate";
    return false;
  }
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONGLONG>(size);
  bool ok = ::SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) != 0;
  if (ok) {
    ok = ::SetEndOfFile(handle) != 0;
  }
  if (!ok) {
    code = Code::kAtomicReplaceFailed;
    message = "cannot truncate " + path.string();
  }
  ::CloseHandle(handle);
  return ok;
}

bool ensure_directory(const std::filesystem::path& path, Code& code, std::string& message) {
  std::error_code error;
  std::filesystem::create_directories(path, error);
  if (error && !std::filesystem::is_directory(path)) {
    code = Code::kDirectoryUnavailable;
    message = "cannot create " + path.string() + ": " + describe_error(error);
    return false;
  }
  return true;
}

bool remove_file(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::remove(path, error);
  return !error;
}

LockToken lock_directory(const std::filesystem::path& directory, Code& code, std::string& message) {
  std::filesystem::path lock_path = directory / "lock.bin";
  HANDLE handle = ::CreateFileW(lock_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    code = Code::kDirectoryUnavailable;
    message = "cannot open the state directory lock";
    return nullptr;
  }
  OVERLAPPED overlapped{};
  if (::LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0,
                   &overlapped) == 0) {
    ::CloseHandle(handle);
    code = Code::kLockHeld;
    message = "another live process owns the state directory";
    return nullptr;
  }
  return static_cast<LockToken>(handle);
}

void unlock_directory(LockToken token) {
  if (token == nullptr) {
    return;
  }
  HANDLE handle = static_cast<HANDLE>(token);
  OVERLAPPED overlapped{};
  ::UnlockFileEx(handle, 0, 1, 0, &overlapped);
  ::CloseHandle(handle);
}

#else  // POSIX

bool flush_file(void* handle, Code& code, std::string& message) {
  if (handle == nullptr) {
    code = Code::kAtomicReplaceFailed;
    message = "no file descriptor to flush";
    return false;
  }
  const int descriptor = *static_cast<int*>(handle);
  if (::fsync(descriptor) != 0) {
    code = Code::kAtomicReplaceFailed;
    message = "fsync failed";
    return false;
  }
  return true;
}

bool read_file(const std::filesystem::path& path, std::size_t max_bytes, std::string& out, Code& code,
               std::string& message) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error) {
    code = Code::kStateUnavailable;
    message = "cannot size " + path.string() + ": " + describe_error(error);
    return false;
  }
  if (size > max_bytes) {
    code = Code::kLedgerOversized;
    message = path.string() + " exceeds the byte bound";
    return false;
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    code = Code::kStateUnavailable;
    message = "cannot open " + path.string();
    return false;
  }
  out.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
  return true;
}

bool write_file_atomic(const std::filesystem::path& path, std::string_view bytes, Code& code,
                       std::string& message) {
  std::filesystem::path temporary = path;
  temporary += ".tmp";
  const int descriptor = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (descriptor < 0) {
    code = Code::kStateUnavailable;
    message = "cannot create " + temporary.string();
    return false;
  }
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t written = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
    if (written <= 0) {
      ::close(descriptor);
      code = Code::kIoFailed;
      message = "write failed for " + temporary.string();
      return false;
    }
    offset += static_cast<std::size_t>(written);
  }
  int handle = descriptor;
  if (!flush_file(&handle, code, message)) {
    ::close(descriptor);
    return false;
  }
  ::close(descriptor);
  std::error_code error;
  std::filesystem::rename(temporary, path, error);
  if (error) {
    code = Code::kAtomicReplaceFailed;
    message = "cannot replace " + path.string() + ": " + describe_error(error);
    return false;
  }
  return true;
}

bool append_file_flushed(const std::filesystem::path& path, std::string_view bytes, Code& code,
                         std::string& message) {
  const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (descriptor < 0) {
    code = Code::kStateUnavailable;
    message = "cannot open " + path.string() + " for append";
    return false;
  }
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t written = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
    if (written <= 0) {
      ::close(descriptor);
      code = Code::kIoFailed;
      message = "append failed for " + path.string();
      return false;
    }
    offset += static_cast<std::size_t>(written);
  }
  int handle = descriptor;
  const bool flushed = flush_file(&handle, code, message);
  ::close(descriptor);
  return flushed;
}

bool file_size(const std::filesystem::path& path, std::uint64_t& size) {
  std::error_code error;
  const std::uintmax_t raw = std::filesystem::file_size(path, error);
  if (error) {
    return false;
  }
  size = static_cast<std::uint64_t>(raw);
  return true;
}

bool truncate_file(const std::filesystem::path& path, std::uint64_t size, Code& code,
                   std::string& message) {
  if (::truncate(path.c_str(), static_cast<off_t>(size)) != 0) {
    code = Code::kAtomicReplaceFailed;
    message = "cannot truncate " + path.string();
    return false;
  }
  return true;
}

bool ensure_directory(const std::filesystem::path& path, Code& code, std::string& message) {
  std::error_code error;
  std::filesystem::create_directories(path, error);
  if (error && !std::filesystem::is_directory(path)) {
    code = Code::kDirectoryUnavailable;
    message = "cannot create " + path.string() + ": " + describe_error(error);
    return false;
  }
  return true;
}

bool remove_file(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::remove(path, error);
  return !error;
}

LockToken lock_directory(const std::filesystem::path& directory, Code& code, std::string& message) {
  const std::filesystem::path lock_path = directory / "lock.bin";
  const int descriptor = ::open(lock_path.c_str(), O_RDWR | O_CREAT, 0644);
  if (descriptor < 0) {
    code = Code::kDirectoryUnavailable;
    message = "cannot open the state directory lock";
    return nullptr;
  }
  if (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
    ::close(descriptor);
    code = Code::kLockHeld;
    message = "another live process owns the state directory";
    return nullptr;
  }
  int* token = new int(descriptor);
  return static_cast<LockToken>(token);
}

void unlock_directory(LockToken token) {
  if (token == nullptr) {
    return;
  }
  int* descriptor = static_cast<int*>(token);
  ::flock(*descriptor, LOCK_UN);
  ::close(*descriptor);
  delete descriptor;
}

#endif

bool is_within(const std::filesystem::path& root, const std::filesystem::path& candidate) {
  std::error_code error;
  const std::filesystem::path normal_root = std::filesystem::weakly_canonical(root, error);
  if (error) {
    return false;
  }
  const std::filesystem::path normal_candidate = std::filesystem::weakly_canonical(candidate, error);
  if (error) {
    return false;
  }
  const std::filesystem::path relative = normal_candidate.lexically_relative(normal_root);
  if (relative.empty()) {
    return normal_candidate == normal_root;
  }
  const std::string text = relative.generic_string();
  return !text.empty() && text.rfind("..", 0) != 0;
}

std::uint64_t monotonic_millis() noexcept {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

std::uint64_t wall_millis() noexcept {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

}  // namespace wnc::state
