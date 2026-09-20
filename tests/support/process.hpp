// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Process control for the multiprocess proof surfaces. Tests spawn real
// operating system processes, kill them without warning, and start fresh ones
// against the same durable state directory. Nothing here is simulated: the
// child is a separate executable with its own address space and its own boot.

#ifndef WNC_TEST_SUPPORT_PROCESS_HPP
#define WNC_TEST_SUPPORT_PROCESS_HPP

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace wnc::test {

class ChildProcess {
 public:
  ChildProcess() = default;
  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ~ChildProcess();

  // Starts the executable with the given arguments and working directory.
  // Returns false when the process could not be created.
  static std::optional<ChildProcess> spawn(const std::filesystem::path& executable,
                                           const std::vector<std::string>& arguments,
                                           const std::filesystem::path& working_directory);

  [[nodiscard]] bool valid() const noexcept { return handle_ != 0; }
  [[nodiscard]] std::uint64_t id() const noexcept { return id_; }

  // True while the process is still running. Reaps the process when it has
  // exited, so a second call reports false.
  [[nodiscard]] bool running();

  // Waits up to the given budget for exit. Returns the exit code when the
  // process exited, and nullopt when the wait expired or the code is unknown.
  std::optional<int> wait_for_exit(std::uint64_t timeout_millis);

  // Terminates the process immediately, without giving it a chance to flush or
  // shut down. This models a crash, not a graceful stop.
  void kill_now();

  // Waits for the process to exit, killing it after the budget expires.
  void kill_and_reap(std::uint64_t timeout_millis);

  // Reads a whole file, tolerating its absence.
  [[nodiscard]] static std::string read_text(const std::filesystem::path& path);

  // Appends a line to a file, used to record child progress.
  static void append_line(const std::filesystem::path& path, const std::string& line);

  // Waits until a file exists or the budget expires.
  static bool wait_for_file(const std::filesystem::path& path, std::uint64_t timeout_millis);

  // Waits until a file contains the given needle or the budget expires.
  static bool wait_for_file_text(const std::filesystem::path& path, const std::string& needle,
                                 std::uint64_t timeout_millis);

 private:
  void release() noexcept;

#if defined(_WIN32)
  void* handle_ = nullptr;  // HANDLE
#else
  int handle_ = 0;  // pid
#endif
  std::uint64_t id_ = 0;
  bool exited_ = false;
  int exit_code_ = 0;
};

}  // namespace wnc::test

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

#if defined(_WIN32)

namespace wnc::test {
namespace detail {

inline std::string quote_argument(const std::string& argument) {
  // Windows command lines are quoted for the C runtime parser: wrap in double
  // quotes and escape interior quotes and trailing backslashes.
  std::string out = "\"";
  unsigned backslashes = 0;
  for (const char c : argument) {
    if (c == '\\') {
      ++backslashes;
      continue;
    }
    if (c == '"') {
      out.append(backslashes * 2 + 1, '\\');
      out.push_back('"');
      backslashes = 0;
      continue;
    }
    out.append(backslashes, '\\');
    backslashes = 0;
    out.push_back(c);
  }
  out.append(backslashes * 2, '\\');
  out.push_back('"');
  return out;
}

}  // namespace detail
}  // namespace wnc::test

#endif

namespace wnc::test {

inline ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : handle_(other.handle_), id_(other.id_), exited_(other.exited_), exit_code_(other.exit_code_) {
  other.handle_ = 0;
  other.id_ = 0;
}

inline ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    release();
    handle_ = other.handle_;
    id_ = other.id_;
    exited_ = other.exited_;
    exit_code_ = other.exit_code_;
    other.handle_ = 0;
    other.id_ = 0;
  }
  return *this;
}

inline ChildProcess::~ChildProcess() {
  if (valid() && !exited_) {
    kill_now();
    wait_for_exit(5000);
  }
  release();
}

inline void ChildProcess::release() noexcept {
#if defined(_WIN32)
  if (handle_ != nullptr) {
    ::CloseHandle(static_cast<HANDLE>(handle_));
    handle_ = nullptr;
  }
#endif
}

inline std::optional<ChildProcess> ChildProcess::spawn(const std::filesystem::path& executable,
                                                       const std::vector<std::string>& arguments,
                                                       const std::filesystem::path& working_directory) {
#if defined(_WIN32)
  std::string command_line = detail::quote_argument(executable.string());
  for (const std::string& argument : arguments) {
    command_line.push_back(' ');
    command_line.append(detail::quote_argument(argument));
  }
  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION information{};
  std::vector<char> mutable_command(command_line.begin(), command_line.end());
  mutable_command.push_back('\0');
  const std::string directory = working_directory.string();
  if (::CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, FALSE, 0, nullptr,
                       directory.empty() ? nullptr : directory.c_str(), &startup,
                       &information) == 0) {
    return std::nullopt;
  }
  ::CloseHandle(information.hThread);
  ChildProcess child;
  child.handle_ = static_cast<void*>(information.hProcess);
  child.id_ = static_cast<std::uint64_t>(information.dwProcessId);
  return child;
#else
  const pid_t pid = ::fork();
  if (pid < 0) {
    return std::nullopt;
  }
  if (pid == 0) {
    if (!working_directory.empty()) {
      (void)::chdir(working_directory.c_str());
    }
    std::vector<char*> argv;
    std::string program = executable.string();
    argv.push_back(program.data());
    std::vector<std::string> storage = arguments;
    for (std::string& argument : storage) {
      argv.push_back(argument.data());
    }
    argv.push_back(nullptr);
    ::execv(program.c_str(), argv.data());
    ::_exit(127);
  }
  ChildProcess child;
  child.handle_ = static_cast<int>(pid);
  child.id_ = static_cast<std::uint64_t>(pid);
  return child;
#endif
}

inline bool ChildProcess::running() {
#if defined(_WIN32)
  if (handle_ == nullptr || exited_) {
    return false;
  }
  const DWORD status = ::WaitForSingleObject(static_cast<HANDLE>(handle_), 0);
  if (status == WAIT_TIMEOUT) {
    return true;
  }
  DWORD code = 0;
  if (::GetExitCodeProcess(static_cast<HANDLE>(handle_), &code) != 0) {
    exit_code_ = static_cast<int>(code);
  }
  exited_ = true;
  return false;
#else
  if (handle_ == 0 || exited_) {
    return false;
  }
  int status = 0;
  const pid_t result = ::waitpid(handle_, &status, WNOHANG);
  if (result == 0) {
    return true;
  }
  exited_ = true;
  exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  return false;
#endif
}

inline std::optional<int> ChildProcess::wait_for_exit(std::uint64_t timeout_millis) {
#if defined(_WIN32)
  if (handle_ == nullptr) {
    return std::nullopt;
  }
  const DWORD status = ::WaitForSingleObject(static_cast<HANDLE>(handle_),
                                             static_cast<DWORD>(timeout_millis));
  if (status != WAIT_OBJECT_0) {
    return std::nullopt;
  }
  DWORD code = 0;
  ::GetExitCodeProcess(static_cast<HANDLE>(handle_), &code);
  exited_ = true;
  exit_code_ = static_cast<int>(code);
  return exit_code_;
#else
  if (handle_ == 0) {
    return std::nullopt;
  }
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeout_millis);
  while (std::chrono::steady_clock::now() < deadline) {
    if (!running()) {
      return exit_code_;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return std::nullopt;
#endif
}

inline void ChildProcess::kill_now() {
#if defined(_WIN32)
  if (handle_ != nullptr) {
    ::TerminateProcess(static_cast<HANDLE>(handle_), 0xC0000001u);
  }
#else
  if (handle_ > 0) {
    ::kill(handle_, SIGKILL);
  }
#endif
}

inline void ChildProcess::kill_and_reap(std::uint64_t timeout_millis) {
  if (wait_for_exit(timeout_millis).has_value()) {
    return;
  }
  kill_now();
  (void)wait_for_exit(10000);
}

inline std::string ChildProcess::read_text(const std::filesystem::path& path) {
  // The C++ stream interface avoids the C runtime's deprecated plain fopen while
  // keeping the helper portable.
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {};
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

inline void ChildProcess::append_line(const std::filesystem::path& path, const std::string& line) {
  std::ofstream stream(path, std::ios::binary | std::ios::app);
  if (!stream) {
    return;
  }
  stream.write(line.data(), static_cast<std::streamsize>(line.size()));
  stream.put('\n');
}

inline bool ChildProcess::wait_for_file(const std::filesystem::path& path,
                                        std::uint64_t timeout_millis) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_millis);
  while (std::chrono::steady_clock::now() < deadline) {
    std::error_code error;
    if (std::filesystem::exists(path, error) && !error) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return false;
}

inline bool ChildProcess::wait_for_file_text(const std::filesystem::path& path,
                                             const std::string& needle,
                                             std::uint64_t timeout_millis) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_millis);
  while (std::chrono::steady_clock::now() < deadline) {
    const std::string text = read_text(path);
    if (text.find(needle) != std::string::npos) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return false;
}

}  // namespace wnc::test

#endif  // WNC_TEST_SUPPORT_PROCESS_HPP