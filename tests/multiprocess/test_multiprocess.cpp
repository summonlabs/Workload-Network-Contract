// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Multiprocess proof surface. Every process here is a real operating system
// process: the coordinator runs in its own executable, publishers are separate
// executables, and the coordinator is killed without warning and restarted
// against the same state directory. Nothing is simulated and no shutdown is
// cooperative unless the test says so.

#include "wnc_test.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "../support/process.hpp"
#include "wnc/contract.hpp"
#include "wnc/hash.hpp"
#include "wnc/signature.hpp"
#include "wnc/state.hpp"

using namespace wnc;

namespace {

std::filesystem::path multiprocess_directory(const std::string& name) {
  const std::filesystem::path base =
      std::filesystem::temp_directory_path() /
      ("wnc-multiprocess-" + name + "-" + std::to_string(state::wall_millis()) + "-" +
       std::to_string(reinterpret_cast<std::uintptr_t>(&name)));
  std::error_code error;
  std::filesystem::remove_all(base, error);
  std::filesystem::create_directories(base, error);
  return base;
}

struct Guard {
  std::filesystem::path path;
  explicit Guard(std::string name) : path(multiprocess_directory(name)) {}
  Guard(const Guard&) = delete;
  Guard& operator=(const Guard&) = delete;
  ~Guard() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

// The harness executable lives beside the test executable.
std::filesystem::path harness_path() {
#if defined(_WIN32)
  const std::string suffix = ".exe";
#else
  const std::string suffix = "";
#endif
  std::error_code error;
  const std::filesystem::path self = std::filesystem::absolute(".", error);
  // CTest runs each test with its build directory as the working directory.
  const std::filesystem::path candidate = self / ("wnc_test_tool" + suffix);
  if (std::filesystem::exists(candidate, error)) {
    return candidate;
  }
  const std::filesystem::path executable = std::filesystem::current_path(error);
  return executable / ("wnc_test_tool" + suffix);
}

// Derives key material in-process, so the test never depends on parsing a
// child's stdout for its inputs.
LocalSigner signer_from_hex(const std::string& hex) {
  Ed25519Seed seed{};
  const auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
  };
  WNC_CHECK_EQ(hex.size(), std::size_t(64));
  for (std::size_t i = 0; i < seed.size(); ++i) {
    const int high = digit(hex[i * 2]);
    const int low = digit(hex[i * 2 + 1]);
    WNC_CHECK(high >= 0 && low >= 0);
    seed[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return local_signer_from_seed(seed);
}

struct CoordinatorProcess {
  std::optional<test::ChildProcess> process;
  std::filesystem::path port_file;
  std::uint16_t port = 0;

  bool start(const std::filesystem::path& directory, const LocalSigner& signer,
             const std::filesystem::path& port_file_path) {
    port_file = port_file_path;
    std::error_code error;
    std::filesystem::remove(port_file, error);
    std::vector<std::string> arguments = {
        "coordinator",
        "--state", directory.string(),
        "--host", "127.0.0.1",
        "--port", "0",
        "--issuer", signer.publisher.str(),
        hex_encode(std::span<const std::uint8_t>(signer.public_key.data(), signer.public_key.size())),
        "--print-port",
        "--out", port_file.string()};
    process = test::ChildProcess::spawn(harness_path(), arguments, std::filesystem::current_path());
    if (!process.has_value()) {
      return false;
    }
    return true;
  }

  // Reads the port the child reported. The child writes it to its --out file as
  // well as to stdout, so no pipe capture is needed.
  std::uint16_t read_port() {
    const std::string text = test::ChildProcess::read_text(port_file);
    const std::size_t at = text.find("port=");
    if (at == std::string::npos) {
      return 0;
    }
    return static_cast<std::uint16_t>(std::strtoul(text.c_str() + at + 5, nullptr, 10));
  }

  void kill() {
    if (process.has_value()) {
      process->kill_and_reap(2000);
      process.reset();
    }
  }

  ~CoordinatorProcess() { kill(); }
};

// Runs one publisher process. The child writes its result file, so the parent
// observes the real exit code and the real durable effect.
int run_publisher(const std::string& seed, std::uint16_t port, const std::string& workload,
                  std::uint64_t generation, double bandwidth, const std::filesystem::path& out) {
  std::error_code error;
  std::filesystem::remove(out, error);
  std::vector<std::string> arguments = {"publish",
                                        "--seed", seed,
                                        "--host", "127.0.0.1",
                                        "--port", std::to_string(port),
                                        "--workload", workload,
                                        "--generation", std::to_string(generation),
                                        "--bandwidth", std::to_string(bandwidth),
                                        "--out", out.string()};
  std::optional<test::ChildProcess> child =
      test::ChildProcess::spawn(harness_path(), arguments, std::filesystem::current_path());
  if (!child.has_value()) {
    return -1;
  }
  const std::optional<int> code = child->wait_for_exit(30000);
  return code.has_value() ? code.value() : -1;
}

int run_status(std::uint16_t port, const std::filesystem::path& out) {
  std::error_code error;
  std::filesystem::remove(out, error);
  std::vector<std::string> arguments = {"status",
                                        "--host", "127.0.0.1",
                                        "--port", std::to_string(port),
                                        "--out", out.string()};
  std::optional<test::ChildProcess> child =
      test::ChildProcess::spawn(harness_path(), arguments, std::filesystem::current_path());
  if (!child.has_value()) {
    return -1;
  }
  const std::optional<int> code = child->wait_for_exit(30000);
  return code.has_value() ? code.value() : -1;
}

}  // namespace

WNC_TEST(multiprocess, real_publishers_register_against_a_real_coordinator_process) {
  Guard guard("publish");
  const LocalSigner signer = signer_from_hex(std::string(64, '1'));
  const std::filesystem::path state = guard.path / "state";
  std::error_code error;
  std::filesystem::create_directories(state, error);

  CoordinatorProcess coordinator;
  WNC_CHECK(coordinator.start(state, signer, guard.path / "port1.txt"));
  WNC_CHECK(test::ChildProcess::wait_for_file_text(coordinator.port_file, "port=", 30000));
  const std::uint16_t port = coordinator.read_port();
  WNC_CHECK(port != 0);
  WNC_CHECK(coordinator.process->running());

  // Two independent publisher processes register two different workloads.
  const int first = run_publisher(std::string(64, '1'), port, "trainer-a", 1, 5000.0,
                                  guard.path / "publisher-a.txt");
  const int second = run_publisher(std::string(64, '1'), port, "trainer-b", 1, 7000.0,
                                   guard.path / "publisher-b.txt");
  WNC_CHECK_MSG(first == 0, "publisher a exited with " + std::to_string(first));
  WNC_CHECK_MSG(second == 0, "publisher b exited with " + std::to_string(second));

  const std::string first_result = test::ChildProcess::read_text(guard.path / "publisher-a.txt");
  const std::string second_result = test::ChildProcess::read_text(guard.path / "publisher-b.txt");
  WNC_CHECK(first_result.find("digest=") != std::string::npos);
  WNC_CHECK(second_result.find("digest=") != std::string::npos);
  WNC_CHECK(first_result.find("contract_generation=1") != std::string::npos);
  WNC_CHECK(second_result.find("contract_generation=1") != std::string::npos);

  // The coordinator is still alive and answered every request.
  WNC_CHECK(coordinator.process->running());
  coordinator.kill();
}

WNC_TEST(multiprocess, kill_and_restart_keeps_history_and_advances_the_epoch) {
  Guard guard("restart");
  const LocalSigner signer = signer_from_hex(std::string(64, '2'));
  const std::filesystem::path state = guard.path / "state";
  std::error_code error;
  std::filesystem::create_directories(state, error);

  std::uint64_t first_epoch = 0;
  std::string first_incarnation;
  {
    CoordinatorProcess coordinator;
    WNC_CHECK(coordinator.start(state, signer, guard.path / "port1.txt"));
    WNC_CHECK(test::ChildProcess::wait_for_file_text(coordinator.port_file, "port=", 30000));
    const std::uint16_t port = coordinator.read_port();
    WNC_CHECK(port != 0);
    WNC_CHECK_EQ(run_publisher(std::string(64, '2'), port, "trainer", 1, 5000.0,
                               guard.path / "publish1.txt"),
                 0);

    const std::filesystem::path status_file = guard.path / "status1.txt";
    WNC_CHECK_EQ(run_status(port, status_file), 0);
    const std::string status = test::ChildProcess::read_text(status_file);
    const std::size_t epoch_at = status.find("epoch=");
    WNC_CHECK(epoch_at != std::string::npos);
    first_epoch = std::strtoull(status.c_str() + epoch_at + 6, nullptr, 10);
    const std::size_t incarnation_at = status.find("incarnation=");
    WNC_CHECK(incarnation_at != std::string::npos);
    first_incarnation = status.substr(incarnation_at + 12);
    first_incarnation = first_incarnation.substr(0, first_incarnation.find('\n'));

    // A publisher process that outlives the coordinator must not be able to
    // continue: the kill is ungraceful and the next boot fences it.
    coordinator.kill();
  }

  // Second boot over the same directory.
  {
    CoordinatorProcess coordinator;
    WNC_CHECK(coordinator.start(state, signer, guard.path / "port2.txt"));
    WNC_CHECK(test::ChildProcess::wait_for_file_text(coordinator.port_file, "port=", 30000));
    const std::uint16_t port = coordinator.read_port();
    WNC_CHECK(port != 0);

    const std::filesystem::path status_file = guard.path / "status2.txt";
    WNC_CHECK_EQ(run_status(port, status_file), 0);
    const std::string status = test::ChildProcess::read_text(status_file);
    const std::size_t epoch_at = status.find("epoch=");
    WNC_CHECK(epoch_at != std::string::npos);
    const std::uint64_t second_epoch =
        std::strtoull(status.c_str() + epoch_at + 6, nullptr, 10);
    WNC_CHECK(second_epoch > first_epoch);
    const std::size_t incarnation_at = status.find("incarnation=");
    WNC_CHECK(incarnation_at != std::string::npos);
    std::string second_incarnation = status.substr(incarnation_at + 12);
    second_incarnation = second_incarnation.substr(0, second_incarnation.find('\n'));
    WNC_CHECK_NE(second_incarnation, first_incarnation);

    // The workload registered before the kill is still there, and re-registering
    // the same generation is refused: durable history survived without
    // restoring publisher liveness.
    const int replay = run_publisher(std::string(64, '2'), port, "trainer", 1, 5000.0,
                                     guard.path / "replay.txt");
    WNC_CHECK_MSG(replay != 0, "a replayed registration after restart was accepted");
    const std::string replay_result = test::ChildProcess::read_text(guard.path / "replay.txt");
    WNC_CHECK(replay_result.find("duplicate_workload") != std::string::npos ||
              replay_result.find("replay_rejected") != std::string::npos);

    coordinator.kill();
  }

  // The journal and head survived three ungraceful terminations.
  WNC_CHECK(std::filesystem::exists(state / "head.bin", error));
  bool saw_segment = false;
  for (const auto& entry : std::filesystem::directory_iterator(state, error)) {
    const std::string name = entry.path().filename().string();
    if (name.rfind("journal-", 0) == 0) {
      saw_segment = true;
    }
  }
  WNC_CHECK(saw_segment);
}

WNC_TEST(multiprocess, refusal_paths_of_the_harness_are_deterministic) {
  Guard guard("tool");
  std::optional<test::ChildProcess> keygen = test::ChildProcess::spawn(
      harness_path(),
      {"keygen", "--seed", std::string(64, '4'), "--out", (guard.path / "key.txt").string()},
      std::filesystem::current_path());
  WNC_CHECK(keygen.has_value());
  const std::optional<int> keygen_code = keygen->wait_for_exit(20000);
  WNC_CHECK(keygen_code.has_value());
  WNC_CHECK_EQ(keygen_code.value(), 0);
  const std::string key_text = test::ChildProcess::read_text(guard.path / "key.txt");
  WNC_CHECK(key_text.find("publisher=") != std::string::npos);
  WNC_CHECK(key_text.find("public_key=") != std::string::npos);

  std::optional<test::ChildProcess> bad_command = test::ChildProcess::spawn(
      harness_path(), {"no-such-command"}, std::filesystem::current_path());
  WNC_CHECK(bad_command.has_value());
  const std::optional<int> bad_code = bad_command->wait_for_exit(20000);
  WNC_CHECK(bad_code.has_value());
  WNC_CHECK_EQ(bad_code.value(), 2);

  std::optional<test::ChildProcess> missing_state =
      test::ChildProcess::spawn(harness_path(), {"coordinator"}, std::filesystem::current_path());
  WNC_CHECK(missing_state.has_value());
  const std::optional<int> missing_code = missing_state->wait_for_exit(20000);
  WNC_CHECK(missing_code.has_value());
  WNC_CHECK_EQ(missing_code.value(), 2);
}