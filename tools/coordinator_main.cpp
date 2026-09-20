// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// wnc-coordinator: runs the coordinator service process.
//
// The tool is a thin shell over wnc::Coordinator. It binds the listener, prints
// the bound port on stdout when asked, and then serves until SIGINT or end of
// input on stdin. stdout carries the port line and nothing else; diagnostics go
// to stderr and only behind --verbose.

#include <array>
#include <atomic>
#include <charconv>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "wnc/coordinator.hpp"
#include "wnc/ed25519.hpp"
#include "wnc/error.hpp"
#include "wnc/identity.hpp"
#include "wnc/runtime.hpp"
#include "wnc/signature.hpp"
#include "wnc/wire.hpp"

using namespace wnc;

namespace {

std::atomic<bool> g_stop_requested{false};

void on_signal(int) { g_stop_requested.store(true); }

// End of input on stdin is the second way to ask the process to stop.
void watch_stdin() {
  std::array<char, 256> buffer{};
  while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), stdin) != nullptr) {
  }
  g_stop_requested.store(true);
}

void print_usage(std::ostream& out) {
  out << "usage: wnc-coordinator --state <dir> [--host <host>] [--port <port>]\n"
         "                       [--publisher <hex> --pubkey <hex>]...\n"
         "                       [--evidence-max-age-ms <n>] [--print-port] [--verbose]\n"
         "\n"
         "  --state <dir>              durable state directory (required)\n"
         "  --host <host>              bind address (default 127.0.0.1)\n"
         "  --port <port>              bind port, 0 selects an ephemeral port\n"
         "  --publisher <hex>          trusted publisher identity, paired with --pubkey\n"
         "  --pubkey <hex>             Ed25519 public key in hex, paired with --publisher\n"
         "  --evidence-max-age-ms <n>  evidence age bound, 0 selects the default\n"
         "  --print-port               print 'port=<n>' on stdout once bound\n"
         "  --out <file>               write port, epoch, and identity to a file once bound\n"
         "  --verbose                  write diagnostics to stderr\n"
         "\n"
         "exit codes: 0 normal, 2 configuration error, 3 runtime error\n";
}

bool parse_u64(std::string_view text, std::uint64_t& out) {
  if (text.empty()) {
    return false;
  }
  std::uint64_t value = 0;
  const char* const begin = text.data();
  const char* const end = text.data() + text.size();
  const std::from_chars_result result = std::from_chars(begin, end, value);
  if (result.ec != std::errc{} || result.ptr != end) {
    return false;
  }
  out = value;
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  std::string state_directory;
  std::string host = "127.0.0.1";
  std::uint64_t port = 0;
  std::uint64_t evidence_max_age_millis = 0;
  bool print_port = false;
std::string status_file;
  bool verbose = false;
  bool show_usage = false;
  std::vector<std::string> publishers;
  std::vector<std::string> public_keys;

  for (int index = 1; index < argc; ++index) {
    std::string_view argument(argv[index]);
    std::string_view inline_value;
    bool has_inline_value = false;
    if (argument.size() > 2 && argument[0] == '-' && argument[1] == '-') {
      const std::size_t equals = argument.find('=');
      if (equals != std::string_view::npos) {
        inline_value = argument.substr(equals + 1);
        has_inline_value = true;
        argument = argument.substr(0, equals);
      }
    }
    const auto take_value = [&](std::string_view& out) -> bool {
      if (has_inline_value) {
        out = inline_value;
        return true;
      }
      if (index + 1 >= argc) {
        return false;
      }
      ++index;
      out = std::string_view(argv[index]);
      return true;
    };

    if (argument == "--state") {
      std::string_view value;
      if (!take_value(value)) {
        std::cerr << "wnc-coordinator: --state requires a directory\n";
        return 2;
      }
      state_directory = std::string(value);
    } else if (argument == "--host") {
      std::string_view value;
      if (!take_value(value)) {
        std::cerr << "wnc-coordinator: --host requires a value\n";
        return 2;
      }
      host = std::string(value);
    } else if (argument == "--port") {
      std::string_view value;
      if (!take_value(value) || !parse_u64(value, port) || port > 65535) {
        std::cerr << "wnc-coordinator: --port requires a value between 0 and 65535\n";
        return 2;
      }
    } else if (argument == "--publisher") {
      std::string_view value;
      if (!take_value(value)) {
        std::cerr << "wnc-coordinator: --publisher requires an identity in hex\n";
        return 2;
      }
      publishers.emplace_back(value);
    } else if (argument == "--pubkey") {
      std::string_view value;
      if (!take_value(value)) {
        std::cerr << "wnc-coordinator: --pubkey requires a key in hex\n";
        return 2;
      }
      public_keys.emplace_back(value);
    } else if (argument == "--evidence-max-age-ms") {
      std::string_view value;
      if (!take_value(value) || !parse_u64(value, evidence_max_age_millis)) {
        std::cerr << "wnc-coordinator: --evidence-max-age-ms requires a non negative integer\n";
        return 2;
      }
    } else if (argument == "--print-port") {
      print_port = true;
    } else if (argument == "--out") {
      std::string_view value;
      if (!take_value(value)) {
        std::cerr << "wnc-coordinator: --out requires a file path\n";
        return 2;
      }
      // A parent process (a test, a supervisor) cannot rely on capturing this
      // process's stdout, so the bound port is also written to the named file.
      status_file = std::string(value);
    } else if (argument == "--verbose" || argument == "-v") {
      verbose = true;
    } else if (argument == "--help" || argument == "-h") {
      show_usage = true;
    } else {
      std::cerr << "wnc-coordinator: unrecognised argument '" << argument << "'\n";
      print_usage(std::cerr);
      return 2;
    }
  }

  if (show_usage) {
    print_usage(std::cout);
    return 0;
  }
  if (state_directory.empty()) {
    std::cerr << "wnc-coordinator: --state is required\n";
    print_usage(std::cerr);
    return 2;
  }
  if (publishers.size() != public_keys.size()) {
    std::cerr << "wnc-coordinator: every --publisher needs one matching --pubkey\n";
    return 2;
  }

  TrustSet trust;
  for (std::size_t index = 0; index < publishers.size(); ++index) {
    const std::optional<PublisherId> publisher = PublisherId::parse(publishers[index]);
    if (!publisher.has_value()) {
      std::cerr << "wnc-coordinator: --publisher must be a 64 character lowercase hex identity\n";
      return 2;
    }
    const std::optional<Digest> key_bytes = hex_decode_digest(public_keys[index]);
    if (!key_bytes.has_value()) {
      std::cerr << "wnc-coordinator: --pubkey must be a 64 character hex Ed25519 public key\n";
      return 2;
    }
    Ed25519PublicKey key{};
    for (std::size_t byte = 0; byte < key.size(); ++byte) {
      key[byte] = (*key_bytes)[byte];
    }
    trust.add_ed25519(*publisher, key);
  }

  CoordinatorOptions options;
  options.bind_host = host;
  options.port = static_cast<std::uint16_t>(port);
  options.evidence_max_age_millis = evidence_max_age_millis;

  Runtime::Options runtime_options;
  runtime_options.state_directory = std::filesystem::path(state_directory);
  runtime_options.trust = std::move(trust);
  runtime_options.evidence_max_age_millis = evidence_max_age_millis;

  Code code = Code::kOk;
  std::string message;
  std::optional<Coordinator> coordinator = Coordinator::start(options, runtime_options, code, message);
  if (!coordinator.has_value()) {
    std::cerr << "wnc-coordinator: " << code_token(code) << ": " << message << "\n";
    return 3;
  }

  if (print_port) {
    std::cout << "port=" << coordinator->port() << "\n" << std::flush;
  }
  if (!status_file.empty()) {
    // Written after the listener is bound, so a reader that sees the file also
    // sees a port that is accepting connections.
    std::ofstream stream(status_file, std::ios::binary | std::ios::trunc);
    if (!stream) {
      std::cerr << "wnc-coordinator: cannot write " << status_file << "\n";
      return 2;
    }
    stream << "port=" << coordinator->port() << "\n";
    stream << "epoch=" << coordinator->epoch() << "\n";
    stream << "coordinator=" << coordinator->coordinator_id().str() << "\n";
    stream.flush();
  }
  if (verbose) {
    std::cerr << "wnc-coordinator: bound " << host << ":" << coordinator->port() << "\n";
  }

  (void)std::signal(SIGINT, on_signal);
  (void)std::signal(SIGTERM, on_signal);
  std::thread(watch_stdin).detach();

  while (!g_stop_requested.load()) {
    coordinator->run_once(100);
  }
  coordinator->request_stop();
  coordinator->stop();

  if (verbose) {
    std::cerr << "wnc-coordinator: stopped; served=" << coordinator->served_requests()
              << " rejected=" << coordinator->rejected_requests() << "\n";
  }
  return 0;
}
