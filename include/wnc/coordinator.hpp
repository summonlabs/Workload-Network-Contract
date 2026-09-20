// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// The coordinator service process.
//
// A Coordinator owns the durable authority surface (contracts, generations,
// evidence, policy, and evaluations) and serves it over the framed transport in
// wnc/wire.hpp. It is single threaded, bounded, and polled: every accept and
// every session wait has a deadline, so a caller can request a stop and be sure
// it is observed without a second thread.

#ifndef WNC_COORDINATOR_HPP
#define WNC_COORDINATOR_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "wnc/config.hpp"
#include "wnc/error.hpp"
#include "wnc/runtime.hpp"

namespace wnc {

// Settings that bound the listener and every session it accepts.
struct CoordinatorOptions {
  std::string bind_host = "127.0.0.1";
  std::uint16_t port = 0;  // 0 selects an ephemeral port
  std::size_t max_sessions = kMaxSessions;
  std::uint64_t idle_timeout_millis = 30000;
  std::uint64_t evidence_max_age_millis = 0;
};

// One service instance. Construction goes through start(), which opens the
// durable runtime before it binds the listener, so a coordinator that answers on
// a port always has its authority surface behind it.
class Coordinator {
 public:
  // Opens the runtime and binds the listener. On failure code and message
  // describe the refusal and no socket is left open.
  static std::optional<Coordinator> start(const CoordinatorOptions& options,
                                          Runtime::Options runtime_options, Code& code,
                                          std::string& message);

  Coordinator(Coordinator&& other) noexcept;
  Coordinator& operator=(Coordinator&& other) noexcept;
  Coordinator(const Coordinator&) = delete;
  Coordinator& operator=(const Coordinator&) = delete;
  ~Coordinator();

  // Identity of the runtime behind this coordinator.
  const CoordinatorId& coordinator_id() const noexcept;
  // Current epoch of the runtime behind this coordinator.
  std::uint64_t epoch() const noexcept;
  // Read-only access to the runtime, for in-process tests that need to compare
  // what the service reported over the wire with what it actually committed.
  const Runtime& runtime() const noexcept;
  // The same runtime, mutable, for an embedding host that drives it directly.
  Runtime& runtime() noexcept;
  // The bound port. Port 0 selects an ephemeral port, which this reports.
  std::uint16_t port() const noexcept;
  // False once stop() has been requested.
  bool healthy() const noexcept;
  // Asks the run loop to return. Nothing is closed here; stop() does that.
  void request_stop() noexcept;
  // Stops accepting, drains what can be drained, closes every session, and
  // releases the listener. Safe to call repeatedly.
  void stop() noexcept;
  std::size_t active_sessions() const noexcept;
  std::uint64_t served_requests() const noexcept;
  std::uint64_t rejected_requests() const noexcept;
  // One bounded accept and serve pass. timeout_millis bounds the wait for a new
  // connection; sessions that already have work are always served first.
  void run_once(std::uint64_t timeout_millis);
  // Loops until request_stop(). The caller owns the shutdown.
  void run();

 private:
  struct Impl;
  explicit Coordinator(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

}  // namespace wnc

#endif  // WNC_COORDINATOR_HPP
