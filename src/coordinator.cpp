// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// The coordinator service process.
//
// The coordinator is the out-of-process authority: it owns contract
// generations, evidence, policy, and evaluations, and no other component
// assigns them. Clients speak the framed protocol of wnc/wire.hpp over TCP;
// every request and every reply is exactly one frame whose body is a canonical
// JSON object, and every failure is an error frame carrying a stable code.
//
// The loop is single threaded and bounded:
//
//   * at most max_sessions concurrent sessions, and a connection above the
//     bound is closed immediately instead of being queued;
//   * the listener is polled with a bounded wait, so request_stop() is observed
//     promptly and stop() can never deadlock;
//   * a session ends when its partial frame exceeds the framing bound, when it
//     stays idle past the configured timeout, when a framing failure makes the
//     stream unresynchronisable, or when the peer stops reading long enough that
//     the queued reply cannot be flushed;
//   * a reply is framed in memory before a single byte of it is written, so a
//     session never observes a partially written frame;
//   * session buffers are reused, no request allocates a thread, and no
//     attacker supplied length reaches an allocator: the declared frame length
//     is checked against kMaxFrameBytes before the body exists.

#include "wnc/coordinator.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "wnc/config.hpp"
#include "wnc/contract.hpp"
#include "wnc/evaluation.hpp"
#include "wnc/identity.hpp"
#include "wnc/json.hpp"
#include "wnc/policy.hpp"
#include "wnc/state.hpp"
#include "wnc/wire.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

namespace wnc {
namespace {

using wire::Frame;
using wire::MessageType;
using wire::Socket;

// One pass never waits longer than this for a new connection, so a stop request
// is observed within it even when the coordinator is completely idle.
constexpr std::uint64_t kAcceptPollMillis = 100;
// A pass that still has session work parks on that work rather than spinning.
constexpr std::uint64_t kWorkPollMillis = 20;
// A bounded wait for a session that is draining during shutdown.
constexpr std::uint64_t kDrainPollMillis = 50;
// Bytes taken from a readable socket in one receive.
constexpr std::size_t kReceiveChunkBytes = 16 * 1024;
// Frames served from one session in one pass before the loop looks elsewhere,
// so one busy peer cannot starve the others.
constexpr std::size_t kFramesPerPass = 8;
// Inbound capacity above this size is released when a session ends instead of
// being retained for reuse.
constexpr std::size_t kRetainedInboundBytes = 64 * 1024;
// Every request schema is namespaced by protocol version. The bare message type
// token is accepted as an alias so that the surface is forgiving about the
// prefix and strict about the tag.
constexpr std::string_view kSchemaPrefix = "wnc/v1/";

std::uint64_t monotonic_now() noexcept { return state::monotonic_millis(); }

bool socket_would_block() noexcept {
#if defined(_WIN32)
  return ::WSAGetLastError() == WSAEWOULDBLOCK;
#else
  return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

enum class ReceiveOutcome { kData, kWouldBlock, kClosed, kFailed };

// Reads what is already available. The socket is non blocking, so this never
// waits: a caller that wants to wait uses wire::wait_readable first.
ReceiveOutcome receive_some(const Socket& socket, std::string& buffer, Code& code,
                            std::string& message) {
  if (!socket.valid()) {
    code = Code::kSessionClosed;
    message = "session is not connected";
    return ReceiveOutcome::kClosed;
  }
  std::array<char, kReceiveChunkBytes> chunk{};
#if defined(_WIN32)
  const int received = ::recv(static_cast<SOCKET>(socket.handle()), chunk.data(),
                              static_cast<int>(chunk.size()), 0);
#else
  const ssize_t received = ::recv(static_cast<int>(socket.handle()), chunk.data(), chunk.size(), 0);
#endif
  if (received > 0) {
    buffer.append(chunk.data(), static_cast<std::size_t>(received));
    return ReceiveOutcome::kData;
  }
  if (received == 0) {
    code = Code::kSessionClosed;
    message = "peer closed the session";
    return ReceiveOutcome::kClosed;
  }
  if (socket_would_block()) {
    return ReceiveOutcome::kWouldBlock;
  }
  code = Code::kIoFailed;
  message = "receive failed";
  return ReceiveOutcome::kFailed;
}

enum class SendOutcome { kProgress, kWouldBlock, kFailed };

// Writes what the socket accepts. Progress is reported through offset.
SendOutcome send_some(const Socket& socket, const std::string& bytes, std::size_t& offset, Code& code,
                      std::string& message) {
  if (offset >= bytes.size()) {
    return SendOutcome::kProgress;
  }
  const std::size_t slice = std::min<std::size_t>(bytes.size() - offset, kReceiveChunkBytes);
#if defined(_WIN32)
  const int sent = ::send(static_cast<SOCKET>(socket.handle()), bytes.data() + offset,
                          static_cast<int>(slice), 0);
#else
  const ssize_t sent = ::send(static_cast<int>(socket.handle()), bytes.data() + offset, slice, MSG_NOSIGNAL);
#endif
  if (sent > 0) {
    offset += static_cast<std::size_t>(sent);
    return SendOutcome::kProgress;
  }
  if (socket_would_block()) {
    return SendOutcome::kWouldBlock;
  }
  code = Code::kIoFailed;
  message = "send failed";
  return SendOutcome::kFailed;
}

// Bounded wait for writability. wire.hpp exposes the read side of this; the
// write side is needed so a peer that stops reading parks the loop instead of
// spinning on it.
bool wait_writable(const Socket& socket, std::uint64_t timeout_millis) noexcept {
  if (!socket.valid()) {
    return false;
  }
  fd_set write_set;
  FD_ZERO(&write_set);
#if defined(_WIN32)
  FD_SET(static_cast<SOCKET>(socket.handle()), &write_set);
#else
  FD_SET(static_cast<int>(socket.handle()), &write_set);
#endif
  timeval timeout{};
  timeout.tv_sec = static_cast<long>(timeout_millis / 1000);
  timeout.tv_usec = static_cast<long>((timeout_millis % 1000) * 1000);
#if defined(_WIN32)
  return ::select(0, nullptr, &write_set, nullptr, &timeout) > 0;
#else
  return ::select(static_cast<int>(socket.handle()) + 1, nullptr, &write_set, nullptr, &timeout) > 0;
#endif
}

std::int64_t as_int(std::uint64_t value) noexcept { return static_cast<std::int64_t>(value); }

std::string incarnation_text(const Incarnation& incarnation) {
  return base64url_encode(std::span<const std::uint8_t>(incarnation.bytes.data(), incarnation.bytes.size()));
}

// The handler a schema tag selects. Reply-only and undefined tags are not
// requests and are refused as unknown payload schemas.
std::optional<MessageType> schema_handler(std::string_view schema) noexcept {
  if (schema.starts_with(kSchemaPrefix)) {
    schema.remove_prefix(kSchemaPrefix.size());
  }
  const std::optional<MessageType> parsed = wire::parse_message_type(schema);
  if (!parsed.has_value()) {
    return std::nullopt;
  }
  switch (*parsed) {
    case MessageType::kHello:
    case MessageType::kRegisterWorkload:
    case MessageType::kPublishContract:
    case MessageType::kAttachEvidence:
    case MessageType::kEvaluate:
    case MessageType::kStatus:
    case MessageType::kDescribeContract:
    case MessageType::kInstallPolicy:
    case MessageType::kRetireWorkload:
    case MessageType::kListWorkloads:
      return parsed;
    default:
      return std::nullopt;
  }
}

// True when the frame type is a value this version defines. message_type_token
// falls back to "unknown" for undefined values, so a defined non-unknown type is
// exactly one whose token is not that fallback.
bool defined_message_type(MessageType type) noexcept {
  return type == MessageType::kUnknown ||
         wire::message_type_token(type) != std::string_view("unknown");
}

// Removes the claims an evidence submitter may not make, before the document is
// decoded.
//
//   * the capture incarnation and epoch belong to the coordinator: the runtime
//     stamps both when the evidence becomes durable, so a placeholder must not
//     be read as malformed provenance and a forged one must not be read as
//     provenance at all;
//   * the evidence identity is the content address of the canonical evidence
//     bytes, which a submitter cannot compute before the coordinator stamps it.
//     The zero identity is the canonical "no identity" value, so a zero
//     evidence_id is treated as not stated; a non zero one is left in place and
//     is still verified against the canonical bytes by the decoder.
Json normalize_evidence_document(const Json& document) {
  if (!document.is_object()) {
    return document;
  }
  JsonObject top;
  for (const auto& field : document.object()) {
    if (field.first == "evidence_id" && field.second.is_string()) {
      const std::optional<EvidenceId> declared = EvidenceId::parse(field.second.as_string());
      if (declared.has_value() && declared->is_zero()) {
        continue;
      }
    }
    if (field.first != "entries" || !field.second.is_array()) {
      top.emplace(field.first, field.second);
      continue;
    }
    JsonArray cleaned;
    cleaned.reserve(field.second.size());
    for (std::size_t index = 0; index < field.second.size(); ++index) {
      const Json* item = field.second.at(index);
      if (item == nullptr || !item->is_object()) {
        cleaned.push_back(item == nullptr ? Json() : *item);
        continue;
      }
      JsonObject entry_fields;
      for (const auto& entry_field : item->object()) {
        if (entry_field.first == "captured_by" || entry_field.first == "epoch") {
          continue;
        }
        entry_fields.emplace(entry_field.first, entry_field.second);
      }
      cleaned.push_back(Json(std::move(entry_fields)));
    }
    top.emplace("entries", Json(std::move(cleaned)));
  }
  return Json(std::move(top));
}

struct Session {
  Socket socket;
  std::string inbound;
  std::string outbound;
  std::size_t out_offset = 0;
  std::uint64_t last_activity_millis = 0;
  bool used = false;
  // True while immediately serviceable work remains, so the loop does not sleep
  // on a socket while a frame is already buffered.
  bool ready = false;

  bool pending_output() const noexcept { return out_offset < outbound.size(); }
};

}  // namespace

struct Coordinator::Impl {
  CoordinatorOptions options{};
  Runtime runtime{};
  Socket listener{};
  std::vector<Session> sessions{};
  std::uint16_t bound_port = 0;
  // The stop flags and the request counters are the only members another thread
  // may touch: a caller may request a stop, and read the counters, while run()
  // is on another thread. Everything else is owned by the serving thread.
  std::atomic<bool> stop_requested{false};
  std::atomic<bool> stopped{false};
  std::atomic<std::uint64_t> served{0};
  std::atomic<std::uint64_t> rejected{0};

  // -------------------------------------------------------------------------
  // Pass structure
  // -------------------------------------------------------------------------

  void run_pass(std::uint64_t timeout_millis) {
    if (stop_requested.load() || stopped.load()) {
      return;
    }
    std::uint64_t wait = std::min<std::uint64_t>(timeout_millis, kAcceptPollMillis);
    if (has_pending_output()) {
      // A peer that has stopped reading must not stall the loop: park on its
      // writability for a bounded slice instead of retrying in a spin.
      if (const Socket* blocked = first_pending_output(); blocked != nullptr) {
        (void)wait_writable(*blocked, std::min<std::uint64_t>(timeout_millis, kWorkPollMillis));
      }
      wait = 0;
    } else if (has_ready_session()) {
      wait = 0;
    }
    accept_pending(wait);
    serve_sessions();
    reap_idle(monotonic_now());
  }

  void serve_sessions() {
    for (Session& session : sessions) {
      if (!session.used) {
        continue;
      }
      pump(session);
    }
  }

  // -------------------------------------------------------------------------
  // Sessions
  // -------------------------------------------------------------------------

  void accept_pending(std::uint64_t timeout_millis) {
    if (!listener.valid() || stop_requested.load()) {
      return;
    }
    Code code = Code::kOk;
    std::string message;
    Socket accepted;
    if (!wire::accept_one(listener, timeout_millis, accepted, code, message)) {
      // kDeadlineExceeded is the normal poll result. A listener failure ends
      // accepting for this pass; the next pass reports it again.
      return;
    }
    if (active_sessions() >= options.max_sessions) {
      ++rejected;
      accepted.close();
      return;
    }
    Code mode_code = Code::kOk;
    std::string mode_message;
    if (!wire::set_non_blocking(accepted, true, mode_code, mode_message)) {
      ++rejected;
      accepted.close();
      return;
    }
    Session* slot = free_slot();
    if (slot == nullptr) {
      ++rejected;
      accepted.close();
      return;
    }
    slot->socket = std::move(accepted);
    slot->inbound.clear();
    slot->outbound.clear();
    slot->out_offset = 0;
    slot->ready = false;
    slot->used = true;
    slot->last_activity_millis = monotonic_now();
  }

  Session* free_slot() {
    for (Session& session : sessions) {
      if (!session.used) {
        return &session;
      }
    }
    if (sessions.size() >= options.max_sessions) {
      return nullptr;
    }
    sessions.emplace_back();
    return &sessions.back();
  }

  void drop(Session& session) noexcept {
    session.socket.close();
    if (session.inbound.capacity() > kRetainedInboundBytes) {
      std::string().swap(session.inbound);
    } else {
      session.inbound.clear();
    }
    session.outbound.clear();
    session.out_offset = 0;
    session.last_activity_millis = 0;
    session.ready = false;
    session.used = false;
  }

  void flush(Session& session) {
    while (session.pending_output()) {
      Code code = Code::kOk;
      std::string message;
      const SendOutcome outcome = send_some(session.socket, session.outbound, session.out_offset, code, message);
      if (outcome == SendOutcome::kWouldBlock) {
        session.ready = true;
        return;
      }
      if (outcome == SendOutcome::kFailed) {
        drop(session);
        return;
      }
      session.last_activity_millis = monotonic_now();
    }
    session.outbound.clear();
    session.out_offset = 0;
  }

  // -------------------------------------------------------------------------
  // Replies
  // -------------------------------------------------------------------------

  bool queue_frame(Session& session, MessageType type, std::uint64_t request_id, const Json& body) {
    std::string encoded;
    Code code = Code::kOk;
    std::string message;
    if (!wire::encode_frame(type, request_id, body.dump(), encoded, code, message)) {
      // A reply that cannot be framed is a session failure, never a partially
      // written frame.
      drop(session);
      return false;
    }
    session.outbound.append(encoded);
    return true;
  }

  void queue_success(Session& session, std::uint64_t request_id, const Json& body) {
    ++served;
    (void)queue_frame(session, MessageType::kRetireReplyGeneric, request_id, body);
  }

  // A refusal the peer can attribute to its request. A framing failure never
  // reaches here: it ends the session without a reply.
  void queue_error(Session& session, std::uint64_t request_id, Code code,
                   const std::string& message) {
    Json body;
    body.set("ok", false);
    body.set("code", std::string(code_token(code)));
    body.set("message", message.empty() ? std::string(code_description(code)) : message);
    ++rejected;
    (void)queue_frame(session, MessageType::kError, request_id, body);
  }

  // -------------------------------------------------------------------------
  // Request handling
  // -------------------------------------------------------------------------

  void pump(Session& session) {
    session.ready = false;
    flush(session);
    if (!session.used) {
      return;
    }
    if (session.pending_output()) {
      session.ready = true;
      return;
    }
    std::size_t processed = 0;
    for (;;) {
      // Serve what is already buffered before waiting on the socket again.
      while (processed < kFramesPerPass && !session.pending_output()) {
        if (session.inbound.size() < wire::kHeaderBytes) {
          break;
        }
        Frame frame;
        std::size_t consumed = 0;
        Code code = Code::kOk;
        std::string message;
        if (!wire::decode_frame(session.inbound, frame, consumed, code, message)) {
          if (code == Code::kTruncatedFrame) {
            break;  // the rest of the frame has not arrived yet
          }
          // A framing failure leaves the byte stream unresynchronisable and no
          // request identifier can be trusted, so the refusal is the close
          // itself: the session ends without a reply that could be attributed
          // to the wrong request.
          ++rejected;
          drop(session);
          return;
        }
        session.inbound.erase(0, consumed);
        session.last_activity_millis = monotonic_now();
        handle_frame(session, frame);
        if (!session.used) {
          return;
        }
        flush(session);
        if (!session.used) {
          return;
        }
        ++processed;
      }
      if (session.pending_output()) {
        session.ready = true;
        return;
      }
      if (processed >= kFramesPerPass) {
        session.ready = true;
        return;
      }
      if (session.inbound.size() > kMaxFrameBytes) {
        // The partial frame passed the framing bound; the session is closed
        // rather than buffering without limit.
        drop(session);
        return;
      }
      Code code = Code::kOk;
      std::string message;
      if (!wire::wait_readable(session.socket, 0, code, message)) {
        if (code != Code::kDeadlineExceeded) {
          drop(session);
        }
        return;
      }
      const ReceiveOutcome outcome = receive_some(session.socket, session.inbound, code, message);
      if (outcome == ReceiveOutcome::kData) {
        session.last_activity_millis = monotonic_now();
        continue;
      }
      if (outcome == ReceiveOutcome::kWouldBlock) {
        return;
      }
      drop(session);
      return;
    }
  }

  void handle_frame(Session& session, const Frame& frame) {
    const std::uint64_t request_id = frame.header.request_id;
    if (!defined_message_type(frame.header.type)) {
      // The frame itself is intact, so the session continues.
      queue_error(session, request_id, Code::kUnknownFrameType,
                  "frame type is not defined by this protocol version");
      return;
    }
    const JsonDecodeResult decoded = json_decode(frame.body, JsonDecodeOptions{});
    if (!decoded.ok) {
      queue_error(session, request_id, decoded.code, decoded.message);
      return;
    }
    if (!decoded.value.is_object()) {
      queue_error(session, request_id, Code::kJsonNotAnObject,
                  "request body must be a JSON object");
      return;
    }
    const Json& body = decoded.value;
    const FieldReader reader{body, "request"};
    std::string_view schema;
    Code code = Code::kOk;
    std::string message;
    if (!reader.require_string("schema", schema, code, message)) {
      queue_error(session, request_id, code, message);
      return;
    }
    const std::optional<MessageType> handler = schema_handler(schema);
    if (!handler.has_value()) {
      queue_error(session, request_id, Code::kUnknownPayloadSchema,
                  "payload schema '" + std::string(schema) + "' is not supported");
      return;
    }
    if (frame.header.type != MessageType::kUnknown && frame.header.type != *handler) {
      queue_error(session, request_id, Code::kUnknownPayloadSchema,
                  "payload schema does not match the frame type");
      return;
    }
    switch (*handler) {
      case MessageType::kHello:
        handle_hello(session, request_id);
        return;
      case MessageType::kRegisterWorkload:
        handle_contract_submission(session, request_id, body, /*publish=*/false);
        return;
      case MessageType::kPublishContract:
        handle_contract_submission(session, request_id, body, true);
        return;
      case MessageType::kAttachEvidence:
        handle_attach_evidence(session, request_id, body);
        return;
      case MessageType::kInstallPolicy:
        handle_install_policy(session, request_id, body);
        return;
      case MessageType::kEvaluate:
        handle_evaluate(session, request_id, body);
        return;
      case MessageType::kStatus:
        handle_status(session, request_id);
        return;
      case MessageType::kListWorkloads:
        handle_list_workloads(session, request_id);
        return;
      case MessageType::kDescribeContract:
        handle_describe_contract(session, request_id, body);
        return;
      case MessageType::kRetireWorkload:
        handle_retire_workload(session, request_id, body);
        return;
      default:
        queue_error(session, request_id, Code::kUnknownPayloadSchema,
                    "payload schema is not a request schema");
        return;
    }
  }

  void handle_hello(Session& session, std::uint64_t request_id) {
    const RuntimeInfo& info = runtime.info();
    Json body;
    body.set("coordinator", info.coordinator.str());
    body.set("incarnation", incarnation_text(info.incarnation));
    body.set("epoch", as_int(info.epoch));
    body.set("trust_digest", hex_encode(info.trust_digest));
    body.set("started_at_millis", as_int(info.started_at_millis));
    body.set("recovered", info.recovered);
    body.set("recovered_records", as_int(info.recovered_records));
    body.set("truncated_bytes", as_int(info.truncated_bytes));
    ++served;
    (void)queue_frame(session, MessageType::kHelloReply, request_id, body);
  }

  void handle_contract_submission(Session& session, std::uint64_t request_id, const Json& body,
                                  bool publish) {
    const Json* document = body.find("contract");
    if (document == nullptr) {
      queue_error(session, request_id, Code::kJsonMissingField, "request.contract is required");
      return;
    }
    const ContractDecodeResult decoded = contract_from_json(*document);
    if (!decoded.ok) {
      queue_error(session, request_id, decoded.code, decoded.message);
      return;
    }
    Json reply;
    reply.set("ok", true);
    if (publish) {
      const PublishResult result = runtime.publish(decoded.contract);
      if (!result.ok) {
        queue_error(session, request_id, result.code, result.message);
        return;
      }
      reply.set("workload", result.workload.str());
      reply.set("contract", result.contract.str());
      reply.set("digest", hex_encode(result.digest));
      reply.set("contract_generation", as_int(result.generation.value));
      reply.set("sequence", as_int(result.sequence));
    } else {
      const RegisterResult result = runtime.register_workload(decoded.contract);
      if (!result.ok) {
        queue_error(session, request_id, result.code, result.message);
        return;
      }
      reply.set("workload", result.workload.str());
      reply.set("contract", result.contract.str());
      reply.set("digest", hex_encode(result.digest));
      reply.set("contract_generation", as_int(result.contract_generation.value));
      reply.set("sequence", as_int(result.sequence));
    }
    queue_success(session, request_id, reply);
  }

  void handle_attach_evidence(Session& session, std::uint64_t request_id, const Json& body) {
    const Json* document = body.find("evidence");
    if (document == nullptr) {
      queue_error(session, request_id, Code::kJsonMissingField, "request.evidence is required");
      return;
    }
    const EvidenceDecodeResult decoded = evidence_from_json(normalize_evidence_document(*document));
    if (!decoded.ok) {
      queue_error(session, request_id, decoded.code, decoded.message);
      return;
    }
    const AttachEvidenceResult result = runtime.attach_evidence(decoded.evidence);
    if (!result.ok) {
      queue_error(session, request_id, result.code, result.message);
      return;
    }
    Json reply;
    reply.set("ok", true);
    reply.set("evidence", result.evidence.str());
    reply.set("evidence_generation", as_int(result.generation.value));
    reply.set("sequence", as_int(result.sequence));
    reply.set("invalidated_evaluations", as_int(static_cast<std::uint64_t>(result.invalidated_evaluations)));
    queue_success(session, request_id, reply);
  }

  void handle_install_policy(Session& session, std::uint64_t request_id, const Json& body) {
    const Json* document = body.find("policy");
    if (document == nullptr) {
      queue_error(session, request_id, Code::kJsonMissingField, "request.policy is required");
      return;
    }
    const PolicyDecodeResult decoded = policy_from_json(*document);
    if (!decoded.ok) {
      queue_error(session, request_id, decoded.code, decoded.message);
      return;
    }
    const RuntimePolicyResult result = runtime.install_policy(decoded.policy);
    if (!result.ok) {
      queue_error(session, request_id, result.code, result.message);
      return;
    }
    Json reply;
    reply.set("ok", true);
    reply.set("policy", result.policy.str());
    reply.set("policy_generation", as_int(result.generation.value));
    reply.set("sequence", as_int(result.sequence));
    queue_success(session, request_id, reply);
  }

  void handle_evaluate(Session& session, std::uint64_t request_id, const Json& body) {
    WorkloadId workload{};
    Code code = Code::kOk;
    std::string message;
    if (!read_workload_id(body, workload, code, message)) {
      queue_error(session, request_id, code, message);
      return;
    }
    const EvaluationResult result = runtime.evaluate(workload);
    if (!result.ok) {
      queue_error(session, request_id, result.code, result.message);
      return;
    }
    Json reply;
    reply.set("ok", true);
    reply.set("evaluation", evaluation_to_json(result.evaluation));
    queue_success(session, request_id, reply);
  }

  void handle_status(Session& session, std::uint64_t request_id) {
    const RuntimeInfo& info = runtime.info();
    const RuntimeState& state = runtime.state();
    Json body;
    body.set("ok", true);
    body.set("coordinator", info.coordinator.str());
    body.set("incarnation", incarnation_text(info.incarnation));
    body.set("epoch", as_int(info.epoch));
    body.set("trust_digest", hex_encode(info.trust_digest));
    body.set("started_at_millis", as_int(info.started_at_millis));
    body.set("recovered", info.recovered);
    body.set("recovered_records", as_int(info.recovered_records));
    body.set("truncated_bytes", as_int(info.truncated_bytes));
    body.set("policy_generation", as_int(state.policy_generation.value));
    body.set("contract_floor", as_int(state.contract_floor.value));
    body.set("evidence_floor", as_int(state.evidence_floor.value));
    body.set("workload_count", as_int(static_cast<std::uint64_t>(state.workloads.size())));
    body.set("active_sessions", as_int(static_cast<std::uint64_t>(active_sessions())));
    body.set("served_requests", as_int(served.load()));
    body.set("rejected_requests", as_int(rejected.load()));
    body.set("healthy", !stop_requested.load() && !stopped.load());
    queue_success(session, request_id, body);
  }

  void handle_list_workloads(Session& session, std::uint64_t request_id) {
    JsonArray items;
    for (const WorkloadId& id : runtime.workloads()) {
      const std::optional<WorkloadSnapshot> snapshot = runtime.snapshot(id);
      if (snapshot.has_value()) {
        items.push_back(snapshot_to_json(*snapshot));
      }
    }
    Json body;
    body.set("ok", true);
    body.set("count", as_int(static_cast<std::uint64_t>(items.size())));
    body.set("workloads", Json(std::move(items)));
    queue_success(session, request_id, body);
  }

  void handle_describe_contract(Session& session, std::uint64_t request_id, const Json& body) {
    WorkloadId workload{};
    Code code = Code::kOk;
    std::string message;
    if (!read_workload_id(body, workload, code, message)) {
      queue_error(session, request_id, code, message);
      return;
    }
    const std::optional<WorkloadSnapshot> snapshot = runtime.snapshot(workload);
    if (!snapshot.has_value()) {
      queue_error(session, request_id, Code::kUnknownWorkload,
                  "no contract is registered for that workload");
      return;
    }
    std::uint64_t generation = snapshot->contract_generation.value;
    if (const Json* requested = body.find("generation"); requested != nullptr) {
      if (!requested->is_int()) {
        queue_error(session, request_id, Code::kJsonWrongType,
                    "request.generation must be an integer");
        return;
      }
      if (requested->as_int() < 0) {
        queue_error(session, request_id, Code::kValueOutOfRange,
                    "request.generation must not be negative");
        return;
      }
      if (requested->as_int() != 0) {
        generation = static_cast<std::uint64_t>(requested->as_int());
      }
    }
    const std::optional<Contract> contract = runtime.contract_at(workload, ContractGeneration{generation});
    if (!contract.has_value()) {
      queue_error(session, request_id, Code::kUnknownContract,
                  "contract generation " + std::to_string(generation) + " is not retained");
      return;
    }
    Json reply;
    reply.set("ok", true);
    reply.set("workload", workload.str());
    reply.set("contract", contract_to_json(*contract));
    reply.set("contract_generation", as_int(generation));
    reply.set("retired", snapshot->retired);
    queue_success(session, request_id, reply);
  }

  void handle_retire_workload(Session& session, std::uint64_t request_id, const Json& body) {
    WorkloadId workload{};
    Code code = Code::kOk;
    std::string message;
    if (!read_workload_id(body, workload, code, message)) {
      queue_error(session, request_id, code, message);
      return;
    }
    const RetireResult result = runtime.retire(workload);
    if (!result.ok) {
      queue_error(session, request_id, result.code, result.message);
      return;
    }
    Json reply;
    reply.set("ok", true);
    reply.set("workload", workload.str());
    reply.set("retired", true);
    reply.set("sequence", as_int(result.sequence));
    queue_success(session, request_id, reply);
  }

  // -------------------------------------------------------------------------
  // Rendering
  // -------------------------------------------------------------------------

  bool read_workload_id(const Json& body, WorkloadId& out, Code& code, std::string& message) const {
    const Json* value = body.find("workload");
    if (value == nullptr) {
      code = Code::kJsonMissingField;
      message = "request.workload is required";
      return false;
    }
    if (!value->is_string()) {
      code = Code::kJsonWrongType;
      message = "request.workload must be a string";
      return false;
    }
    const std::optional<WorkloadId> parsed = WorkloadId::parse(value->as_string());
    if (!parsed.has_value()) {
      code = Code::kJsonWrongType;
      message = "request.workload must be a 64 character lowercase hexadecimal identity";
      return false;
    }
    // The zero identity is a well formed identity that no workload can hold:
    // it is answered as an unknown workload, never as a malformed request.
    out = *parsed;
    return true;
  }

  static Json summary_to_json(const EvaluationSummary& summary) {
    Json out;
    out.set("required_total", as_int(summary.required_total));
    out.set("required_satisfied", as_int(summary.required_satisfied));
    out.set("required_unsatisfied", as_int(summary.required_unsatisfied));
    out.set("required_unknown", as_int(summary.required_unknown));
    out.set("preferred_satisfied", as_int(summary.preferred_satisfied));
    out.set("preferred_unsatisfied", as_int(summary.preferred_unsatisfied));
    out.set("preferred_unknown", as_int(summary.preferred_unknown));
    out.set("informational", as_int(summary.informational));
    out.set("not_applicable", as_int(summary.not_applicable));
    return out;
  }

  static Json requirement_to_json(const RequirementEvaluation& item) {
    Json out;
    out.set("requirement", item.requirement.str());
    out.set("scope", item.scope);
    out.set("kind", std::string(requirement_kind_token(item.kind)));
    out.set("strength", std::string(requirement_strength_token(item.strength)));
    out.set("satisfaction", std::string(satisfaction_token(item.satisfaction)));
    out.set("reason_code", std::string(code_token(item.reason_code)));
    out.set("reason", item.reason);
    out.set("evidence", item.evidence.str());
    out.set("evidence_generation", as_int(item.evidence_generation.value));
    out.set("freshness", std::string(freshness_token(item.freshness)));
    if (item.observed.has_value()) {
      out.set("observed", *item.observed);
    }
    return out;
  }

  static Json evaluation_to_json(const ContractEvaluation& evaluation) {
    Json out;
    out.set("workload", evaluation.workload.str());
    out.set("contract", evaluation.contract.str());
    out.set("contract_generation", as_int(evaluation.contract_generation.value));
    out.set("contract_digest", hex_encode(evaluation.contract_digest));
    out.set("policy_generation", as_int(evaluation.policy_generation.value));
    out.set("evidence_generation", as_int(evaluation.evidence_generation.value));
    out.set("evaluated_by", incarnation_text(evaluation.evaluated_by));
    out.set("epoch", as_int(evaluation.epoch));
    out.set("evaluated_at_millis", as_int(evaluation.evaluated_at_millis));
    out.set("aggregate", std::string(satisfaction_token(evaluation.aggregate)));
    out.set("summary", summary_to_json(evaluation.summary));
    JsonArray requirements;
    requirements.reserve(evaluation.requirements.size());
    for (const RequirementEvaluation& item : evaluation.requirements) {
      requirements.push_back(requirement_to_json(item));
    }
    out.set("requirements", Json(std::move(requirements)));
    return out;
  }

  static Json snapshot_to_json(const WorkloadSnapshot& snapshot) {
    Json out;
    out.set("id", snapshot.id.str());
    out.set("name", snapshot.name);
    out.set("workload_generation", as_int(snapshot.workload_generation.value));
    out.set("contract_generation", as_int(snapshot.contract_generation.value));
    out.set("digest", hex_encode(snapshot.digest));
    out.set("contract", snapshot.contract.str());
    out.set("policy_generation", as_int(snapshot.policy_generation.value));
    out.set("evidence_generation", as_int(snapshot.evidence_generation.value));
    out.set("retired", snapshot.retired);
    JsonArray history;
    history.reserve(snapshot.history.size());
    for (const GenerationHistory& record : snapshot.history) {
      Json entry;
      entry.set("generation", as_int(record.generation.value));
      entry.set("digest", hex_encode(record.digest));
      entry.set("contract", record.contract_id.str());
      entry.set("recorded_at_millis", as_int(record.recorded_at_millis));
      entry.set("superseded", record.superseded);
      entry.set("retired", record.retired);
      history.push_back(std::move(entry));
    }
    out.set("history", Json(std::move(history)));
    return out;
  }

  // -------------------------------------------------------------------------
  // Bookkeeping
  // -------------------------------------------------------------------------

  std::size_t active_sessions() const noexcept {
    std::size_t count = 0;
    for (const Session& session : sessions) {
      if (session.used) {
        ++count;
      }
    }
    return count;
  }

  bool has_ready_session() const noexcept {
    for (const Session& session : sessions) {
      if (session.used && session.ready) {
        return true;
      }
    }
    return false;
  }

  bool has_pending_output() const noexcept { return first_pending_output() != nullptr; }

  const Socket* first_pending_output() const noexcept {
    for (const Session& session : sessions) {
      if (session.used && session.pending_output()) {
        return &session.socket;
      }
    }
    return nullptr;
  }

  void reap_idle(std::uint64_t now_millis) noexcept {
    if (options.idle_timeout_millis == 0) {
      return;
    }
    for (Session& session : sessions) {
      if (!session.used) {
        continue;
      }
      if (now_millis - session.last_activity_millis > options.idle_timeout_millis) {
        drop(session);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Shutdown
  // -------------------------------------------------------------------------

  void shutdown() noexcept {
    stop_requested = true;
    // Stop accepting first: no new session may be created after this point.
    listener.close();
    const std::uint64_t deadline = monotonic_now() + kSessionDrainMillis;
    for (Session& session : sessions) {
      if (!session.used) {
        continue;
      }
      while (session.used && session.pending_output() && monotonic_now() < deadline) {
        if (!wait_writable(session.socket, kDrainPollMillis)) {
          continue;
        }
        flush(session);
      }
      if (session.used) {
        // Whatever could not be written inside the drain window is abandoned by
        // closing the socket; no partial frame is ever composed by hand.
        drop(session);
      }
    }
    sessions.clear();
    stopped = true;
  }
};

// ---------------------------------------------------------------------------
// Coordinator
// ---------------------------------------------------------------------------

std::optional<Coordinator> Coordinator::start(const CoordinatorOptions& options,
                                              Runtime::Options runtime_options, Code& code,
                                              std::string& message) {
  auto impl = std::make_unique<Impl>();
  impl->options = options;
  if (impl->options.max_sessions == 0) {
    impl->options.max_sessions = kMaxSessions;
  }
  if (options.evidence_max_age_millis != 0) {
    runtime_options.evidence_max_age_millis = options.evidence_max_age_millis;
  }
  if (runtime_options.max_sessions == 0) {
    runtime_options.max_sessions = impl->options.max_sessions;
  }

  std::optional<Runtime> runtime = Runtime::open(runtime_options, code, message);
  if (!runtime.has_value()) {
    return std::nullopt;
  }
  impl->runtime = std::move(*runtime);

  Socket listener;
  if (!wire::listen_on(impl->options.bind_host, impl->options.port, listener, code, message)) {
    return std::nullopt;
  }
  impl->bound_port = wire::bound_port(listener);
  impl->listener = std::move(listener);
  impl->sessions.resize(std::min<std::size_t>(impl->options.max_sessions, kMaxSessions));
  return Coordinator(std::move(impl));
}

Coordinator::Coordinator(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}

Coordinator::Coordinator(Coordinator&& other) noexcept = default;
Coordinator& Coordinator::operator=(Coordinator&& other) noexcept = default;
Coordinator::~Coordinator() { stop(); }

const CoordinatorId& Coordinator::coordinator_id() const noexcept {
  static const CoordinatorId kNoCoordinator{};
  return impl_ ? impl_->runtime.info().coordinator : kNoCoordinator;
}

std::uint64_t Coordinator::epoch() const noexcept {
  return impl_ ? impl_->runtime.info().epoch : 0;
}

const Runtime& Coordinator::runtime() const noexcept {
  static const Runtime kNoRuntime{};
  return impl_ ? impl_->runtime : kNoRuntime;
}

Runtime& Coordinator::runtime() noexcept {
  static Runtime kNoRuntime{};
  return impl_ ? impl_->runtime : kNoRuntime;
}

std::uint16_t Coordinator::port() const noexcept { return impl_ ? impl_->bound_port : 0; }

bool Coordinator::healthy() const noexcept {
  return impl_ && !impl_->stop_requested.load() && !impl_->stopped.load();
}

void Coordinator::request_stop() noexcept {
  if (impl_) {
    impl_->stop_requested = true;
  }
}

void Coordinator::stop() noexcept {
  if (impl_) {
    impl_->shutdown();
  }
}

std::size_t Coordinator::active_sessions() const noexcept {
  return impl_ ? impl_->active_sessions() : 0;
}

std::uint64_t Coordinator::served_requests() const noexcept {
  return impl_ ? impl_->served.load() : 0;
}

std::uint64_t Coordinator::rejected_requests() const noexcept {
  return impl_ ? impl_->rejected.load() : 0;
}

void Coordinator::run_once(std::uint64_t timeout_millis) {
  if (impl_) {
    impl_->run_pass(timeout_millis);
  }
}

void Coordinator::run() {
  if (!impl_) {
    return;
  }
  while (!impl_->stop_requested.load() && !impl_->stopped.load()) {
    impl_->run_pass(kAcceptPollMillis);
  }
}

}  // namespace wnc
