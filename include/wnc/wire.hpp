// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Framed transport for the coordinator. The framing is fixed and versioned, the
// body is canonical JSON, and every frame carries a CRC32 over its header and a
// length that is checked against a hard bound before any allocation.
//
// Frame layout (little-endian):
//
//   offset  size  field
//   0       4     magic 0x574E4331 ("WNC1")
//   4       2     version
//   6       2     message type
//   8       4     flags
//   12      4     body length
//   16      8     request identifier
//   24      4     crc32 of bytes 0..23
//   28      ...   body
//
// A reader never trusts the declared length: it is checked against
// kMaxFrameBytes before the body is allocated, and the CRC is verified before
// the body is decoded.

#ifndef WNC_WIRE_HPP
#define WNC_WIRE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "wnc/error.hpp"
#include "wnc/json.hpp"

namespace wnc::wire {

inline constexpr std::size_t kHeaderBytes = 28;

enum class MessageType : std::uint16_t {
  kUnknown = 0,
  kHello = 1,
  kHelloReply = 2,
  kRegisterWorkload = 3,
  kPublishContract = 4,
  kAttachEvidence = 5,
  kEvaluate = 6,
  kStatus = 7,
  kDescribeContract = 8,
  kInstallPolicy = 9,
  kRetireWorkload = 10,
  kListWorkloads = 11,
  kRetireReplyGeneric = 12,
  kError = 255,
};

std::string_view message_type_token(MessageType type) noexcept;
std::optional<MessageType> parse_message_type(std::string_view token) noexcept;

struct Header {
  std::uint16_t version = 0;
  MessageType type = MessageType::kUnknown;
  std::uint32_t flags = 0;
  std::uint32_t body_length = 0;
  std::uint64_t request_id = 0;
};

// Appends one complete frame to out. Refuses a body above the bound.
bool encode_frame(MessageType type, std::uint64_t request_id, std::string_view body,
                  std::string& out, Code& code, std::string& message);

struct Frame {
  Header header;
  std::string body;
};

// Decodes one frame from a complete buffer. Returns false when the buffer is
// incomplete (kTruncatedFrame) or invalid.
bool decode_frame(std::string_view bytes, Frame& frame, std::size_t& consumed, Code& code,
                  std::string& message);

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

class Socket {
 public:
  Socket() = default;
  explicit Socket(std::uintptr_t handle) : handle_(handle) {}
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  ~Socket();

  [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidHandle; }
  [[nodiscard]] std::uintptr_t handle() const noexcept { return handle_; }
  void close() noexcept;

 private:
  static constexpr std::uintptr_t kInvalidHandle = static_cast<std::uintptr_t>(~0ull);
  std::uintptr_t handle_ = kInvalidHandle;
};

// Initialises the process wide socket layer. Safe to call repeatedly.
bool start_transport(Code& code, std::string& message);
void stop_transport() noexcept;

// Binds a listener to host:port. Port 0 selects an ephemeral port, which
// bound_port reports.
bool listen_on(std::string_view host, std::uint16_t port, Socket& listener, Code& code,
               std::string& message);
std::uint16_t bound_port(const Socket& listener);

// Connects to host:port.
bool connect_to(std::string_view host, std::uint16_t port, Socket& socket, Code& code,
                std::string& message);

// Reads exactly size bytes. Returns false with kIoFailed when the peer closed.
bool read_exact(const Socket& socket, std::span<std::uint8_t> buffer, Code& code, std::string& message);
bool write_all(const Socket& socket, std::string_view bytes, Code& code, std::string& message);

// Bounded wait for readability. Returns false with kDeadlineExceeded on expiry.
bool wait_readable(const Socket& socket, std::uint64_t timeout_millis, Code& code,
                   std::string& message);

// Accepts one connection. Returns false with kDeadlineExceeded when the wait
// expires, which is the normal way a server polls for shutdown.
bool accept_one(const Socket& listener, std::uint64_t timeout_millis, Socket& accepted, Code& code,
                std::string& message);

// Reads one whole frame from a socket. The declared length is refused when it
// exceeds kMaxFrameBytes, before any body allocation.
bool read_frame(const Socket& socket, Frame& frame, Code& code, std::string& message);

bool send_frame(const Socket& socket, MessageType type, std::uint64_t request_id,
                std::string_view body, Code& code, std::string& message);

// Makes a socket non blocking. Servers use this so that a stalled peer can
// never block the accept loop.
bool set_non_blocking(const Socket& socket, bool enabled, Code& code, std::string& message);

}  // namespace wnc::wire

#endif  // WNC_WIRE_HPP
