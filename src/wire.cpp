// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/wire.hpp"

#include <array>
#include <cstring>

#include "wnc/config.hpp"
#include "wnc/hash.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace wnc::wire {
namespace {

constexpr std::array<std::pair<MessageType, std::string_view>, 13> kMessageTokens = {{
    {MessageType::kUnknown, "unknown"},
    {MessageType::kHello, "hello"},
    {MessageType::kHelloReply, "hello_reply"},
    {MessageType::kRegisterWorkload, "register_workload"},
    {MessageType::kPublishContract, "publish_contract"},
    {MessageType::kAttachEvidence, "attach_evidence"},
    {MessageType::kEvaluate, "evaluate"},
    {MessageType::kStatus, "status"},
    {MessageType::kDescribeContract, "describe_contract"},
    {MessageType::kInstallPolicy, "install_policy"},
    {MessageType::kRetireWorkload, "retire_workload"},
    {MessageType::kListWorkloads, "list_workloads"},
    {MessageType::kError, "error"},
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

#if defined(_WIN32)

SOCKET as_socket(std::uintptr_t handle) { return static_cast<SOCKET>(handle); }

#else

int as_socket(std::uintptr_t handle) { return static_cast<int>(handle); }

#endif

}  // namespace

std::string_view message_type_token(MessageType type) noexcept {
  for (const auto& entry : kMessageTokens) {
    if (entry.first == type) {
      return entry.second;
    }
  }
  return kMessageTokens.front().second;
}

std::optional<MessageType> parse_message_type(std::string_view token) noexcept {
  for (const auto& entry : kMessageTokens) {
    if (entry.second == token) {
      return entry.first;
    }
  }
  return std::nullopt;
}

bool encode_frame(MessageType type, std::uint64_t request_id, std::string_view body,
                  std::string& out, Code& code, std::string& message) {
  if (body.size() > kMaxFrameBytes - kHeaderBytes) {
    code = Code::kBodyTooLarge;
    message = "frame body of " + std::to_string(body.size()) + " bytes exceeds the bound";
    return false;
  }
  std::string header;
  header.reserve(kHeaderBytes);
  write_u32(header, kWireMagic);
  write_u16(header, kWireVersion);
  write_u16(header, static_cast<std::uint16_t>(type));
  write_u32(header, 0);
  write_u32(header, static_cast<std::uint32_t>(body.size()));
  write_u64(header, request_id);
  write_u32(header, crc32(std::string_view(header.data(), header.size())));
  out.append(header);
  out.append(body);
  return true;
}

bool decode_frame(std::string_view bytes, Frame& frame, std::size_t& consumed, Code& code,
                  std::string& message) {
  consumed = 0;
  if (bytes.size() < kHeaderBytes) {
    code = Code::kTruncatedFrame;
    message = "frame header is incomplete";
    return false;
  }
  const char* header = bytes.data();
  if (read_u32(header) != kWireMagic) {
    code = Code::kBadMagic;
    message = "frame magic does not match this protocol";
    return false;
  }
  const std::uint16_t version = read_u16(header + 4);
  if (version != kWireVersion) {
    code = Code::kBadVersion;
    message = "frame version " + std::to_string(version) + " is not supported";
    return false;
  }
  if (read_u32(header + 24) != crc32(std::string_view(header, 24))) {
    code = Code::kFrameCrcMismatch;
    message = "frame header integrity check failed";
    return false;
  }
  frame.header.version = version;
  frame.header.type = static_cast<MessageType>(read_u16(header + 6));
  frame.header.flags = read_u32(header + 8);
  frame.header.body_length = read_u32(header + 12);
  frame.header.request_id = read_u64(header + 16);

  if (frame.header.body_length > kMaxFrameBytes - kHeaderBytes) {
    code = Code::kFrameTooLarge;
    message = "frame declares " + std::to_string(frame.header.body_length) + " body bytes";
    return false;
  }
  const std::size_t total = kHeaderBytes + frame.header.body_length;
  if (bytes.size() < total) {
    code = Code::kTruncatedFrame;
    message = "frame body is incomplete";
    return false;
  }
  frame.body.assign(bytes.data() + kHeaderBytes, frame.header.body_length);
  consumed = total;
  return true;
}

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) { other.handle_ = kInvalidHandle; }

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = kInvalidHandle;
  }
  return *this;
}

Socket::~Socket() { close(); }

void Socket::close() noexcept {
  if (handle_ == kInvalidHandle) {
    return;
  }
#if defined(_WIN32)
  ::closesocket(as_socket(handle_));
#else
  ::close(as_socket(handle_));
#endif
  handle_ = kInvalidHandle;
}

bool start_transport(Code& code, std::string& message) {
#if defined(_WIN32)
  static bool started = false;
  static bool ok = false;
  if (!started) {
    WSADATA data{};
    ok = ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
    started = true;
  }
  if (!ok) {
    code = Code::kListenFailed;
    message = "Winsock could not be initialised";
    return false;
  }
#else
  (void)code;
  (void)message;
#endif
  return true;
}

void stop_transport() noexcept {
#if defined(_WIN32)
  ::WSACleanup();
#endif
}

bool listen_on(std::string_view host, std::uint16_t port, Socket& listener, Code& code,
               std::string& message) {
  if (!start_transport(code, message)) {
    return false;
  }
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  const std::string host_text(host);
  const std::string port_text = std::to_string(port);
  addrinfo* results = nullptr;
  if (::getaddrinfo(host_text.c_str(), port_text.c_str(), &hints, &results) != 0 || results == nullptr) {
    code = Code::kBindFailed;
    message = "cannot resolve the listen address";
    return false;
  }
  std::uintptr_t handle = static_cast<std::uintptr_t>(~0ull);
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
#if defined(_WIN32)
    SOCKET socket = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (socket == INVALID_SOCKET) {
      continue;
    }
    const char reuse = 1;
    ::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (::bind(socket, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) != 0 ||
        ::listen(socket, kListenBacklog) != 0) {
      ::closesocket(socket);
      continue;
    }
    handle = static_cast<std::uintptr_t>(socket);
#else
    const int socket = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (socket < 0) {
      continue;
    }
    const int reuse = 1;
    ::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (::bind(socket, candidate->ai_addr, candidate->ai_addrlen) != 0 || ::listen(socket, kListenBacklog) != 0) {
      ::close(socket);
      continue;
    }
    handle = static_cast<std::uintptr_t>(socket);
#endif
    break;
  }
  ::freeaddrinfo(results);
  if (handle == static_cast<std::uintptr_t>(~0ull)) {
    code = Code::kBindFailed;
    message = "no address could be bound";
    return false;
  }
  listener.close();
  listener = Socket(handle);
  return true;
}

std::uint16_t bound_port(const Socket& listener) {
  if (!listener.valid()) {
    return 0;
  }
  sockaddr_in address{};
#if defined(_WIN32)
  int length = sizeof(address);
  if (::getsockname(as_socket(listener.handle()), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return 0;
  }
#else
  socklen_t length = sizeof(address);
  if (::getsockname(as_socket(listener.handle()), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return 0;
  }
#endif
  return ::ntohs(address.sin_port);
}

bool connect_to(std::string_view host, std::uint16_t port, Socket& socket, Code& code,
                std::string& message) {
  if (!start_transport(code, message)) {
    return false;
  }
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  const std::string host_text(host);
  const std::string port_text = std::to_string(port);
  addrinfo* results = nullptr;
  if (::getaddrinfo(host_text.c_str(), port_text.c_str(), &hints, &results) != 0 || results == nullptr) {
    code = Code::kConnectFailed;
    message = "cannot resolve the coordinator address";
    return false;
  }
  std::uintptr_t handle = static_cast<std::uintptr_t>(~0ull);
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
#if defined(_WIN32)
    SOCKET created = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (created == INVALID_SOCKET) {
      continue;
    }
    if (::connect(created, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) != 0) {
      ::closesocket(created);
      continue;
    }
    const char nodelay = 1;
    ::setsockopt(created, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    handle = static_cast<std::uintptr_t>(created);
#else
    const int created = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (created < 0) {
      continue;
    }
    if (::connect(created, candidate->ai_addr, candidate->ai_addrlen) != 0) {
      ::close(created);
      continue;
    }
    const int nodelay = 1;
    ::setsockopt(created, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    handle = static_cast<std::uintptr_t>(created);
#endif
    break;
  }
  ::freeaddrinfo(results);
  if (handle == static_cast<std::uintptr_t>(~0ull)) {
    code = Code::kConnectFailed;
    message = "no address could be connected";
    return false;
  }
  socket.close();
  socket = Socket(handle);
  return true;
}

bool read_exact(const Socket& socket, std::span<std::uint8_t> buffer, Code& code,
                std::string& message) {
  std::size_t offset = 0;
  while (offset < buffer.size()) {
#if defined(_WIN32)
    const int received = ::recv(as_socket(socket.handle()),
                                reinterpret_cast<char*>(buffer.data() + offset),
                                static_cast<int>(buffer.size() - offset), 0);
#else
    const ssize_t received = ::recv(as_socket(socket.handle()), buffer.data() + offset,
                                    buffer.size() - offset, 0);
#endif
    if (received == 0) {
      code = Code::kSessionClosed;
      message = "peer closed the connection";
      return false;
    }
    if (received < 0) {
      code = Code::kIoFailed;
      message = "receive failed";
      return false;
    }
    offset += static_cast<std::size_t>(received);
  }
  return true;
}

bool write_all(const Socket& socket, std::string_view bytes, Code& code, std::string& message) {
  std::size_t offset = 0;
  while (offset < bytes.size()) {
#if defined(_WIN32)
    const int sent = ::send(as_socket(socket.handle()), bytes.data() + offset,
                            static_cast<int>(bytes.size() - offset), 0);
#else
    const ssize_t sent = ::send(as_socket(socket.handle()), bytes.data() + offset,
                                bytes.size() - offset, MSG_NOSIGNAL);
#endif
    if (sent <= 0) {
      code = Code::kIoFailed;
      message = "send failed";
      return false;
    }
    offset += static_cast<std::size_t>(sent);
  }
  return true;
}

bool wait_readable(const Socket& socket, std::uint64_t timeout_millis, Code& code,
                   std::string& message) {
  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(as_socket(socket.handle()), &read_set);
  timeval timeout{};
  timeout.tv_sec = static_cast<long>(timeout_millis / 1000);
  timeout.tv_usec = static_cast<long>((timeout_millis % 1000) * 1000);
#if defined(_WIN32)
  const int ready = ::select(0, &read_set, nullptr, nullptr, &timeout);
#else
  const int ready = ::select(as_socket(socket.handle()) + 1, &read_set, nullptr, nullptr, &timeout);
#endif
  if (ready == 0) {
    code = Code::kDeadlineExceeded;
    message = "no frame arrived within the bounded wait";
    return false;
  }
  if (ready < 0) {
    code = Code::kIoFailed;
    message = "select failed";
    return false;
  }
  return true;
}

bool accept_one(const Socket& listener, std::uint64_t timeout_millis, Socket& accepted, Code& code,
                std::string& message) {
  if (!wait_readable(listener, timeout_millis, code, message)) {
    return false;
  }
  sockaddr_in address{};
#if defined(_WIN32)
  int length = sizeof(address);
  SOCKET handle = ::accept(as_socket(listener.handle()), reinterpret_cast<sockaddr*>(&address), &length);
  if (handle == INVALID_SOCKET) {
    code = Code::kIoFailed;
    message = "accept failed";
    return false;
  }
#else
  socklen_t length = sizeof(address);
  const int handle = ::accept(as_socket(listener.handle()), reinterpret_cast<sockaddr*>(&address), &length);
  if (handle < 0) {
    code = Code::kIoFailed;
    message = "accept failed";
    return false;
  }
#endif
  accepted.close();
  accepted = Socket(static_cast<std::uintptr_t>(handle));
  return true;
}

bool read_frame(const Socket& socket, Frame& frame, Code& code, std::string& message) {
  std::array<std::uint8_t, kHeaderBytes> header{};
  if (!read_exact(socket, std::span<std::uint8_t>(header.data(), header.size()), code, message)) {
    return false;
  }
  const char* raw = reinterpret_cast<const char*>(header.data());
  if (read_u32(raw) != kWireMagic) {
    code = Code::kBadMagic;
    message = "frame magic does not match this protocol";
    return false;
  }
  const std::uint16_t version = read_u16(raw + 4);
  if (version != kWireVersion) {
    code = Code::kBadVersion;
    message = "frame version is not supported";
    return false;
  }
  if (read_u32(raw + 24) != crc32(std::string_view(raw, 24))) {
    code = Code::kFrameCrcMismatch;
    message = "frame header integrity check failed";
    return false;
  }
  const std::uint32_t body_length = read_u32(raw + 12);
  if (body_length > kMaxFrameBytes - kHeaderBytes) {
    // Refused before any body allocation.
    code = Code::kFrameTooLarge;
    message = "frame declares " + std::to_string(body_length) + " body bytes";
    return false;
  }
  frame.header.version = version;
  frame.header.type = static_cast<MessageType>(read_u16(raw + 6));
  frame.header.flags = read_u32(raw + 8);
  frame.header.body_length = body_length;
  frame.header.request_id = read_u64(raw + 16);
  frame.body.assign(body_length, '\0');
  if (body_length > 0) {
    if (!read_exact(socket,
                    std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(frame.body.data()),
                                            frame.body.size()),
                    code, message)) {
      return false;
    }
  }
  return true;
}

bool send_frame(const Socket& socket, MessageType type, std::uint64_t request_id,
                std::string_view body, Code& code, std::string& message) {
  std::string frame;
  frame.reserve(kHeaderBytes + body.size());
  if (!encode_frame(type, request_id, body, frame, code, message)) {
    return false;
  }
  return write_all(socket, frame, code, message);
}

bool set_non_blocking(const Socket& socket, bool enabled, Code& code, std::string& message) {
#if defined(_WIN32)
  u_long mode = enabled ? 1ul : 0ul;
  if (::ioctlsocket(as_socket(socket.handle()), FIONBIO, &mode) != 0) {
    code = Code::kIoFailed;
    message = "cannot change the socket blocking mode";
    return false;
  }
#else
  const int flags = ::fcntl(as_socket(socket.handle()), F_GETFL, 0);
  if (flags < 0) {
    code = Code::kIoFailed;
    message = "cannot read the socket flags";
    return false;
  }
  const int updated = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
  if (::fcntl(as_socket(socket.handle()), F_SETFL, updated) < 0) {
    code = Code::kIoFailed;
    message = "cannot change the socket blocking mode";
    return false;
  }
#endif
  return true;
}

}  // namespace wnc::wire
