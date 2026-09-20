// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Real loopback TCP protocol surface. Every case here uses a real listening
// socket on 127.0.0.1 and a real client connection: framing, integrity,
// reordering, duplicate request identifiers, truncated frames, and bounded
// waits. No transport behaviour is simulated.

#include "wnc_test.hpp"

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "wnc/hash.hpp"
#include "wnc/wire.hpp"

using namespace wnc;

namespace {

struct ListenerPair {
  wire::Socket listener;
  std::uint16_t port = 0;
};

bool start_listener(ListenerPair& pair, Code& code, std::string& message) {
  if (!wire::listen_on("127.0.0.1", 0, pair.listener, code, message)) {
    return false;
  }
  pair.port = wire::bound_port(pair.listener);
  return pair.port != 0;
}

std::string frame_for(wire::MessageType type, std::uint64_t request_id, const std::string& body) {
  std::string frame;
  Code code = Code::kOk;
  std::string message;
  if (!wire::encode_frame(type, request_id, body, frame, code, message)) {
    return {};
  }
  return frame;
}

}  // namespace

WNC_TEST(protocol, framed_round_trip_over_loopback_tcp) {
  ListenerPair pair;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(start_listener(pair, code, message), message);

  std::atomic<bool> server_ok{false};
  std::thread server([&] {
    wire::Socket accepted;
    Code accept_code = Code::kOk;
    std::string accept_message;
    if (!wire::accept_one(pair.listener, 5000, accepted, accept_code, accept_message)) {
      return;
    }
    wire::Frame request;
    if (!wire::read_frame(accepted, request, accept_code, accept_message)) {
      return;
    }
    if (!wire::send_frame(accepted, wire::MessageType::kHelloReply, request.header.request_id,
                          "{\"echo\":true}", accept_code, accept_message)) {
      return;
    }
    server_ok = true;
  });

  wire::Socket client;
  WNC_CHECK_MSG(wire::connect_to("127.0.0.1", pair.port, client, code, message), message);
  const std::string frame = frame_for(wire::MessageType::kHello, 1234, "{\"schema\":\"hello\"}");
  WNC_CHECK(!frame.empty());
  WNC_CHECK(wire::write_all(client, frame, code, message));
  wire::Frame reply;
  WNC_CHECK_MSG(wire::read_frame(client, reply, code, message), message);
  WNC_CHECK_EQ(reply.header.type, wire::MessageType::kHelloReply);
  WNC_CHECK_EQ(reply.header.request_id, std::uint64_t(1234));
  WNC_CHECK_EQ(reply.body, std::string("{\"echo\":true}"));
  server.join();
  WNC_CHECK(server_ok.load());
  client.close();
  pair.listener.close();
}

WNC_TEST(protocol, many_frames_in_one_write_are_read_individually) {
  ListenerPair pair;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(start_listener(pair, code, message), message);

  constexpr int kFrames = 64;
  std::atomic<int> received{0};
  std::thread server([&] {
    wire::Socket accepted;
    Code accept_code = Code::kOk;
    std::string accept_message;
    if (!wire::accept_one(pair.listener, 5000, accepted, accept_code, accept_message)) {
      return;
    }
    for (int i = 0; i < kFrames; ++i) {
      wire::Frame request;
      if (!wire::read_frame(accepted, request, accept_code, accept_message)) {
        return;
      }
      if (request.header.request_id != static_cast<std::uint64_t>(i)) {
        return;
      }
      ++received;
    }
  });

  wire::Socket client;
  WNC_CHECK_MSG(wire::connect_to("127.0.0.1", pair.port, client, code, message), message);
  std::string batch;
  for (int i = 0; i < kFrames; ++i) {
    batch += frame_for(wire::MessageType::kStatus, static_cast<std::uint64_t>(i), "{}");
  }
  WNC_CHECK(wire::write_all(client, batch, code, message));
  server.join();
  WNC_CHECK_EQ(received.load(), kFrames);
  client.close();
  pair.listener.close();
}

WNC_TEST(protocol, one_frame_split_across_writes_is_reassembled) {
  ListenerPair pair;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(start_listener(pair, code, message), message);

  std::atomic<bool> good{false};
  std::thread server([&] {
    wire::Socket accepted;
    Code accept_code = Code::kOk;
    std::string accept_message;
    if (!wire::accept_one(pair.listener, 5000, accepted, accept_code, accept_message)) {
      return;
    }
    wire::Frame request;
    if (!wire::read_frame(accepted, request, accept_code, accept_message)) {
      return;
    }
    good = request.header.request_id == 77 && request.body == "{\"split\":true}";
  });

  wire::Socket client;
  WNC_CHECK_MSG(wire::connect_to("127.0.0.1", pair.port, client, code, message), message);
  const std::string frame = frame_for(wire::MessageType::kStatus, 77, "{\"split\":true}");
  // Send the frame one byte at a time; the reader must reassemble it.
  for (const char byte : frame) {
    WNC_CHECK(wire::write_all(client, std::string_view(&byte, 1), code, message));
  }
  server.join();
  WNC_CHECK(good.load());
  client.close();
  pair.listener.close();
}

WNC_TEST(protocol, tampered_frame_is_rejected_by_the_reader) {
  ListenerPair pair;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(start_listener(pair, code, message), message);

  std::atomic<Code> observed{Code::kOk};
  std::thread server([&] {
    wire::Socket accepted;
    Code accept_code = Code::kOk;
    std::string accept_message;
    if (!wire::accept_one(pair.listener, 5000, accepted, accept_code, accept_message)) {
      return;
    }
    wire::Frame request;
    Code read_code = Code::kOk;
    std::string read_message;
    if (!wire::read_frame(accepted, request, read_code, read_message)) {
      observed = read_code;
    }
  });

  wire::Socket client;
  WNC_CHECK_MSG(wire::connect_to("127.0.0.1", pair.port, client, code, message), message);
  std::string frame = frame_for(wire::MessageType::kStatus, 5, "{\"v\":1}");
  frame[6] = static_cast<char>(frame[6] ^ 0x01);  // body length low byte
  WNC_CHECK(wire::write_all(client, frame, code, message));
  server.join();
  WNC_CHECK_EQ(observed.load(), Code::kFrameCrcMismatch);
  client.close();
  pair.listener.close();
}

WNC_TEST(protocol, duplicate_request_identifiers_are_distinguishable_by_the_caller) {
  ListenerPair pair;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(start_listener(pair, code, message), message);

  std::atomic<int> seen{0};
  std::thread server([&] {
    wire::Socket accepted;
    Code accept_code = Code::kOk;
    std::string accept_message;
    if (!wire::accept_one(pair.listener, 5000, accepted, accept_code, accept_message)) {
      return;
    }
    for (int i = 0; i < 2; ++i) {
      wire::Frame request;
      if (!wire::read_frame(accepted, request, accept_code, accept_message)) {
        return;
      }
      // The transport carries the identifier verbatim; it is the caller's job to
      // treat a repeated identifier as a repeated request, so the reader must
      // not silently drop it.
      if (request.header.request_id == 9) {
        ++seen;
      }
    }
  });

  wire::Socket client;
  WNC_CHECK_MSG(wire::connect_to("127.0.0.1", pair.port, client, code, message), message);
  WNC_CHECK(wire::write_all(client, frame_for(wire::MessageType::kStatus, 9, "{\"first\":1}"), code,
                            message));
  WNC_CHECK(wire::write_all(client, frame_for(wire::MessageType::kStatus, 9, "{\"second\":1}"), code,
                            message));
  server.join();
  WNC_CHECK_EQ(seen.load(), 2);
  client.close();
  pair.listener.close();
}

WNC_TEST(protocol, oversized_declared_length_is_refused_before_allocation) {
  ListenerPair pair;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(start_listener(pair, code, message), message);

  std::atomic<Code> observed{Code::kOk};
  std::thread server([&] {
    wire::Socket accepted;
    Code accept_code = Code::kOk;
    std::string accept_message;
    if (!wire::accept_one(pair.listener, 5000, accepted, accept_code, accept_message)) {
      return;
    }
    wire::Frame request;
    Code read_code = Code::kOk;
    std::string read_message;
    if (!wire::read_frame(accepted, request, read_code, read_message)) {
      observed = read_code;
    }
  });

  wire::Socket client;
  WNC_CHECK_MSG(wire::connect_to("127.0.0.1", pair.port, client, code, message), message);
  std::string frame = frame_for(wire::MessageType::kStatus, 1, "");
  const std::uint32_t huge = 0xFFFFFFF0u;
  for (int i = 0; i < 4; ++i) {
    frame[12 + i] = static_cast<char>((huge >> (8 * i)) & 0xFFu);
  }
  const std::uint32_t crc = crc32(std::string_view(frame.data(), 24));
  for (int i = 0; i < 4; ++i) {
    frame[24 + i] = static_cast<char>((crc >> (8 * i)) & 0xFFu);
  }
  WNC_CHECK(wire::write_all(client, frame, code, message));
  server.join();
  WNC_CHECK(observed.load() == Code::kFrameTooLarge || observed.load() == Code::kBodyTooLarge);
  client.close();
  pair.listener.close();
}

WNC_TEST(protocol, bounded_wait_expires_without_a_frame) {
  ListenerPair pair;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(start_listener(pair, code, message), message);

  wire::Socket client;
  WNC_CHECK_MSG(wire::connect_to("127.0.0.1", pair.port, client, code, message), message);
  wire::Socket accepted;
  WNC_CHECK(wire::accept_one(pair.listener, 5000, accepted, code, message));

  Code wait_code = Code::kOk;
  std::string wait_message;
  WNC_CHECK(!wire::wait_readable(accepted, 150, wait_code, wait_message));
  WNC_CHECK_EQ(wait_code, Code::kDeadlineExceeded);

  // Closing the peer makes the session observable as closed rather than hanging.
  client.close();
  wire::Frame frame;
  Code read_code = Code::kOk;
  std::string read_message;
  WNC_CHECK(!wire::read_frame(accepted, frame, read_code, read_message));
  WNC_CHECK(read_code == Code::kSessionClosed || read_code == Code::kIoFailed);
  accepted.close();
  pair.listener.close();
}

WNC_TEST(protocol, reordering_and_interleaving_across_sessions_is_isolated) {
  ListenerPair pair;
  Code code = Code::kOk;
  std::string message;
  WNC_CHECK_MSG(start_listener(pair, code, message), message);

  std::atomic<int> matched{0};
  std::thread server([&] {
    wire::Socket first;
    wire::Socket second;
    Code accept_code = Code::kOk;
    std::string accept_message;
    if (!wire::accept_one(pair.listener, 5000, first, accept_code, accept_message)) {
      return;
    }
    if (!wire::accept_one(pair.listener, 5000, second, accept_code, accept_message)) {
      return;
    }
    wire::Frame a;
    wire::Frame b;
    if (!wire::read_frame(first, a, accept_code, accept_message)) {
      return;
    }
    if (!wire::read_frame(second, b, accept_code, accept_message)) {
      return;
    }
    if (a.header.request_id == 1 && a.body == "{\"session\":\"one\"}") {
      ++matched;
    }
    if (b.header.request_id == 2 && b.body == "{\"session\":\"two\"}") {
      ++matched;
    }
  });

  wire::Socket one;
  wire::Socket two;
  WNC_CHECK(wire::connect_to("127.0.0.1", pair.port, one, code, message));
  WNC_CHECK(wire::connect_to("127.0.0.1", pair.port, two, code, message));
  // Interleave the two sessions: the reader must never mix their bytes.
  const std::string first_frame = frame_for(wire::MessageType::kStatus, 1, "{\"session\":\"one\"}");
  const std::string second_frame = frame_for(wire::MessageType::kStatus, 2, "{\"session\":\"two\"}");
  const std::size_t half = first_frame.size() / 2;
  WNC_CHECK(wire::write_all(one, first_frame.substr(0, half), code, message));
  WNC_CHECK(wire::write_all(two, second_frame, code, message));
  WNC_CHECK(wire::write_all(one, first_frame.substr(half), code, message));
  server.join();
  WNC_CHECK_EQ(matched.load(), 2);
  one.close();
  two.close();
  pair.listener.close();
}
