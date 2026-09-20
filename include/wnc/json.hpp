// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// A bounded, canonical JSON subset used for every document this runtime writes
// or reads: contracts, evidence, policies, snapshots, journal payloads, and
// transport bodies.
//
// Canonical form (the bytes that a digest covers):
//   * object members are ordered by ascending UTF-8 byte order of the key;
//   * no insignificant whitespace is emitted;
//   * strings are escaped only where JSON requires it, and all other UTF-8
//     bytes are emitted verbatim;
//   * integers are emitted in shortest decimal form, and integers that arrive
//     through a decoder are stored as integers, never as reals;
//   * reals are emitted in the shortest form that round trips through double,
//     expanded to ordinary decimal notation;
//   * -0.0 canonicalises to 0.0 and non-finite values are rejected;
//   * the top level value is always an object for documents this boundary owns.
//
// The decoder is a strict, bounded, single pass parser: duplicate keys, invalid
// UTF-8, trailing bytes, over-deep nesting, over-long strings, and unrepresentable
// numbers are all rejected with a deterministic code.

#ifndef WNC_JSON_HPP
#define WNC_JSON_HPP

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "wnc/error.hpp"

namespace wnc {

class Json;

using JsonArray = std::vector<Json>;
// Ordered by key so that iteration order equals canonical order.
using JsonObject = std::map<std::string, Json, std::less<>>;

class Json {
 public:
  enum class Kind : std::uint8_t { kNull = 0, kBool = 1, kInt = 2, kReal = 3, kString = 4, kArray = 5, kObject = 6 };

  Json() noexcept = default;
  Json(std::nullptr_t) noexcept {}
  Json(bool value) noexcept : kind_(Kind::kBool), bool_(value) {}
  Json(int value) noexcept : kind_(Kind::kInt), int_(value) {}
  Json(long value) noexcept : kind_(Kind::kInt), int_(value) {}
  Json(long long value) noexcept : kind_(Kind::kInt), int_(value) {}
  Json(unsigned value) noexcept : kind_(Kind::kInt), int_(value) {}
  Json(unsigned long value) noexcept : kind_(Kind::kInt), int_(value) {}
  Json(unsigned long long value) noexcept : kind_(Kind::kInt), int_(value) {}
  Json(double value) noexcept;
  Json(const char* value) : kind_(Kind::kString), string_(value) {}
  Json(std::string value) : kind_(Kind::kString), string_(std::move(value)) {}
  Json(std::string_view value) : kind_(Kind::kString), string_(value) {}
  Json(const JsonArray& value);
  Json(JsonArray&& value) noexcept;
  Json(const JsonObject& value);
  Json(JsonObject&& value) noexcept;

  Json(const Json& other);
  Json& operator=(const Json& other);
  Json(Json&& other) noexcept;
  Json& operator=(Json&& other) noexcept;
  ~Json();

  [[nodiscard]] Kind kind() const noexcept { return kind_; }
  [[nodiscard]] bool is_null() const noexcept { return kind_ == Kind::kNull; }
  [[nodiscard]] bool is_bool() const noexcept { return kind_ == Kind::kBool; }
  [[nodiscard]] bool is_int() const noexcept { return kind_ == Kind::kInt; }
  [[nodiscard]] bool is_real() const noexcept { return kind_ == Kind::kReal; }
  [[nodiscard]] bool is_number() const noexcept { return kind_ == Kind::kInt || kind_ == Kind::kReal; }
  [[nodiscard]] bool is_string() const noexcept { return kind_ == Kind::kString; }
  [[nodiscard]] bool is_array() const noexcept { return kind_ == Kind::kArray; }
  [[nodiscard]] bool is_object() const noexcept { return kind_ == Kind::kObject; }

  [[nodiscard]] bool as_bool() const noexcept { return bool_; }
  [[nodiscard]] std::int64_t as_int() const noexcept { return int_; }
  [[nodiscard]] double as_real() const noexcept;
  [[nodiscard]] const std::string& as_string() const noexcept { return string_; }

  [[nodiscard]] std::size_t size() const noexcept;
  [[nodiscard]] bool empty() const noexcept { return size() == 0; }

  // Array access. Returns nullptr when the index or kind does not match.
  [[nodiscard]] const Json* at(std::size_t index) const;
  // Object access. Returns nullptr when the key is absent.
  [[nodiscard]] const Json* find(std::string_view key) const;

  [[nodiscard]] const JsonArray& array() const;
  [[nodiscard]] const JsonObject& object() const;

  void set(std::string key, Json value);
  void push(Json value);

  // Canonical serialization. Objects are already stored in canonical key order.
  [[nodiscard]] std::string dump() const;

  // Canonical serialization with a stable trailing newline, for file output.
  [[nodiscard]] std::string dump_line() const;

  friend bool operator==(const Json& a, const Json& b) noexcept;
  friend bool operator!=(const Json& a, const Json& b) noexcept { return !(a == b); }

 private:
  void destroy() noexcept;
  void copy_from(const Json& other);

  Kind kind_ = Kind::kNull;
  bool bool_ = false;
  double real_ = 0.0;
  std::int64_t int_ = 0;
  std::string string_;
  std::unique_ptr<JsonArray> array_;
  std::unique_ptr<JsonObject> object_;
};

// ---------------------------------------------------------------------------
// Canonical number formatting
// ---------------------------------------------------------------------------

// Formats a double in the canonical form described above. Returns nullopt for
// NaN and infinities, which have no JSON representation.
std::optional<std::string> format_canonical_real(double value);

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

struct JsonDecodeOptions {
  std::size_t max_bytes = 512 * 1024;
  std::size_t max_depth = 32;
  std::size_t max_string_bytes = 4096;
  bool require_object = false;
  bool allow_trailing_whitespace = true;
};

struct JsonDecodeResult {
  bool ok = false;
  Json value;
  Code code = Code::kOk;
  std::size_t offset = 0;
  std::string message;
};

// Strict bounded parse of a complete document.
JsonDecodeResult json_decode(std::string_view text, const JsonDecodeOptions& options = {});
JsonDecodeResult json_decode(std::span<const std::uint8_t> bytes, const JsonDecodeOptions& options = {});

// Incremental decoder for transport bodies. Input is fed in chunks; the result
// is only complete when the whole body has been supplied. Bounded by max_bytes.
class JsonStreamingDecoder {
 public:
  explicit JsonStreamingDecoder(JsonDecodeOptions options = {}) : options_(options) {}

  // Appends bytes. Returns false when the accumulated size exceeds the bound.
  bool feed(std::span<const std::uint8_t> bytes);
  bool feed(std::string_view text);

  [[nodiscard]] std::size_t bytes_received() const noexcept { return buffer_.size(); }

  JsonDecodeResult finish() const;

 private:
  JsonDecodeOptions options_;
  std::string buffer_;
};

// ---------------------------------------------------------------------------
// Field readers: deterministic type and range checks with stable codes
// ---------------------------------------------------------------------------

struct FieldReader {
  const Json& object;
  std::string_view path;

  [[nodiscard]] bool has(std::string_view key) const;
  [[nodiscard]] const Json* optional(std::string_view key) const;

  bool require_object(std::string_view key, const Json*& out, Code& code, std::string& message) const;
  bool require_array(std::string_view key, const Json*& out, Code& code, std::string& message) const;
  bool require_string(std::string_view key, std::string_view& out, Code& code,
                      std::string& message) const;
  bool require_bool(std::string_view key, bool& out, Code& code, std::string& message) const;
  bool require_int(std::string_view key, std::int64_t& out, Code& code, std::string& message) const;
  bool require_uint(std::string_view key, std::uint64_t& out, Code& code,
                    std::string& message) const;
  bool require_real(std::string_view key, double& out, Code& code, std::string& message) const;
};

}  // namespace wnc

#endif  // WNC_JSON_HPP
