// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.

#include "wnc/json.hpp"

#include <array>
#include <charconv>
#include <cmath>
#include <limits>

#include "wnc/config.hpp"

namespace wnc {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";
// Encodings of the two characters that always require a backslash escape.
constexpr std::string_view kQuotedQuote = "\\\"";
constexpr std::string_view kQuotedBackslash = "\\\\";

constexpr bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }
constexpr bool is_ws(char c) noexcept { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

constexpr int hex_value(char c) noexcept {
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
}

// Decodes one UTF-8 sequence starting at index i. Returns the number of bytes
// consumed (1..4) or 0 when the sequence is invalid. Rejects overlong forms,
// surrogates, and values above U+10FFFF, so accepted input is well formed.
std::size_t decode_utf8(std::string_view text, std::size_t i, std::uint32_t& codepoint) noexcept {
  const unsigned char b0 = static_cast<unsigned char>(text[i]);
  if (b0 < 0x80u) {
    codepoint = b0;
    return 1;
  }
  std::size_t length = 0;
  std::uint32_t value = 0;
  std::uint32_t minimum = 0;
  if ((b0 & 0xE0u) == 0xC0u) {
    length = 2;
    value = b0 & 0x1Fu;
    minimum = 0x80u;
  } else if ((b0 & 0xF0u) == 0xE0u) {
    length = 3;
    value = b0 & 0x0Fu;
    minimum = 0x800u;
  } else if ((b0 & 0xF8u) == 0xF0u) {
    length = 4;
    value = b0 & 0x07u;
    minimum = 0x10000u;
  } else {
    return 0;
  }
  if (i + length > text.size()) {
    return 0;
  }
  for (std::size_t k = 1; k < length; ++k) {
    const unsigned char bk = static_cast<unsigned char>(text[i + k]);
    if ((bk & 0xC0u) != 0x80u) {
      return 0;
    }
    value = (value << 6) | (bk & 0x3Fu);
  }
  if (value < minimum) {
    return 0;
  }
  if (value >= 0xD800u && value <= 0xDFFFu) {
    return 0;
  }
  if (value > 0x10FFFFu) {
    return 0;
  }
  codepoint = value;
  return length;
}

void append_utf8(std::string& out, std::uint32_t codepoint) {
  if (codepoint < 0x80u) {
    out.push_back(static_cast<char>(codepoint));
  } else if (codepoint < 0x800u) {
    out.push_back(static_cast<char>(0xC0u | (codepoint >> 6)));
    out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
  } else if (codepoint < 0x10000u) {
    out.push_back(static_cast<char>(0xE0u | (codepoint >> 12)));
    out.push_back(static_cast<char>(0x80u | ((codepoint >> 6) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
  } else {
    out.push_back(static_cast<char>(0xF0u | (codepoint >> 18)));
    out.push_back(static_cast<char>(0x80u | ((codepoint >> 12) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | ((codepoint >> 6) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
  }
}

// Returns the short escape letter for a control character, or 0 when the
// character is emitted verbatim.
constexpr char escape_for(unsigned char c) noexcept {
  switch (c) {
    case 0x08u:
      return 'b';
    case 0x09u:
      return 't';
    case 0x0Au:
      return 'n';
    case 0x0Cu:
      return 'f';
    case 0x0Du:
      return 'r';
    default:
      return 0;
  }
}

void write_escaped_string(std::string& out, std::string_view value) {
  out.push_back('"');
  for (const char raw : value) {
    const unsigned char c = static_cast<unsigned char>(raw);
    if (c == static_cast<unsigned char>('"')) {
      out.append(kQuotedQuote);
    } else if (c == static_cast<unsigned char>('\\')) {
      out.append(kQuotedBackslash);
    } else if (c < 0x20u) {
      const char letter = escape_for(c);
      if (letter != 0) {
        out.push_back('\\');
        out.push_back(letter);
      } else {
        out.append("\\u00");
        out.push_back(kHexDigits[(c >> 4) & 0x0Fu]);
        out.push_back(kHexDigits[c & 0x0Fu]);
      }
    } else {
      out.push_back(raw);
    }
  }
  out.push_back('"');
}

std::string format_int(std::int64_t value) {
  std::array<char, 24> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  return std::string(buffer.data(), static_cast<std::size_t>(result.ptr - buffer.data()));
}

// Attempts to rewrite scientific notation as ordinary decimal notation. Returns
// nullopt when the exponent is outside the range where expansion is exact.
std::optional<std::string> expand_exponent(std::string_view digits, int exponent) {
  if (exponent > 40 || exponent < -400) {
    return std::nullopt;
  }
  std::string integer_part;
  std::string fraction_part;
  bool seen_point = false;
  for (const char c : digits) {
    if (c == '.') {
      seen_point = true;
      continue;
    }
    if (seen_point) {
      fraction_part.push_back(c);
    } else {
      integer_part.push_back(c);
    }
  }
  std::string combined = integer_part + fraction_part;
  const int point = static_cast<int>(integer_part.size()) + exponent;

  std::string out;
  out.reserve(combined.size() + 8);
  if (point <= 0) {
    out.append("0.");
    out.append(static_cast<std::size_t>(-point), '0');
    out.append(combined);
  } else if (static_cast<std::size_t>(point) >= combined.size()) {
    out.append(combined);
    out.append(static_cast<std::size_t>(point) - combined.size(), '0');
    out.append(".0");
  } else {
    out.append(combined.substr(0, static_cast<std::size_t>(point)));
    out.push_back('.');
    out.append(combined.substr(static_cast<std::size_t>(point)));
  }

  // Strip redundant trailing zeros in the fraction, keeping one fraction digit
  // so the value stays visibly a real number.
  const std::size_t point_index = out.find('.');
  if (point_index != std::string::npos) {
    std::size_t last = out.size();
    while (last > point_index + 2 && out[last - 1] == '0') {
      --last;
    }
    out.resize(last);
  }
  return out;
}

void dump_impl(const Json& value, std::string& out, std::size_t budget) {
  if (out.size() > budget) {
    return;
  }
  switch (value.kind()) {
    case Json::Kind::kNull:
      out.append("null");
      return;
    case Json::Kind::kBool:
      out.append(value.as_bool() ? "true" : "false");
      return;
    case Json::Kind::kInt:
      out.append(format_int(value.as_int()));
      return;
    case Json::Kind::kReal: {
      const std::optional<std::string> text = format_canonical_real(value.as_real());
      if (text.has_value()) {
        out.append(*text);
      }
      return;
    }
    case Json::Kind::kString:
      write_escaped_string(out, value.as_string());
      return;
    case Json::Kind::kArray: {
      out.push_back('[');
      const JsonArray& items = value.array();
      for (std::size_t i = 0; i < items.size(); ++i) {
        if (i != 0) {
          out.push_back(',');
        }
        dump_impl(items[i], out, budget);
        if (out.size() > budget) {
          return;
        }
      }
      out.push_back(']');
      return;
    }
    case Json::Kind::kObject: {
      out.push_back('{');
      const JsonObject& members = value.object();
      bool first = true;
      for (const auto& entry : members) {
        if (!first) {
          out.push_back(',');
        }
        first = false;
        write_escaped_string(out, entry.first);
        out.push_back(':');
        dump_impl(entry.second, out, budget);
        if (out.size() > budget) {
          return;
        }
      }
      out.push_back('}');
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct JsonError {
  Code code = Code::kJsonSyntax;
  std::size_t offset = 0;
  std::string message;
};

class Parser {
 public:
  Parser(std::string_view text, const JsonDecodeOptions& options)
      : text_(text),
        options_(options),
        max_depth_(options.max_depth == 0 ? 1 : options.max_depth) {}

  bool parse_document(Json& out) {
    skip_ws();
    if (pos_ >= text_.size()) {
      return fail(Code::kJsonSyntax, "document is empty");
    }
    if (!parse_value(out, 0)) {
      return false;
    }
    skip_ws();
    if (pos_ != text_.size()) {
      return fail(Code::kTrailingGarbage, "bytes remain after the top level value");
    }
    if (options_.require_object && !out.is_object()) {
      return fail(Code::kJsonNotAnObject, "top level value must be an object");
    }
    return true;
  }

  [[nodiscard]] const std::optional<JsonError>& error() const noexcept { return error_; }

 private:
  void skip_ws() noexcept {
    while (pos_ < text_.size() && is_ws(text_[pos_])) {
      ++pos_;
    }
  }

  bool fail(Code code, std::string message) {
    if (!error_.has_value()) {
      error_ = JsonError{code, pos_, std::move(message)};
    }
    return false;
  }

  bool literal(std::string_view token) {
    if (text_.size() - pos_ < token.size()) {
      return fail(Code::kJsonInvalidLiteral, "literal is truncated");
    }
    if (text_.compare(pos_, token.size(), token) != 0) {
      return fail(Code::kJsonInvalidLiteral, "literal is malformed");
    }
    pos_ += token.size();
    return true;
  }

  bool parse_value(Json& out, std::size_t depth) {
    if (pos_ >= text_.size()) {
      return fail(Code::kJsonSyntax, "value expected but input ended");
    }
    if (depth > max_depth_) {
      return fail(Code::kJsonDepthExceeded, "nesting depth exceeds the configured bound");
    }
    switch (text_[pos_]) {
      case '{':
        return parse_object(out, depth);
      case '[':
        return parse_array(out, depth);
      case '"': {
        std::string value;
        if (!parse_string(value)) {
          return false;
        }
        out = Json(std::move(value));
        return true;
      }
      case 't':
        if (!literal("true")) {
          return false;
        }
        out = Json(true);
        return true;
      case 'f':
        if (!literal("false")) {
          return false;
        }
        out = Json(false);
        return true;
      case 'n':
        if (!literal("null")) {
          return false;
        }
        out = Json(nullptr);
        return true;
      default:
        if (text_[pos_] == '-' || is_digit(text_[pos_])) {
          return parse_number(out);
        }
        return fail(Code::kJsonSyntax, "unexpected character where a value was expected");
    }
  }

  bool parse_number(Json& out) {
    const std::size_t start = pos_;
    if (pos_ < text_.size() && text_[pos_] == '-') {
      ++pos_;
    }
    if (pos_ >= text_.size() || !is_digit(text_[pos_])) {
      return fail(Code::kJsonSyntax, "number has no integer digits");
    }
    if (text_[pos_] == '0') {
      ++pos_;
      if (pos_ < text_.size() && is_digit(text_[pos_])) {
        return fail(Code::kJsonSyntax, "number has a leading zero");
      }
    } else {
      while (pos_ < text_.size() && is_digit(text_[pos_])) {
        ++pos_;
      }
    }

    bool is_real = false;
    if (pos_ < text_.size() && text_[pos_] == '.') {
      is_real = true;
      ++pos_;
      if (pos_ >= text_.size() || !is_digit(text_[pos_])) {
        return fail(Code::kJsonSyntax, "fraction has no digits");
      }
      while (pos_ < text_.size() && is_digit(text_[pos_])) {
        ++pos_;
      }
    }
    if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
      is_real = true;
      ++pos_;
      if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) {
        ++pos_;
      }
      if (pos_ >= text_.size() || !is_digit(text_[pos_])) {
        return fail(Code::kJsonSyntax, "exponent has no digits");
      }
      while (pos_ < text_.size() && is_digit(text_[pos_])) {
        ++pos_;
      }
    }

    const std::string_view token = text_.substr(start, pos_ - start);
    if (token.size() > 64) {
      return fail(Code::kJsonNumberOutOfRange, "number literal is longer than 64 characters");
    }

    if (!is_real) {
      bool negative = false;
      std::size_t index = 0;
      if (token[0] == '-') {
        negative = true;
        index = 1;
      }
      std::uint64_t magnitude = 0;
      for (; index < token.size(); ++index) {
        const std::uint64_t digit = static_cast<std::uint64_t>(token[index] - '0');
        if (magnitude > (std::numeric_limits<std::uint64_t>::max() - digit) / 10u) {
          return fail(Code::kJsonNumberOutOfRange, "integer magnitude is not representable");
        }
        magnitude = magnitude * 10u + digit;
      }
      constexpr std::uint64_t kInt64Max =
          static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
      if (negative) {
        if (magnitude > kInt64Max + 1u) {
          return fail(Code::kJsonNumberOutOfRange, "integer is below the representable minimum");
        }
        if (magnitude == kInt64Max + 1u) {
          out = Json(std::numeric_limits<std::int64_t>::min());
          return true;
        }
        out = Json(-static_cast<std::int64_t>(magnitude));
        return true;
      }
      if (magnitude > kInt64Max) {
        return fail(Code::kJsonNumberOutOfRange, "integer exceeds the representable maximum");
      }
      out = Json(static_cast<std::int64_t>(magnitude));
      return true;
    }

    double value = 0.0;
    const auto result = std::from_chars(token.data(), token.data() + token.size(), value);
    if (result.ec != std::errc{} || result.ptr != token.data() + token.size()) {
      return fail(Code::kJsonNumberOutOfRange, "real number is not representable as a double");
    }
    if (!std::isfinite(value)) {
      return fail(Code::kJsonNumberOutOfRange, "real number is not finite");
    }
    out = Json(value);
    return true;
  }

  bool parse_hex4(std::uint32_t& out) {
    if (text_.size() - pos_ < 4) {
      return fail(Code::kJsonSyntax, "unicode escape is truncated");
    }
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
      const int digit = hex_value(text_[pos_ + static_cast<std::size_t>(i)]);
      if (digit < 0) {
        return fail(Code::kJsonSyntax, "unicode escape contains a non hex digit");
      }
      value = (value << 4) | static_cast<std::uint32_t>(digit);
    }
    pos_ += 4;
    out = value;
    return true;
  }

  bool parse_string(std::string& out) {
    if (pos_ >= text_.size() || text_[pos_] != '"') {
      return fail(Code::kJsonSyntax, "string must start with a quote");
    }
    ++pos_;
    out.clear();
    while (true) {
      if (pos_ >= text_.size()) {
        return fail(Code::kJsonSyntax, "string is not terminated");
      }
      const unsigned char c = static_cast<unsigned char>(text_[pos_]);
      if (c == static_cast<unsigned char>('"')) {
        ++pos_;
        return true;
      }
      if (c < 0x20u) {
        return fail(Code::kJsonSyntax, "string contains a raw control character");
      }
      if (c == static_cast<unsigned char>('\\')) {
        ++pos_;
        if (pos_ >= text_.size()) {
          return fail(Code::kJsonSyntax, "escape sequence is truncated");
        }
        const char escape = text_[pos_];
        switch (escape) {
          case '"':
            out.push_back('"');
            ++pos_;
            break;
          case '\\':
            out.push_back('\\');
            ++pos_;
            break;
          case '/':
            out.push_back('/');
            ++pos_;
            break;
          case 'b':
            out.push_back('\b');
            ++pos_;
            break;
          case 'f':
            out.push_back('\f');
            ++pos_;
            break;
          case 'n':
            out.push_back('\n');
            ++pos_;
            break;
          case 'r':
            out.push_back('\r');
            ++pos_;
            break;
          case 't':
            out.push_back('\t');
            ++pos_;
            break;
          case 'u': {
            ++pos_;
            std::uint32_t first = 0;
            if (!parse_hex4(first)) {
              return false;
            }
            std::uint32_t codepoint = first;
            if (first >= 0xD800u && first <= 0xDBFFu) {
              if (text_.size() - pos_ < 6 || text_[pos_] != '\\' || text_[pos_ + 1] != 'u') {
                return fail(Code::kJsonSyntax, "high surrogate is not followed by a low surrogate");
              }
              pos_ += 2;
              std::uint32_t second = 0;
              if (!parse_hex4(second)) {
                return false;
              }
              if (second < 0xDC00u || second > 0xDFFFu) {
                return fail(Code::kJsonSyntax, "low surrogate is out of range");
              }
              codepoint = 0x10000u + ((first - 0xD800u) << 10) + (second - 0xDC00u);
            } else if (first >= 0xDC00u && first <= 0xDFFFu) {
              return fail(Code::kJsonSyntax, "lone low surrogate in escape sequence");
            }
            append_utf8(out, codepoint);
            break;
          }
          default:
            return fail(Code::kJsonSyntax, "unknown escape sequence");
        }
      } else {
        std::uint32_t codepoint = 0;
        const std::size_t length = decode_utf8(text_, pos_, codepoint);
        if (length == 0) {
          return fail(Code::kJsonInvalidUtf8, "string contains an invalid UTF-8 sequence");
        }
        out.append(text_.substr(pos_, length));
        pos_ += length;
      }
      if (out.size() > options_.max_string_bytes) {
        return fail(Code::kJsonStringTooLong, "string exceeds the configured byte bound");
      }
    }
  }

  bool parse_object(Json& out, std::size_t depth) {
    ++pos_;  // consume '{'
    JsonObject members;
    skip_ws();
    if (pos_ < text_.size() && text_[pos_] == '}') {
      ++pos_;
      out = Json(std::move(members));
      return true;
    }
    while (true) {
      skip_ws();
      std::string key;
      if (!parse_string(key)) {
        return false;
      }
      skip_ws();
      if (pos_ >= text_.size() || text_[pos_] != ':') {
        return fail(Code::kJsonSyntax, "object member is missing its colon");
      }
      ++pos_;
      skip_ws();
      Json value;
      if (!parse_value(value, depth + 1)) {
        return false;
      }
      if (members.find(key) != members.end()) {
        return fail(Code::kJsonDuplicateKey, "object repeats key '" + key + "'");
      }
      members.emplace(std::move(key), std::move(value));
      skip_ws();
      if (pos_ >= text_.size()) {
        return fail(Code::kJsonSyntax, "object is not terminated");
      }
      if (text_[pos_] == ',') {
        ++pos_;
        continue;
      }
      if (text_[pos_] == '}') {
        ++pos_;
        out = Json(std::move(members));
        return true;
      }
      return fail(Code::kJsonSyntax, "expected ',' or '}' in object");
    }
  }

  bool parse_array(Json& out, std::size_t depth) {
    ++pos_;  // consume '['
    JsonArray items;
    skip_ws();
    if (pos_ < text_.size() && text_[pos_] == ']') {
      ++pos_;
      out = Json(std::move(items));
      return true;
    }
    while (true) {
      skip_ws();
      Json value;
      if (!parse_value(value, depth + 1)) {
        return false;
      }
      items.push_back(std::move(value));
      skip_ws();
      if (pos_ >= text_.size()) {
        return fail(Code::kJsonSyntax, "array is not terminated");
      }
      if (text_[pos_] == ',') {
        ++pos_;
        continue;
      }
      if (text_[pos_] == ']') {
        ++pos_;
        out = Json(std::move(items));
        return true;
      }
      return fail(Code::kJsonSyntax, "expected ',' or ']' in array");
    }
  }

  std::string_view text_;
  JsonDecodeOptions options_;
  std::size_t pos_ = 0;
  std::size_t max_depth_;
  std::optional<JsonError> error_;
};

}  // namespace

// ---------------------------------------------------------------------------
// Json
// ---------------------------------------------------------------------------

Json::Json(double value) noexcept : kind_(Kind::kReal), real_(value == 0.0 ? 0.0 : value) {}

Json::Json(const JsonArray& value) : kind_(Kind::kArray) {
  array_ = std::make_unique<JsonArray>(value);
}

Json::Json(JsonArray&& value) noexcept : kind_(Kind::kArray) {
  array_ = std::make_unique<JsonArray>(std::move(value));
}

Json::Json(const JsonObject& value) : kind_(Kind::kObject) {
  object_ = std::make_unique<JsonObject>(value);
}

Json::Json(JsonObject&& value) noexcept : kind_(Kind::kObject) {
  object_ = std::make_unique<JsonObject>(std::move(value));
}

Json::Json(const Json& other) { copy_from(other); }

Json& Json::operator=(const Json& other) {
  if (this != &other) {
    destroy();
    copy_from(other);
  }
  return *this;
}

Json::Json(Json&& other) noexcept
    : kind_(other.kind_),
      bool_(other.bool_),
      real_(other.real_),
      int_(other.int_),
      string_(std::move(other.string_)),
      array_(std::move(other.array_)),
      object_(std::move(other.object_)) {
  other.kind_ = Kind::kNull;
  other.bool_ = false;
  other.real_ = 0.0;
  other.int_ = 0;
}

Json& Json::operator=(Json&& other) noexcept {
  if (this != &other) {
    destroy();
    kind_ = other.kind_;
    bool_ = other.bool_;
    real_ = other.real_;
    int_ = other.int_;
    string_ = std::move(other.string_);
    array_ = std::move(other.array_);
    object_ = std::move(other.object_);
    other.kind_ = Kind::kNull;
    other.bool_ = false;
    other.real_ = 0.0;
    other.int_ = 0;
  }
  return *this;
}

Json::~Json() { destroy(); }

void Json::destroy() noexcept {
  kind_ = Kind::kNull;
  bool_ = false;
  real_ = 0.0;
  int_ = 0;
  string_.clear();
  array_.reset();
  object_.reset();
}

void Json::copy_from(const Json& other) {
  kind_ = other.kind_;
  bool_ = other.bool_;
  real_ = other.real_;
  int_ = other.int_;
  string_ = other.string_;
  if (other.array_) {
    array_ = std::make_unique<JsonArray>(*other.array_);
  }
  if (other.object_) {
    object_ = std::make_unique<JsonObject>(*other.object_);
  }
}

double Json::as_real() const noexcept {
  if (kind_ == Kind::kInt) {
    return static_cast<double>(int_);
  }
  return real_;
}

std::size_t Json::size() const noexcept {
  if (kind_ == Kind::kArray && array_) {
    return array_->size();
  }
  if (kind_ == Kind::kObject && object_) {
    return object_->size();
  }
  if (kind_ == Kind::kString) {
    return string_.size();
  }
  return 0;
}

const Json* Json::at(std::size_t index) const {
  if (kind_ != Kind::kArray || !array_ || index >= array_->size()) {
    return nullptr;
  }
  return &(*array_)[index];
}

const Json* Json::find(std::string_view key) const {
  if (kind_ != Kind::kObject || !object_) {
    return nullptr;
  }
  const auto it = object_->find(key);
  if (it == object_->end()) {
    return nullptr;
  }
  return &it->second;
}

const JsonArray& Json::array() const {
  static const JsonArray kEmpty;
  if (kind_ != Kind::kArray || !array_) {
    return kEmpty;
  }
  return *array_;
}

const JsonObject& Json::object() const {
  static const JsonObject kEmpty;
  if (kind_ != Kind::kObject || !object_) {
    return kEmpty;
  }
  return *object_;
}

void Json::set(std::string key, Json value) {
  if (kind_ != Kind::kObject || !object_) {
    destroy();
    kind_ = Kind::kObject;
    object_ = std::make_unique<JsonObject>();
  }
  (*object_)[std::move(key)] = std::move(value);
}

void Json::push(Json value) {
  if (kind_ != Kind::kArray || !array_) {
    destroy();
    kind_ = Kind::kArray;
    array_ = std::make_unique<JsonArray>();
  }
  array_->push_back(std::move(value));
}

std::string Json::dump() const {
  std::string out;
  dump_impl(*this, out, kMaxDocumentBytes * 2);
  return out;
}

std::string Json::dump_line() const {
  std::string out = dump();
  out.push_back('\n');
  return out;
}

bool operator==(const Json& a, const Json& b) noexcept {
  if (a.kind_ != b.kind_) {
    return false;
  }
  switch (a.kind_) {
    case Json::Kind::kNull:
      return true;
    case Json::Kind::kBool:
      return a.bool_ == b.bool_;
    case Json::Kind::kInt:
      return a.int_ == b.int_;
    case Json::Kind::kReal:
      return a.real_ == b.real_;
    case Json::Kind::kString:
      return a.string_ == b.string_;
    case Json::Kind::kArray: {
      const JsonArray& left = a.array();
      const JsonArray& right = b.array();
      if (left.size() != right.size()) {
        return false;
      }
      for (std::size_t i = 0; i < left.size(); ++i) {
        if (!(left[i] == right[i])) {
          return false;
        }
      }
      return true;
    }
    case Json::Kind::kObject: {
      const JsonObject& left = a.object();
      const JsonObject& right = b.object();
      if (left.size() != right.size()) {
        return false;
      }
      auto li = left.begin();
      auto ri = right.begin();
      for (; li != left.end() && ri != right.end(); ++li, ++ri) {
        if (li->first != ri->first || !(li->second == ri->second)) {
          return false;
        }
      }
      return true;
    }
  }
  return false;
}

std::optional<std::string> format_canonical_real(double value) {
  if (!std::isfinite(value)) {
    return std::nullopt;
  }
  if (value == 0.0) {
    return std::string("0.0");
  }

  // Shortest round-tripping form. Every supported standard library implements
  // shortest round-trip formatting for the general format.
  std::array<char, 64> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  if (result.ec != std::errc{}) {
    return std::nullopt;
  }
  const std::string_view text(buffer.data(), static_cast<std::size_t>(result.ptr - buffer.data()));

  bool negative = false;
  std::size_t start = 0;
  if (!text.empty() && text[0] == '-') {
    negative = true;
    start = 1;
  }
  const std::size_t exponent_pos = text.find_first_of("eE", start);
  if (exponent_pos == std::string_view::npos) {
    std::string plain(text.substr(start));
    // A value that arrived as a real stays a real: "2.0" must not be emitted as
    // "2", because the canonical form has to preserve the decoded type.
    if (plain.find('.') == std::string::npos) {
      plain.append(".0");
    }
    return plain;
  }

  const std::string_view mantissa = text.substr(start, exponent_pos - start);
  int exponent = 0;
  {
    std::size_t index = exponent_pos + 1;
    bool exponent_negative = false;
    if (index < text.size() && (text[index] == '+' || text[index] == '-')) {
      exponent_negative = text[index] == '-';
      ++index;
    }
    if (index >= text.size()) {
      return std::nullopt;
    }
    for (; index < text.size(); ++index) {
      if (!is_digit(text[index])) {
        return std::nullopt;
      }
      if (exponent > 100000) {
        return std::nullopt;
      }
      exponent = exponent * 10 + (text[index] - '0');
    }
    if (exponent_negative) {
      exponent = -exponent;
    }
  }

  const std::optional<std::string> expanded = expand_exponent(mantissa, exponent);
  if (!expanded.has_value()) {
    return std::nullopt;
  }
  if (negative) {
    return std::string("-") + *expanded;
  }
  return expanded;
}

// ---------------------------------------------------------------------------
// Decoder entry points
// ---------------------------------------------------------------------------

JsonDecodeResult json_decode(std::string_view text, const JsonDecodeOptions& options) {
  JsonDecodeResult result;
  if (text.size() > options.max_bytes) {
    result.code = Code::kDocumentTooLarge;
    result.offset = 0;
    result.message = "document of " + std::to_string(text.size()) + " bytes exceeds the " +
                     std::to_string(options.max_bytes) + " byte bound";
    return result;
  }
  Parser parser(text, options);
  Json value;
  if (!parser.parse_document(value)) {
    const std::optional<JsonError>& error = parser.error();
    if (error.has_value()) {
      result.code = error->code;
      result.offset = error->offset;
      result.message = error->message;
    } else {
      result.code = Code::kJsonSyntax;
      result.message = "document was rejected";
    }
    return result;
  }
  result.ok = true;
  result.value = std::move(value);
  return result;
}

JsonDecodeResult json_decode(std::span<const std::uint8_t> bytes, const JsonDecodeOptions& options) {
  const std::string_view text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  return json_decode(text, options);
}

bool JsonStreamingDecoder::feed(std::span<const std::uint8_t> bytes) {
  if (buffer_.size() + bytes.size() > options_.max_bytes) {
    return false;
  }
  buffer_.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  return true;
}

bool JsonStreamingDecoder::feed(std::string_view text) {
  if (buffer_.size() + text.size() > options_.max_bytes) {
    return false;
  }
  buffer_.append(text);
  return true;
}

JsonDecodeResult JsonStreamingDecoder::finish() const { return json_decode(buffer_, options_); }

// ---------------------------------------------------------------------------
// Field readers
// ---------------------------------------------------------------------------

const Json* FieldReader::optional(std::string_view key) const { return object.find(key); }

bool FieldReader::has(std::string_view key) const { return object.find(key) != nullptr; }

namespace {

std::string qualify(std::string_view path, std::string_view key) {
  std::string out(path);
  if (!out.empty()) {
    out.push_back('.');
  }
  out.append(key);
  return out;
}

std::string missing_field_message(std::string_view path, std::string_view key) {
  std::string out = qualify(path, key);
  out.append(" is required");
  return out;
}

std::string wrong_type_message(std::string_view path, std::string_view key,
                               std::string_view expected) {
  std::string out = qualify(path, key);
  out.append(" must be ");
  out.append(expected);
  return out;
}

}  // namespace

bool FieldReader::require_object(std::string_view key, const Json*& out, Code& code,
                                 std::string& message) const {
  const Json* value = object.find(key);
  if (value == nullptr) {
    code = Code::kJsonMissingField;
    message = missing_field_message(path, key);
    return false;
  }
  if (!value->is_object()) {
    code = Code::kJsonWrongType;
    message = wrong_type_message(path, key, "an object");
    return false;
  }
  out = value;
  return true;
}

bool FieldReader::require_array(std::string_view key, const Json*& out, Code& code,
                                std::string& message) const {
  const Json* value = object.find(key);
  if (value == nullptr) {
    code = Code::kJsonMissingField;
    message = missing_field_message(path, key);
    return false;
  }
  if (!value->is_array()) {
    code = Code::kJsonWrongType;
    message = wrong_type_message(path, key, "an array");
    return false;
  }
  out = value;
  return true;
}

bool FieldReader::require_string(std::string_view key, std::string_view& out, Code& code,
                                 std::string& message) const {
  const Json* value = object.find(key);
  if (value == nullptr) {
    code = Code::kJsonMissingField;
    message = missing_field_message(path, key);
    return false;
  }
  if (!value->is_string()) {
    code = Code::kJsonWrongType;
    message = wrong_type_message(path, key, "a string");
    return false;
  }
  out = value->as_string();
  return true;
}

bool FieldReader::require_bool(std::string_view key, bool& out, Code& code,
                               std::string& message) const {
  const Json* value = object.find(key);
  if (value == nullptr) {
    code = Code::kJsonMissingField;
    message = missing_field_message(path, key);
    return false;
  }
  if (!value->is_bool()) {
    code = Code::kJsonWrongType;
    message = wrong_type_message(path, key, "a boolean");
    return false;
  }
  out = value->as_bool();
  return true;
}

bool FieldReader::require_int(std::string_view key, std::int64_t& out, Code& code,
                              std::string& message) const {
  const Json* value = object.find(key);
  if (value == nullptr) {
    code = Code::kJsonMissingField;
    message = missing_field_message(path, key);
    return false;
  }
  if (!value->is_int()) {
    code = Code::kJsonWrongType;
    message = wrong_type_message(path, key, "an integer");
    return false;
  }
  out = value->as_int();
  return true;
}

bool FieldReader::require_uint(std::string_view key, std::uint64_t& out, Code& code,
                               std::string& message) const {
  std::int64_t raw = 0;
  if (!require_int(key, raw, code, message)) {
    return false;
  }
  if (raw < 0) {
    code = Code::kValueOutOfRange;
    message = wrong_type_message(path, key, "a non negative integer");
    return false;
  }
  out = static_cast<std::uint64_t>(raw);
  return true;
}

bool FieldReader::require_real(std::string_view key, double& out, Code& code,
                               std::string& message) const {
  const Json* value = object.find(key);
  if (value == nullptr) {
    code = Code::kJsonMissingField;
    message = missing_field_message(path, key);
    return false;
  }
  if (!value->is_number()) {
    code = Code::kJsonWrongType;
    message = wrong_type_message(path, key, "a number");
    return false;
  }
  out = value->as_real();
  return true;
}

}  // namespace wnc
