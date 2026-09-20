// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Minimal deterministic test harness. It exists so that the build has no
// third party test dependency, and so that a failing expectation reports the
// file, the line, the expression, and the values that produced the failure.

#ifndef WNC_TEST_HPP
#define WNC_TEST_HPP

#include <chrono>
#include <cstdint>
#include <type_traits>
#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "wnc/error.hpp"

namespace wnc::test {

class Failure : public std::exception {
 public:
  explicit Failure(std::string message) : message_(std::move(message)) {}
  [[nodiscard]] const char* what() const noexcept override { return message_.c_str(); }

 private:
  std::string message_;
};

struct Context {
  std::string test_name;
  std::uint64_t seed = 0;
  bool seed_set = false;

  void set_seed(std::uint64_t value) {
    seed = value;
    seed_set = true;
  }
};

using Body = void (*)(Context&);

struct Case {
  std::string suite;
  std::string name;
  Body body;
};

class Registry {
 public:
  static Registry& instance() {
    static Registry registry;
    return registry;
  }

  void add(std::string_view suite, std::string_view name, Body body) {
    cases_.push_back(Case{std::string(suite), std::string(name), body});
  }

  [[nodiscard]] const std::vector<Case>& cases() const noexcept { return cases_; }

 private:
  std::vector<Case> cases_;
};

class Registrar {
 public:
  Registrar(std::string_view suite, std::string_view name, Body body) {
    Registry::instance().add(suite, name, body);
  }
};

// Renders a value for diagnostics.
std::string describe(const std::uint8_t* data, std::size_t size);
std::string escape(std::string_view text);

// Opens a file for binary append, read/write, or write. The C runtime's plain
// fopen is deprecated on MSVC in favour of fopen_s, and this boundary does not
// want a warning suppression or a non-portable call at every use site, so the
// portable wrapper lives here once.
inline std::FILE* open_file(const std::string& path, const char* mode, bool& ok) {
  std::FILE* file = nullptr;
#if defined(_MSC_VER)
  ok = ::fopen_s(&file, path.c_str(), mode) == 0 && file != nullptr;
#else
  file = std::fopen(path.c_str(), mode);
  ok = file != nullptr;
#endif
  return file;
}

}  // namespace wnc::test

// Marks a test body parameter as intentionally unused.
#define WNC_UNUSED(value) static_cast<void>(value)

#define WNC_TEST_IMPL_NAME2(suite, name, line) wnc_test_registrar_##suite##_##name##_##line
#define WNC_TEST_IMPL_NAME(suite, name, line) WNC_TEST_IMPL_NAME2(suite, name, line)

#define WNC_TEST(suite, name)                                                                      \
  static void wnc_test_body_##suite##_##name(::wnc::test::Context&);                               \
  static const ::wnc::test::Registrar WNC_TEST_IMPL_NAME(suite, name, __LINE__)(                   \
      #suite, #name, &wnc_test_body_##suite##_##name);                                             \
  static void wnc_test_body_##suite##_##name([[maybe_unused]] ::wnc::test::Context& wnc_ctx)

#define WNC_FAIL(message)                                                                          \
  do {                                                                                             \
    std::ostringstream wnc_os;                                                                     \
    wnc_os << "failure in " << __FILE__ << ":" << __LINE__ << ": " << message;                      \
    throw ::wnc::test::Failure(wnc_os.str());                                                       \
  } while (false)

#define WNC_CHECK(expr)                                                                            \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      std::ostringstream wnc_os;                                                                   \
      wnc_os << "check failed: " << #expr << " at " << __FILE__ << ":" << __LINE__;                 \
      throw ::wnc::test::Failure(wnc_os.str());                                                     \
    }                                                                                              \
  } while (false)

#define WNC_CHECK_MSG(expr, message)                                                               \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      std::ostringstream wnc_os;                                                                   \
      wnc_os << "check failed: " << #expr << " at " << __FILE__ << ":" << __LINE__ << " ("          \
             << message << ")";                                                                    \
      throw ::wnc::test::Failure(wnc_os.str());                                                     \
    }                                                                                              \
  } while (false)

#define WNC_CHECK_EQ(a, b)                                                                         \
  do {                                                                                             \
    const auto& wnc_left = (a);                                                                    \
    const auto& wnc_right = (b);                                                                   \
    if (!(wnc_left == wnc_right)) {                                                                \
      std::ostringstream wnc_os;                                                                   \
      wnc_os << "check failed: " << #a << " == " << #b << " at " << __FILE__ << ":" << __LINE__     \
             << " (left=" << ::wnc::test::render_value(wnc_left)                                   \
             << ", right=" << ::wnc::test::render_value(wnc_right) << ")";                         \
      throw ::wnc::test::Failure(wnc_os.str());                                                     \
    }                                                                                              \
  } while (false)

#define WNC_CHECK_NE(a, b)                                                                         \
  do {                                                                                             \
    if ((a) == (b)) {                                                                              \
      std::ostringstream wnc_os;                                                                   \
      wnc_os << "check failed: " << #a << " != " << #b << " at " << __FILE__ << ":" << __LINE__;    \
      throw ::wnc::test::Failure(wnc_os.str());                                                     \
    }                                                                                              \
  } while (false)

namespace wnc::test {

std::string describe_value(const std::string& value);
std::string describe_value(std::string_view value);
std::string describe_value(const char* value);
std::string describe_value(bool value);
std::string describe_value(int value);
std::string describe_value(unsigned value);
std::string describe_value(long value);
std::string describe_value(unsigned long value);
std::string describe_value(long long value);
std::string describe_value(unsigned long long value);
std::string describe_value(double value);

// Diagnostic codes render as their stable token so that a failing expectation
// reads as "json_duplicate_key" rather than as an integer.
std::string render_value(::wnc::Code code);

// Fallback for enum class values that have no dedicated renderer: they are shown
// as their underlying ordinal, which is enough to tell two verdicts apart in a
// failure message.
template <class T>
  requires(std::is_enum_v<T>)
std::string describe_value(T value) {
  return std::to_string(static_cast<long long>(static_cast<std::underlying_type_t<T>>(value)));
}

// A vector of strings is compared as an ordered list; the failure message shows
// the first differing element rather than the whole list.
inline std::string describe_value(const std::vector<std::string>& value) {
  return "vector<string> of " + std::to_string(value.size()) + " elements";
}

template <class T>
std::string render_value(const T& value) {
  return describe_value(value);
}

}  // namespace wnc::test

#endif  // WNC_TEST_HPP
