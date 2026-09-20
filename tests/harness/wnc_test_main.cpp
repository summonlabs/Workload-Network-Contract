// Workload Network Contract 1.0.0
// Copyright 2026 Summon Software Labs.
//
// Test runner. Usage:  <binary> [suite-filter] [test-filter]
// Prints one line per test:  "PASS suite/name" or "FAIL suite/name: reason".
// Exits non-zero when any test fails. No timeout is applied here or by the
// build system: a test that hangs is a defect to diagnose, not to cut short.

#include "wnc_test.hpp"

#include <cstdlib>

namespace wnc::test {
namespace {

std::string hex_nibble(unsigned value) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.push_back(kDigits[value & 0x0Fu]);
  return out;
}

}  // namespace

std::string describe(const std::uint8_t* data, std::size_t size) {
  std::string out;
  out.reserve(size * 2);
  for (std::size_t i = 0; i < size; ++i) {
    out.push_back("0123456789abcdef"[data[i] >> 4]);
    out.push_back("0123456789abcdef"[data[i] & 0x0Fu]);
  }
  return out;
}

std::string escape(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char c : text) {
    if (c == '\n') {
      out.append("\\n");
    } else if (c == '\r') {
      out.append("\\r");
    } else if (c == '\t') {
      out.append("\\t");
    } else {
      out.push_back(c);
    }
  }
  return out;
}

std::string describe_value(const std::string& value) { return "\"" + escape(value) + "\""; }
std::string describe_value(std::string_view value) { return "\"" + escape(value) + "\""; }
std::string describe_value(const char* value) {
  return value == nullptr ? std::string("null") : describe_value(std::string_view(value));
}
std::string describe_value(bool value) { return value ? "true" : "false"; }
std::string describe_value(int value) { return std::to_string(value); }
std::string describe_value(unsigned value) { return std::to_string(value); }
std::string describe_value(long value) { return std::to_string(value); }
std::string describe_value(unsigned long value) { return std::to_string(value); }
std::string describe_value(long long value) { return std::to_string(value); }
std::string describe_value(unsigned long long value) { return std::to_string(value); }
std::string describe_value(double value) {
  char buffer[64];
  std::snprintf(buffer, sizeof(buffer), "%.17g", value);
  return std::string(buffer);
}
std::string render_value(::wnc::Code code) { return std::string(::wnc::code_token(code)); }

}  // namespace wnc::test

int main(int argc, char** argv) {
  const std::string suite_filter = argc > 1 ? argv[1] : std::string();
  const std::string test_filter = argc > 2 ? argv[2] : std::string();

  std::size_t passed = 0;
  std::size_t failed = 0;
  std::size_t skipped = 0;
  std::vector<std::string> failures;

  for (const ::wnc::test::Case& test_case : ::wnc::test::Registry::instance().cases()) {
    if (!suite_filter.empty() && test_case.suite != suite_filter) {
      ++skipped;
      continue;
    }
    if (!test_filter.empty() && test_case.name.find(test_filter) == std::string::npos) {
      ++skipped;
      continue;
    }
    wnc::test::Context context;
    context.test_name = test_case.suite + "/" + test_case.name;
    const auto started = std::chrono::steady_clock::now();
    try {
      test_case.body(context);
      const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                               std::chrono::steady_clock::now() - started)
                               .count();
      ++passed;
      std::cout << "PASS " << context.test_name << " (" << elapsed << " us)\n";
      std::cout.flush();
    } catch (const std::exception& error) {
      ++failed;
      const std::string reason = error.what();
      failures.push_back(context.test_name + ": " + reason);
      std::cout << "FAIL " << context.test_name << ": " << reason << "\n";
      std::cout.flush();
    } catch (...) {
      ++failed;
      failures.push_back(context.test_name + ": non standard exception");
      std::cout << "FAIL " << context.test_name << ": non standard exception\n";
      std::cout.flush();
    }
  }

  std::cout << "SUMMARY passed=" << passed << " failed=" << failed << " skipped=" << skipped << "\n";
  if (!failures.empty()) {
    std::cout << "FAILURES:\n";
    for (const std::string& failure : failures) {
      std::cout << "  " << failure << "\n";
    }
  }
  std::cout.flush();
  return failed == 0 ? 0 : 1;
}