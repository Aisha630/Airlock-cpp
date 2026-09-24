// A minimal JSON value and writer for the analyzer's machine-readable report.
//
// Objects keep their keys in insertion order, the writer indents by two
// spaces, and non-ASCII text is escaped as \uXXXX, so the output is plain
// ASCII whatever bytes an SSID contained.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace airlock::wifi::json {

class Value;
using Array = std::vector<Value>;
using Object = std::vector<std::pair<std::string, Value>>;

class Value {
 public:
  Value() : data_(nullptr) {}
  Value(std::nullptr_t) : data_(nullptr) {}
  Value(bool b) : data_(b) {}
  template <typename T>
    requires(std::is_integral_v<T> && !std::is_same_v<T, bool>)
  Value(T i) : data_(static_cast<std::int64_t>(i)) {}
  Value(double d) : data_(d) {}
  Value(const char* s) : data_(std::string(s)) {}
  Value(std::string s) : data_(std::move(s)) {}
  Value(Array a) : data_(std::make_shared<Array>(std::move(a))) {}
  Value(Object o) : data_(std::make_shared<Object>(std::move(o))) {}

  template <typename T>
  static Value optional(const std::optional<T>& v) {
    return v ? Value(*v) : Value(nullptr);
  }

  // Serialise with two-space indentation and no trailing newline.
  std::string dump() const;

 private:
  void write(std::string& out, int depth) const;

  std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, std::shared_ptr<Array>,
               std::shared_ptr<Object>>
      data_;
};

// A JSON string literal, quotes included.
std::string quote(const std::string& text);

}  // namespace airlock::wifi::json
