#include "wifi/json.hpp"

#include <format>

#include "wifi/text.hpp"

namespace airlock::wifi::json {
namespace {

void indent(std::string& out, int depth) {
  out += '\n';
  out.append(static_cast<std::size_t>(depth) * 2, ' ');
}

// Decode one UTF-8 code point. Input comes from decode_utf8_lossy, so it is
// well-formed; anything else is passed through byte by byte.
char32_t next_code_point(const std::string& s, std::size_t& at) {
  const auto lead = static_cast<unsigned char>(s[at]);
  int length = lead < 0x80 ? 1 : lead < 0xE0 ? 2 : lead < 0xF0 ? 3 : 4;
  if (at + static_cast<std::size_t>(length) > s.size()) length = 1;
  char32_t cp = length == 1 ? lead : lead & (0xFF >> (length + 1));
  for (int i = 1; i < length; ++i) {
    cp = cp << 6 | (static_cast<unsigned char>(s[at + static_cast<std::size_t>(i)]) & 0x3F);
  }
  at += static_cast<std::size_t>(length);
  return cp;
}

}  // namespace

std::string quote(const std::string& text) {
  std::string out = "\"";
  std::size_t at = 0;
  while (at < text.size()) {
    const char32_t cp = next_code_point(text, at);
    switch (cp) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      default:
        if (cp < 0x20 || (cp >= 0x7f && cp < 0x10000)) {
          out += std::format("\\u{:04x}", static_cast<unsigned>(cp));
        } else if (cp >= 0x10000) {
          const char32_t v = cp - 0x10000;
          out += std::format("\\u{:04x}\\u{:04x}", static_cast<unsigned>(0xD800 + (v >> 10)),
                             static_cast<unsigned>(0xDC00 + (v & 0x3FF)));
        } else {
          out += static_cast<char>(cp);
        }
    }
  }
  return out + "\"";
}

std::string Value::dump() const {
  std::string out;
  write(out, 0);
  return out;
}

void Value::write(std::string& out, int depth) const {
  if (std::holds_alternative<std::nullptr_t>(data_)) {
    out += "null";
  } else if (const bool* b = std::get_if<bool>(&data_)) {
    out += *b ? "true" : "false";
  } else if (const std::int64_t* i = std::get_if<std::int64_t>(&data_)) {
    out += std::to_string(*i);
  } else if (const double* d = std::get_if<double>(&data_)) {
    out += shortest_float(*d);
  } else if (const std::string* s = std::get_if<std::string>(&data_)) {
    out += quote(*s);
  } else if (const auto* a = std::get_if<std::shared_ptr<Array>>(&data_)) {
    if ((*a)->empty()) {
      out += "[]";
      return;
    }
    out += '[';
    for (std::size_t n = 0; n < (*a)->size(); ++n) {
      if (n) out += ',';
      indent(out, depth + 1);
      (**a)[n].write(out, depth + 1);
    }
    indent(out, depth);
    out += ']';
  } else if (const auto* o = std::get_if<std::shared_ptr<Object>>(&data_)) {
    if ((*o)->empty()) {
      out += "{}";
      return;
    }
    out += '{';
    for (std::size_t n = 0; n < (*o)->size(); ++n) {
      if (n) out += ',';
      indent(out, depth + 1);
      out += quote((**o)[n].first);
      out += ": ";
      (**o)[n].second.write(out, depth + 1);
    }
    indent(out, depth);
    out += '}';
  }
}

}  // namespace airlock::wifi::json
