#include "wifi/text.hpp"

#include <charconv>
#include <cstdlib>
#include <format>
#include <string_view>
#include <system_error>

namespace airlock::wifi {
namespace {

constexpr const char* REPLACEMENT = "\xEF\xBF\xBD";  // U+FFFD in UTF-8

// Length of the well-formed UTF-8 sequence starting at `at`, or, for an
// ill-formed one, the negated length of its maximal subpart (at least 1).
// Follows Table 3-7 of the Unicode standard.
int sequence_length(ByteView d, std::size_t at) {
  const std::uint8_t lead = d[at];
  if (lead < 0x80) return 1;
  int length = 0;
  std::uint8_t low = 0x80, high = 0xBF;
  if (lead >= 0xC2 && lead <= 0xDF) {
    length = 2;
  } else if (lead >= 0xE0 && lead <= 0xEF) {
    length = 3;
    if (lead == 0xE0) low = 0xA0;
    if (lead == 0xED) high = 0x9F;
  } else if (lead >= 0xF0 && lead <= 0xF4) {
    length = 4;
    if (lead == 0xF0) low = 0x90;
    if (lead == 0xF4) high = 0x8F;
  } else {
    return -1;
  }
  for (int i = 1; i < length; ++i) {
    const std::size_t pos = at + static_cast<std::size_t>(i);
    if (pos >= d.size()) return -i;
    const std::uint8_t c = d[pos];
    const std::uint8_t lo = i == 1 ? low : 0x80;
    const std::uint8_t hi = i == 1 ? high : 0xBF;
    if (c < lo || c > hi) return -i;
  }
  return length;
}

std::string escape_repr(std::string_view text) {
  const bool has_single = text.find('\'') != std::string_view::npos;
  const bool has_double = text.find('"') != std::string_view::npos;
  const char quote = has_single && !has_double ? '"' : '\'';
  std::string out(1, quote);
  for (std::size_t at = 0; at < text.size(); ++at) {
    const char ch = text[at];
    const auto c = static_cast<unsigned char>(ch);
    if (ch == '\\' || ch == quote) {
      out += '\\';
      out += ch;
    } else if (ch == '\t') {
      out += "\\t";
    } else if (ch == '\n') {
      out += "\\n";
    } else if (ch == '\r') {
      out += "\\r";
    } else if (c < 0x20 || c == 0x7f) {
      out += std::format("\\x{:02x}", c);
    } else if (c == 0xC2 && at + 1 < text.size() &&
               ((static_cast<unsigned char>(text[at + 1]) >= 0x80 &&
                 static_cast<unsigned char>(text[at + 1]) <= 0x9F) ||
                static_cast<unsigned char>(text[at + 1]) == 0xAD)) {
      // C1 controls and the soft hyphen are not printable either.
      out += std::format("\\x{:02x}", static_cast<unsigned char>(text[++at]));
    } else {
      out += ch;
    }
  }
  out += quote;
  return out;
}

}  // namespace

std::string decode_utf8_lossy(ByteView raw) {
  std::string out;
  out.reserve(raw.size());
  std::size_t at = 0;
  while (at < raw.size()) {
    const int length = sequence_length(raw, at);
    if (length > 0) {
      out.append(reinterpret_cast<const char*>(raw.data() + at), static_cast<std::size_t>(length));
      at += static_cast<std::size_t>(length);
    } else {
      out += REPLACEMENT;
      at += static_cast<std::size_t>(-length);
    }
  }
  return out;
}

std::size_t display_width(const std::string& text) {
  std::size_t count = 0;
  for (char c : text) {
    if ((static_cast<unsigned char>(c) & 0xC0) != 0x80) ++count;  // skip continuation bytes
  }
  return count;
}

std::string or_none(const std::optional<std::string>& value) {
  return value ? *value : "None";
}

std::string or_none(const std::optional<int>& value) {
  return value ? std::to_string(*value) : "None";
}

std::string quoted_repr(const std::optional<std::string>& value) {
  return value ? escape_repr(*value) : "None";
}

std::string int_list(const std::vector<int>& values) {
  std::string out = "[";
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i) out += ", ";
    out += std::to_string(values[i]);
  }
  return out + "]";
}

std::string join(const std::vector<std::string>& parts, const std::string& separator) {
  std::string out;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i) out += separator;
    out += parts[i];
  }
  return out;
}

std::string shortest_float(double value) {
  // Shortest round-trip digits in scientific form, then laid out as fixed
  // notation when the exponent is in [-4, 16), scientific otherwise.
  char buffer[64];
  auto result = std::to_chars(buffer, buffer + sizeof buffer, value, std::chars_format::scientific);
  std::string sci(buffer, result.ptr);
  const std::size_t e = sci.find('e');
  std::string mantissa = sci.substr(0, e);
  const int exponent = std::atoi(sci.c_str() + e + 1);
  std::string sign;
  if (!mantissa.empty() && mantissa[0] == '-') {
    sign = "-";
    mantissa.erase(0, 1);
  }
  std::string digits;
  for (char c : mantissa) {
    if (c != '.') digits += c;
  }

  if (exponent < -4 || exponent >= 16) {
    std::string out = sign + digits.substr(0, 1);
    if (digits.size() > 1) out += "." + digits.substr(1);
    return out + std::format("e{}{:02}", exponent < 0 ? "-" : "+", std::abs(exponent));
  }
  std::string out;
  if (exponent < 0) {
    out = "0." + std::string(static_cast<std::size_t>(-exponent - 1), '0') + digits;
  } else {
    const auto point = static_cast<std::size_t>(exponent + 1);
    if (digits.size() <= point) {
      out = digits + std::string(point - digits.size(), '0') + ".0";
    } else {
      out = digits.substr(0, point) + "." + digits.substr(point);
    }
  }
  return sign + out;
}

double round_to(double value, int digits) {
  // std::format rounds the exact binary value correctly (half-to-even on
  // ties), and parsing the result back gives the nearest double.
  const std::string text = std::format("{:.{}f}", value, digits);
  double out = 0;
  std::from_chars(text.data(), text.data() + text.size(), out);
  return out;
}

}  // namespace airlock::wifi
