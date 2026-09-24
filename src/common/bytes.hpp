// Byte-string helpers shared by both halves of the project.
//
// Everything on the wire is a sequence of octets, so one alias is used
// throughout: `Bytes` for owned buffers and `ByteView` for borrowed ones.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace airlock {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

inline Bytes to_bytes(std::string_view text) {
  return Bytes(text.begin(), text.end());
}

inline Bytes repeat(std::uint8_t value, std::size_t count) {
  return Bytes(count, value);
}

inline void append(Bytes& out, ByteView data) {
  out.insert(out.end(), data.begin(), data.end());
}

inline Bytes concat(std::initializer_list<ByteView> parts) {
  Bytes out;
  for (ByteView part : parts) append(out, part);
  return out;
}

inline Bytes slice(ByteView data, std::size_t start, std::size_t length) {
  if (start > data.size()) return {};
  length = std::min(length, data.size() - start);
  return Bytes(data.begin() + static_cast<std::ptrdiff_t>(start),
               data.begin() + static_cast<std::ptrdiff_t>(start + length));
}

inline std::string to_hex(ByteView data) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (std::uint8_t byte : data) {
    out.push_back(digits[byte >> 4]);
    out.push_back(digits[byte & 0x0f]);
  }
  return out;
}

inline Bytes from_hex(std::string_view hex) {
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  Bytes out;
  int high = -1;
  for (char c : hex) {
    if (c == ' ' || c == '\n' || c == '\t') continue;
    int value = nibble(c);
    if (value < 0) throw std::invalid_argument("invalid hex digit");
    if (high < 0) {
      high = value;
    } else {
      out.push_back(static_cast<std::uint8_t>(high << 4 | value));
      high = -1;
    }
  }
  if (high >= 0) throw std::invalid_argument("odd number of hex digits");
  return out;
}

// Big-endian ("network order") and little-endian integer codecs. 802.11
// fields are little-endian; EAPOL and the AKEX wire format are
// big-endian.
inline void put_be16(Bytes& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}
inline void put_be32(Bytes& out, std::uint32_t v) {
  for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(v >> shift));
}
inline void put_be64(Bytes& out, std::uint64_t v) {
  for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(v >> shift));
}
inline void put_le16(Bytes& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v));
  out.push_back(static_cast<std::uint8_t>(v >> 8));
}
inline void put_le32(Bytes& out, std::uint32_t v) {
  for (int shift = 0; shift <= 24; shift += 8) out.push_back(static_cast<std::uint8_t>(v >> shift));
}

// Readers assume the caller has already checked that the bytes exist.
inline std::uint16_t get_be16(ByteView d, std::size_t at) {
  return static_cast<std::uint16_t>(d[at] << 8 | d[at + 1]);
}
inline std::uint32_t get_be32(ByteView d, std::size_t at) {
  return static_cast<std::uint32_t>(d[at]) << 24 | static_cast<std::uint32_t>(d[at + 1]) << 16 |
         static_cast<std::uint32_t>(d[at + 2]) << 8 | d[at + 3];
}
inline std::uint64_t get_be64(ByteView d, std::size_t at) {
  return static_cast<std::uint64_t>(get_be32(d, at)) << 32 | get_be32(d, at + 4);
}
inline std::uint16_t get_le16(ByteView d, std::size_t at) {
  return static_cast<std::uint16_t>(d[at] | d[at + 1] << 8);
}
inline std::uint32_t get_le32(ByteView d, std::size_t at) {
  return d[at] | static_cast<std::uint32_t>(d[at + 1]) << 8 |
         static_cast<std::uint32_t>(d[at + 2]) << 16 | static_cast<std::uint32_t>(d[at + 3]) << 24;
}

}  // namespace airlock
