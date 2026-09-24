#include "wifi/build.hpp"

#include <stdexcept>

namespace airlock::wifi::build {
namespace {

// Radiotap "present" bits: Channel (3) and dBm Antenna Signal (5).
constexpr std::uint32_t PRESENT_CHANNEL = 1u << 3;
constexpr std::uint32_t PRESENT_DBM_SIGNAL = 1u << 5;

bool has_addr2(int type, int subtype) {
  if (type != 1 && type != 3) return true;
  switch (subtype) {
    case 4: case 5: case 6: case 8: case 9: case 10: case 11: case 14: case 15:
      return true;
    default:
      return false;
  }
}

void put_mac(Bytes& out, std::string_view text) {
  if (text.empty()) {
    out.insert(out.end(), 6, 0);
  } else {
    append(out, mac(text));
  }
}

}  // namespace

Bytes mac(std::string_view text) {
  std::string hex;
  for (char c : text) {
    if (c != ':') hex.push_back(c);
  }
  Bytes out = from_hex(hex);
  if (out.size() != 6) throw std::invalid_argument("a MAC address has six octets");
  return out;
}

Bytes radiotap(std::uint16_t frequency_mhz, std::uint16_t channel_flags, std::int8_t signal_dbm) {
  Bytes out = {0, 0};  // version, padding
  put_le16(out, 13);   // header length
  put_le32(out, PRESENT_CHANNEL | PRESENT_DBM_SIGNAL);
  put_le16(out, frequency_mhz);  // offset 8, already 2-byte aligned
  put_le16(out, channel_flags);
  out.push_back(static_cast<std::uint8_t>(signal_dbm));
  return out;
}

Bytes radiotap_empty() {
  Bytes out = {0, 0};
  put_le16(out, 8);
  put_le32(out, 0);
  return out;
}

Bytes dot11(int type, int subtype, std::uint8_t flags, std::string_view addr1,
            std::string_view addr2, std::string_view addr3) {
  Bytes out;
  out.push_back(static_cast<std::uint8_t>((subtype & 0x0f) << 4 | (type & 0x03) << 2));
  out.push_back(flags);
  put_le16(out, 0);  // duration / ID
  put_mac(out, addr1);
  if (has_addr2(type, subtype)) put_mac(out, addr2);
  if (type == 0 || type == 2) {
    put_mac(out, addr3);
    put_le16(out, 0);  // sequence control
  }
  return out;
}

Bytes element(std::uint8_t id, ByteView body) {
  if (body.size() > 255) throw std::invalid_argument("an element body is at most 255 bytes");
  Bytes out = {id, static_cast<std::uint8_t>(body.size())};
  append(out, body);
  return out;
}

Bytes beacon_body(std::uint16_t interval, std::uint16_t capability) {
  Bytes out(8, 0);  // timestamp
  put_le16(out, interval);
  put_le16(out, capability);
  return out;
}

Bytes assoc_request_body(std::uint16_t capability, std::uint16_t listen_interval) {
  Bytes out;
  put_le16(out, capability);
  put_le16(out, listen_interval);
  return out;
}

Bytes assoc_response_body(std::uint16_t capability, std::uint16_t status, std::uint16_t aid) {
  Bytes out;
  put_le16(out, capability);
  put_le16(out, status);
  put_le16(out, aid);
  return out;
}

Bytes auth_body(std::uint16_t algorithm, std::uint16_t sequence, std::uint16_t status) {
  Bytes out;
  put_le16(out, algorithm);
  put_le16(out, sequence);
  put_le16(out, status);
  return out;
}

Bytes reason_body(std::uint16_t reason) {
  Bytes out;
  put_le16(out, reason);
  return out;
}

Bytes llc_snap_eapol() {
  // DSAP/SSAP 0xAA with control 0x03, then OUI 00-00-00 and EtherType 0x888E.
  // Omitting this is the classic mistake when synthesising 802.11 data
  // frames: the bytes look plausible but no dissector finds the EAPOL layer.
  return {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
}

Bytes eapol(std::uint8_t packet_type, ByteView body) {
  Bytes out = {2, packet_type};
  put_be16(out, static_cast<std::uint16_t>(body.size()));
  append(out, body);
  return out;
}

}  // namespace airlock::wifi::build
