// Byte-level builders for 802.11 frames.
//
// The synthetic capture and the tests both need well-formed (and sometimes
// deliberately malformed) frames. These helpers lay the fields out exactly as
// IEEE 802.11-2020 Section 9.3 and the radiotap specification define them, so
// the parser in capture.cpp is exercised against real wire layouts.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "common/bytes.hpp"

namespace airlock::wifi::build {

// Frame Control flag bits (the second octet of the field).
inline constexpr std::uint8_t FC_TO_DS = 0x01;
inline constexpr std::uint8_t FC_FROM_DS = 0x02;
inline constexpr std::uint8_t FC_RETRY = 0x08;
inline constexpr std::uint8_t FC_PROTECTED = 0x40;

// "aa:bb:cc:dd:ee:ff" to six octets. Throws std::invalid_argument.
Bytes mac(std::string_view text);

// A radiotap header carrying Channel and dBm Antenna Signal, as a capturing
// adapter would prepend.
Bytes radiotap(std::uint16_t frequency_mhz, std::uint16_t channel_flags, std::int8_t signal_dbm);
// The smallest radiotap header: no fields present.
Bytes radiotap_empty();

// A MAC header. Which address fields exist depends on the type and subtype,
// exactly as on the air: control frames other than RTS, PS-Poll, Block Ack and
// a few others carry only addr1, and only management and data frames carry
// addr3 and a Sequence Control field. Addresses that the frame type calls for
// but the caller leaves out are written as zeros.
Bytes dot11(int type, int subtype, std::uint8_t flags, std::string_view addr1,
            std::string_view addr2 = {}, std::string_view addr3 = {});

// One information element: id, length, body.
Bytes element(std::uint8_t id, ByteView body);

// Management frame bodies (fixed fields only; elements follow separately).
Bytes beacon_body(std::uint16_t interval, std::uint16_t capability);
Bytes assoc_request_body(std::uint16_t capability, std::uint16_t listen_interval);
Bytes assoc_response_body(std::uint16_t capability, std::uint16_t status, std::uint16_t aid);
Bytes auth_body(std::uint16_t algorithm, std::uint16_t sequence, std::uint16_t status);
Bytes reason_body(std::uint16_t reason);

// LLC/SNAP header announcing an EAPOL payload (EtherType 0x888E).
Bytes llc_snap_eapol();
// EAPOL header (version 2) around an EAPOL-Key body.
Bytes eapol(std::uint8_t packet_type, ByteView body);

}  // namespace airlock::wifi::build
