// 802.11 frame classification from header metadata.
//
// The type/subtype pair lives in the two-byte Frame Control field at the head
// of every 802.11 MAC header, which is transmitted in the clear even on a
// fully protected network. This is the basis of the analyzer: an observer who
// cannot read a single byte of your traffic can still see who is talking to
// whom, when, and what they are doing.
#pragma once

#include <cstddef>
#include <map>
#include <optional>
#include <string>

namespace airlock::wifi {

// IEEE 802.11-2020, Table 9-1. Type 3 is reserved for frame extensions
// (S1G / DMG); it is listed so unknown frames are labelled rather than lost.
inline constexpr int TYPE_MANAGEMENT = 0;
inline constexpr int TYPE_CONTROL = 1;
inline constexpr int TYPE_DATA = 2;
inline constexpr int TYPE_EXTENSION = 3;

const std::map<int, std::string>& type_names();
// The type's name, or "type-N" when it has none.
std::string type_name(int frame_type);
// Human-readable subtype, falling back to "subtype-N".
std::string subtype_name(int frame_type, int subtype);

// IEEE 802.11-2020, Tables 9-49 and 9-50. Only the codes this analyzer
// expects to see are named; anything else is reported by number.
const std::map<int, std::string>& reason_codes();
const std::map<int, std::string>& status_codes();
// The reason's description, or "unknown".
std::string reason_text(int code);

// Metadata extracted from one captured 802.11 frame.
//
// Address semantics depend on the To DS / From DS bits, so addr1..addr3 are
// kept under their positional names rather than being guessed into source
// and destination. `receiver()` and `transmitter()` give the one
// interpretation that is always true: addr1 receives, addr2 transmits.
struct FrameInfo {
  std::size_t index = 0;
  double timestamp = 0.0;
  int frame_type = 0;
  int subtype = 0;
  std::string type_name;
  std::string subtype_name;
  std::optional<std::string> addr1;
  std::optional<std::string> addr2;
  std::optional<std::string> addr3;
  std::optional<std::string> bssid;
  std::optional<std::string> ssid;
  bool to_ds = false;
  bool from_ds = false;
  bool is_protected = false;
  bool retry = false;
  std::size_t length = 0;
  std::optional<int> signal_dbm;
  std::optional<int> channel;
  std::optional<int> reason_code;
  std::optional<int> status_code;
  bool suspect = false;
  // Authentication frames only: the algorithm name and transaction number.
  std::optional<std::string> auth_algorithm;
  std::optional<int> auth_seq;
  // EAPOL-Key frames only: which of the four handshake messages this is.
  std::optional<int> eapol_message;

  // True when addr2 is a legal individual (unicast) address.
  //
  // IEEE 802.11 requires the transmitter address to be an individual address:
  // the low bit of the first octet (the Individual/Group bit) must be clear.
  // A frame claiming to be transmitted by a group address is structurally
  // impossible, so in a real capture it means the frame was received
  // corrupted: monitor mode hands up frames that failed their checksum, and a
  // flipped bit in the address field is as likely as anywhere else.
  //
  // This is an exact test, not a heuristic, which is why it is used to
  // exclude frames rather than merely to flag them.
  bool transmitter_is_valid() const;

  const std::optional<std::string>& receiver() const { return addr1; }
  // Absent in ACK and CTS, which have no addr2.
  const std::optional<std::string>& transmitter() const { return addr2; }

  bool is_management() const { return frame_type == TYPE_MANAGEMENT; }
  bool is_control() const { return frame_type == TYPE_CONTROL; }
  bool is_data() const { return frame_type == TYPE_DATA; }

  // One-line summary for the report tables.
  std::string describe() const;
};

}  // namespace airlock::wifi
