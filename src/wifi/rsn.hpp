// Parser for the RSN and legacy WPA information elements.
//
// An access point advertises what it will accept in the RSN element (id 48)
// of its beacons and probe responses, in the clear. Reading it tells you the
// generation of the network (WPA2 / WPA3 / transition mode), the ciphers, and
// crucially whether management frames are protected, which decides whether
// the deauthentication attack in anomalies.cpp would work against it.
//
// Parsed by hand from the byte layout in IEEE 802.11-2020 Section 9.4.2.24,
// because the field this analyzer most cares about (the two MFP bits in RSN
// Capabilities) is exactly the sort of detail a convenience wrapper hides.
#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/bytes.hpp"

namespace airlock::wifi {

inline constexpr int RSN_ELEMENT_ID = 48;
inline constexpr int VENDOR_ELEMENT_ID = 221;

// Raised when an element is truncated or internally inconsistent.
class RSNParseError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Security capabilities advertised by an access point.
struct RSNInfo {
  int version = 1;
  std::string group_cipher = "unknown";
  std::vector<std::string> pairwise_ciphers;
  std::vector<std::string> akm_suites;
  bool mfp_capable = false;
  bool mfp_required = false;
  int pmkids = 0;
  std::optional<std::string> group_mgmt_cipher;
  int raw_capabilities = 0;
  bool is_wpa1 = false;

  // Name the security generation from the AKM list.
  //
  // Transition mode (SAE and PSK offered together) is called out separately
  // because it is a real downgrade exposure: a client that supports both can
  // be pushed onto the PSK path, where the passphrase is open to the offline
  // dictionary attack SAE was designed to remove.
  std::string generation() const;

  // Summarise the two MFP bits into one readable state.
  std::string mfp_state() const;

  // Findings a reviewer should act on, worst first.
  std::vector<std::string> weaknesses() const;
};

// Parse the body of an RSN element (element id 48).
//
// Every field after the version is optional and the element simply ends
// where the AP stopped writing, so each read is guarded by a length check. A
// truncated element is a parse error, not a silent default: quietly treating
// a cut-off element as "no MFP" would invent a finding.
RSNInfo parse_rsn_element(ByteView data);

// Parse a vendor-specific element, returning info only for legacy WPA1.
//
// WPA1 predates the RSN element, so it was carried in a vendor element with
// Microsoft's OUI and type 1. The body layout matches RSN but with a
// different OUI on the suite selectors and no capabilities field.
std::optional<RSNInfo> parse_wpa1_element(ByteView data);

// What to put in a generated RSN element.
struct RsnSpec {
  std::uint8_t group_cipher = 4;
  std::vector<std::uint8_t> pairwise_ciphers = {4};
  std::vector<std::uint8_t> akm_suites = {2};
  bool mfp_capable = false;
  bool mfp_required = false;
  std::optional<std::uint8_t> group_mgmt_cipher;
};

// Build an RSN element body. Used by the synthetic capture generator.
//
// Having the encoder next to the decoder keeps the two honest: the round trip
// is asserted in tests/test_rsn.cpp.
Bytes build_rsn_element(const RsnSpec& spec = {});

}  // namespace airlock::wifi
