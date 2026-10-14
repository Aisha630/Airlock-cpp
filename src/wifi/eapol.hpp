// EAPOL-Key parsing and WPA2 four-way handshake tracking.
//
// The four-way handshake is the closest real-world relative of the AKEX key
// exchange in the other half of this project:
//
//     AKEX                          WPA2 four-way handshake
//     PSK, hashed into HKDF salt    PMK, from PBKDF2(passphrase, SSID)
//     ephemeral DH secret           ANonce + SNonce, no DH at all
//     HKDF-SHA256 key schedule      PRF-384/512 -> PTK, split into KCK/KEK/TK
//     HMAC tag over the transcript  Key MIC under the KCK
//     tag_r in message 2            MIC on messages 2, 3, 4
//
// The structural difference that matters: WPA2 has no Diffie-Hellman, so the
// PTK is a deterministic function of the PMK and the two nonces. Anyone who
// captures the handshake and later guesses the passphrase recovers the PTK and
// decrypts the whole session retroactively. AKEX and WPA3-SAE both fix this
// with a fresh key exchange per session, which is what forward secrecy buys.
//
// This module reads handshake metadata only. It does not attempt to recover
// keys or crack passphrases.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "common/bytes.hpp"

namespace airlock::wifi {

inline constexpr int EAPOL_TYPE_KEY = 3;

// IEEE 802.11-2020 Figure 12-34, Key Information bit positions.
inline constexpr std::uint16_t KEY_INFO_PAIRWISE = 1 << 3;
inline constexpr std::uint16_t KEY_INFO_INSTALL = 1 << 6;
inline constexpr std::uint16_t KEY_INFO_ACK = 1 << 7;
inline constexpr std::uint16_t KEY_INFO_MIC = 1 << 8;
inline constexpr std::uint16_t KEY_INFO_SECURE = 1 << 9;
inline constexpr std::uint16_t KEY_INFO_ERROR = 1 << 10;
inline constexpr std::uint16_t KEY_INFO_REQUEST = 1 << 11;
inline constexpr std::uint16_t KEY_INFO_ENCRYPTED = 1 << 12;

// Raised when an EAPOL-Key body is truncated or malformed.
class EapolParseError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// One parsed EAPOL-Key frame.
struct EapolKeyFrame {
  int descriptor_type = 0;
  std::uint16_t key_info = 0;
  int key_length = 0;
  std::uint64_t replay_counter = 0;
  Bytes nonce;
  Bytes key_mic;
  int key_data_length = 0;
  Bytes key_data;

  bool pairwise() const { return key_info & KEY_INFO_PAIRWISE; }
  bool install() const { return key_info & KEY_INFO_INSTALL; }
  bool ack() const { return key_info & KEY_INFO_ACK; }
  bool has_mic() const { return key_info & KEY_INFO_MIC; }
  bool secure() const { return key_info & KEY_INFO_SECURE; }
  bool encrypted_key_data() const { return key_info & KEY_INFO_ENCRYPTED; }
  // Message 4 carries an all-zero nonce; messages 1-3 carry real ones.
  bool nonce_is_zero() const;

  // Identify which of the four messages this is, from the flag bits.
  //
  // The standard never gave the messages an explicit number, so they are
  // distinguished by three bits:
  //
  //     M1  pairwise, Ack,        no MIC     (AP sends ANonce)
  //     M2  pairwise,      MIC,   not Secure (STA sends SNonce + RSN IE)
  //     M3  pairwise, Ack, MIC,   Secure     (AP confirms, installs key)
  //     M4  pairwise,      MIC,   Secure     (STA acknowledges)
  //
  // M2 and M4 differ only in the Secure bit and the presence of key data,
  // which is why a capture that starts mid-handshake can be genuinely
  // ambiguous. Returns nothing rather than guessing.
  std::optional<int> message_number() const;

  // Extract a PMKID from message 1's key data, if the AP included one.
  //
  // PSK-derived PMKIDs can support offline password guesses. SAE and other
  // AKMs have different key establishment; extraction alone is not a risk
  // assessment, and the PMKID calculation depends on the selected AKM.
  std::optional<Bytes> pmkid() const;
};

// Parse an EAPOL-Key frame starting at the EAPOL header.
EapolKeyFrame parse_eapol_key(ByteView payload);

// State of one four-way handshake between an AP and a station.
struct Handshake {
  std::string ap;
  std::string station;
  std::map<int, double> messages;  // message number -> timestamp
  std::map<int, std::uint64_t> replay_counters;
  std::map<int, std::size_t> frame_indices;
  std::optional<Bytes> anonce;
  std::optional<Bytes> snonce;
  std::optional<Bytes> pmkid;

  // All four messages observed.
  bool complete() const;
  std::vector<int> observed() const;
  // Wall-clock time from message 1 to message 4.
  std::optional<double> duration_ms() const;
  // Observations about this handshake.
  std::vector<std::string> notes() const;
};

// Groups EAPOL-Key frames into per-(AP, station) handshakes.
//
// A station may handshake with the same AP several times in one capture:
// after a deauthentication, or on a periodic rekey. Each attempt is kept as
// its own record rather than overwriting the last, because the earlier ones
// are often the interesting ones: the handshake captured right after a deauth
// flood is the attacker's objective, and it is the first message 1 that
// tends to carry the PMKID.
class HandshakeTracker {
 public:
  // Record one EAPOL-Key frame. Returns the message number, if known.
  //
  // Direction tells us which endpoint is the AP: messages 1 and 3 carry the
  // Ack bit and always flow from the authenticator.
  std::optional<int> observe(const EapolKeyFrame& frame, const std::string& transmitter,
                             const std::string& receiver, double timestamp, std::size_t index);

  // Every handshake attempt, in the order it started.
  const std::vector<Handshake>& all() const { return handshakes_; }

 private:
  std::map<std::pair<std::string, std::string>, std::size_t> active_;
  std::vector<Handshake> handshakes_;
};

}  // namespace airlock::wifi
