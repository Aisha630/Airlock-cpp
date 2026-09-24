// Canonical wire encoding for handshake messages.
//
// Every field is fixed-width or length-prefixed and every integer is
// big-endian. The encoding has to be canonical (exactly one byte string per
// message) because the transcript hash is computed over these bytes. If two
// different encodings of the same logical message were both accepted, an
// attacker could show one to each party and break the transcript binding.
#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <stdexcept>
#include <string_view>

#include "common/bytes.hpp"

namespace airlock::akex {

inline constexpr std::string_view MAGIC = "AKX1";
inline constexpr std::size_t NONCE_LEN = 32;
inline constexpr std::size_t TAG_LEN = 32;

inline constexpr std::uint8_t MSG_INIT = 1;
inline constexpr std::uint8_t MSG_RESPONSE = 2;
inline constexpr std::uint8_t MSG_CONFIRM = 3;

// Domain-separation labels. Distinct strings keep a tag computed for one
// purpose from ever verifying in another position in the protocol.
inline constexpr std::string_view LABEL_RESPONDER_AUTH = "AKEX v1 responder auth";
inline constexpr std::string_view LABEL_INITIATOR_AUTH = "AKEX v1 initiator auth";
inline constexpr std::string_view LABEL_SESSION_I2R = "AKEX v1 session key i2r";
inline constexpr std::string_view LABEL_SESSION_R2I = "AKEX v1 session key r2i";
inline constexpr std::string_view LABEL_SALT = "AKEX v1 salt";
inline constexpr std::string_view LABEL_RECORD = "AKEX v1 record";

// Raised on a malformed or truncated message.
class WireError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Message 1, initiator -> responder: group choice, nonce, public key.
struct InitMessage {
  std::uint16_t group_id = 0;
  Bytes nonce_i;
  Bytes pub_i;

  Bytes encode() const;
  static InitMessage decode(ByteView raw);
  bool operator==(const InitMessage&) const = default;
};

// Message 2, responder -> initiator: nonce, public key, and auth tag.
//
// `core_bytes` (everything but the tag) is what gets hashed into the
// transcript the tag commits to, because a tag cannot cover itself.
struct ResponseMessage {
  std::uint16_t group_id = 0;
  Bytes nonce_r;
  Bytes pub_r;
  Bytes tag_r;

  Bytes core_bytes() const;
  Bytes encode() const;
  static ResponseMessage decode(ByteView raw);
  bool operator==(const ResponseMessage&) const = default;
};

// Message 3, initiator -> responder: proof the initiator holds the PSK.
struct ConfirmMessage {
  Bytes tag_i;

  Bytes encode() const;
  static ConfirmMessage decode(ByteView raw);
  bool operator==(const ConfirmMessage&) const = default;
};

// Hash an ordered list of message encodings into a transcript digest.
//
// Each chunk is length-prefixed before hashing so that concatenation is
// unambiguous. Without the prefix, ("ab", "c") and ("a", "bc") would produce
// the same digest: a splicing attack on the transcript itself.
Bytes transcript_hash(std::initializer_list<ByteView> chunks);

}  // namespace airlock::akex
