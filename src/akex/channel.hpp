// An authenticated record layer over the derived session keys.
//
// Scope, stated up front so the README and the code agree: this layer
// provides integrity and authenticity only. It does not encrypt. Messages
// travel in the clear with an HMAC-SHA256 tag over a header that includes a
// sequence number. Adding confidentiality would mean swapping the MAC for an
// AEAD (AES-GCM or ChaCha20-Poly1305) keyed by the same session key, a change
// confined to `seal` and `open_record`. That is left out deliberately: the
// properties this layer does have are the ones the tamper and replay demos
// exercise.
#pragma once

#include <cstdint>
#include <stdexcept>

#include "akex/protocol.hpp"
#include "common/bytes.hpp"

namespace airlock::akex {

inline constexpr std::uint8_t DIR_I2R = 0;
inline constexpr std::uint8_t DIR_R2I = 1;

// Sequence number (8 bytes) and payload length (4 bytes) precede the payload.
inline constexpr std::size_t RECORD_HEADER_LEN = 12;

// Raised when a record fails authentication, ordering, or parsing.
class RecordError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// One peer's send and receive state.
//
// Each peer holds one channel with a send key and a receive key, taken from
// the two directional session keys in opposite order.
class AuthenticatedChannel {
 public:
  AuthenticatedChannel(Bytes send_key, Bytes recv_key, std::uint8_t send_direction,
                       std::uint8_t recv_direction);

  static AuthenticatedChannel for_initiator(const SessionKeys& keys);
  static AuthenticatedChannel for_responder(const SessionKeys& keys);

  // Authenticate a payload and advance the send counter.
  Bytes seal(ByteView payload);

  // Verify a record and return its payload.
  //
  // Ordering matters here. The tag is checked before the sequence number is
  // accepted, so an attacker cannot move our replay window by sending
  // unauthenticated garbage with a high sequence number.
  Bytes open_record(ByteView record);

  std::uint64_t send_seq() const { return send_seq_; }
  std::uint64_t recv_seq() const { return recv_seq_; }

 private:
  Bytes send_key_;
  Bytes recv_key_;
  std::uint8_t send_direction_;
  std::uint8_t recv_direction_;
  std::uint64_t send_seq_ = 0;
  std::uint64_t recv_seq_ = 0;
  // A 64-bit counter cannot wrap in any realistic session, but the check is
  // explicit rather than assumed: a silently wrapping counter would let an
  // old record replay as a new one. These flags record that the final
  // sequence number has been used in each direction.
  bool send_exhausted_ = false;
  bool recv_exhausted_ = false;
};

}  // namespace airlock::akex
