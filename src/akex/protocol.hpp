// The AKEX handshake: authenticated ephemeral Diffie-Hellman.
//
//     I -> R   InitMessage      group, nonce_i, g^i
//     R -> I   ResponseMessage  nonce_r, g^r, tag_r
//     I -> R   ConfirmMessage   tag_i
//
// Plain Diffie-Hellman agrees a key with somebody but says nothing about who.
// A machine-in-the-middle can run one exchange with each side and relay
// plaintext forever. The two tags are what fix that: each is an HMAC over the
// handshake transcript under a key derived from both the DH secret and a
// pre-shared key, so producing one requires knowing the PSK and having run
// the exchange. This is the same shape as the WPA2 four-way handshake, where
// MICs under a PMK-derived key authenticate nonces the two sides just traded.
//
// Security properties: mutual authentication against anyone without the PSK;
// forward secrecy, since DH keys are ephemeral; transcript integrity, since
// every field of messages 1 and 2 (group id included) is hashed into both
// tags; and key separation, four independent keys from one exchange via HKDF
// info labels. What it does not do is resist an offline dictionary attack on
// a low-entropy PSK. See THREAT_MODEL.md.
#pragma once

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "akex/dh.hpp"
#include "akex/params.hpp"
#include "akex/wire.hpp"
#include "common/bytes.hpp"

namespace airlock::akex {

inline constexpr std::size_t KEY_LEN = 32;

// Raised when a peer's tag does not verify.
//
// This is the failure that matters. It fires for a tampered transcript, a
// machine-in-the-middle without the PSK, and a wrong PSK alike: the receiver
// cannot tell which, and does not need to.
class AuthenticationError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Raised when messages arrive out of order or a field is unacceptable.
class ProtocolError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// The four keys derived from one handshake.
//
// Directional session keys mean a record the initiator sent can never be
// reflected back at it and accepted as one the responder sent.
struct SessionKeys {
  Bytes auth_i;
  Bytes auth_r;
  Bytes session_i2r;
  Bytes session_r2i;

  // Short public digest of the session, for demos and logs. Derived by
  // hashing, never by printing key material, so two parties can compare
  // fingerprints out loud without revealing anything useful.
  std::string fingerprint() const;

  bool operator==(const SessionKeys&) const = default;
};

// Turn the DH secret and the PSK into four independent keys.
//
// Extract: the salt is a hash of both nonces and the PSK, and the input
// keying material is the DH shared secret. Binding the PSK here means the PRK,
// and so every key below it, is unreachable without both the PSK and the DH
// secret. Binding the nonces means two handshakes with the same PSK and
// (through some failure) the same DH keys still produce different keys.
//
// Expand: four calls that differ only in the info label, each with the
// transcript hash appended. Distinct labels give independent keys; the
// transcript makes those keys depend on every byte of the handshake, so the
// peers agree on keys only if they saw the identical conversation.
SessionKeys derive_keys(ByteView shared_secret, ByteView psk, ByteView nonce_i, ByteView nonce_r,
                        ByteView transcript);

// Initiator state machine. Call `start`, then `finish`.
class Initiator {
 public:
  explicit Initiator(Bytes psk, const DHGroup& group = default_group());

  // Generate the ephemeral key pair and nonce, and emit message 1.
  InitMessage start();

  // Verify the responder's tag, then emit our own.
  //
  // The order is deliberate: derive, verify, and only then treat the session
  // as live. Nothing derived from an unverified transcript escapes.
  std::pair<ConfirmMessage, SessionKeys> finish(const ResponseMessage& response);

  const std::optional<SessionKeys>& keys() const { return keys_; }

 private:
  Bytes psk_;
  const DHGroup* group_;
  std::optional<DHKeyPair> keypair_;
  Bytes nonce_i_;
  Bytes init_bytes_;
  std::optional<SessionKeys> keys_;
};

// Responder state machine. Call `respond`, then `confirm`.
class Responder {
 public:
  // Accept any supported group the initiator proposes.
  explicit Responder(Bytes psk);
  // Accept only `required`, refusing anything else the initiator proposes.
  Responder(Bytes psk, const DHGroup& required);

  // Process message 1 and emit message 2 with our tag.
  //
  // The responder authenticates first. That ordering is what lets the
  // initiator abort against an impostor before sending anything of its own,
  // and it mirrors the WPA2 four-way handshake, where the AP's message 3 MIC
  // is what proves the AP knows the PMK.
  std::pair<ResponseMessage, SessionKeys> respond(const InitMessage& init);

  // Verify the initiator's tag. Until this succeeds, nothing is live.
  //
  // The responder has usable keys after `respond`, but it must not act on
  // them yet: at that point it has proved itself to the initiator without the
  // initiator having proved anything back.
  SessionKeys confirm(const ConfirmMessage& confirm);

  const std::optional<SessionKeys>& keys() const { return keys_; }

 private:
  Bytes psk_;
  const DHGroup* group_;
  std::optional<DHKeyPair> keypair_;
  Bytes nonce_r_;
  Bytes init_bytes_;
  Bytes response_bytes_;
  std::optional<SessionKeys> keys_;
};

// Run a full in-process handshake, with every message passed through its wire
// encoding. Returns (initiator keys, responder keys).
std::pair<SessionKeys, SessionKeys> run_handshake(ByteView psk,
                                                  const DHGroup& group = default_group());

}  // namespace airlock::akex
