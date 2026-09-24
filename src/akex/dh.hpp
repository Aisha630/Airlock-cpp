// Finite-field Diffie-Hellman with strict public-key validation.
//
// The arithmetic here is three lines. Everything else is validation, which is
// where finite-field DH actually goes wrong in practice.
#pragma once

#include <stdexcept>

#include "akex/bignum.hpp"
#include "akex/params.hpp"
#include "common/bytes.hpp"

namespace airlock::akex {

// Raised when a peer's public value fails validation.
//
// Treated as fatal by the protocol layer: a peer sending an invalid public
// key is either broken or probing, and neither deserves a second message.
class InvalidPublicKey : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// A 256-bit exponent gives ~128-bit security in these groups: the best known
// attack on the discrete log is the generic sqrt(2^256) = 2^128 baby-step
// giant-step / Pollard rho bound. Using a full-width (2048-bit) exponent costs
// 8x the modexp time and buys nothing.
inline constexpr int EXPONENT_BITS = 256;

// Reject peer public values that are not honest subgroup elements.
//
// Two distinct checks, for two distinct attacks:
//
// 1. Range. y in {0, 1, p-1} forces the shared secret to a value the attacker
//    already knows (0, 1, or +/-1), regardless of our private key. This is
//    the classic "small subgroup confinement" degenerate case.
//
// 2. Subgroup membership, y^q mod p == 1. In a safe-prime group the only
//    subgroups are of order 1, 2, q, and 2q. An element outside the order-q
//    subgroup leaks one bit of our private exponent per handshake through the
//    Legendre symbol of the shared secret. Cheap to check, so we check it.
void validate_public_key(const BigNum& y, const DHGroup& group);

// An ephemeral DH key pair. One handshake, then discard.
//
// Ephemeral keys are what give this protocol forward secrecy: the private
// exponent never touches disk, so a later compromise of the long-term PSK
// does not decrypt a recorded past session.
class DHKeyPair {
 public:
  // Generate a fresh key pair from OpenSSL's private-key DRBG.
  static DHKeyPair generate(const DHGroup& group = default_group());

  const DHGroup& group() const { return *group_; }
  const BigNum& private_key() const { return private_; }
  const BigNum& public_key() const { return public_; }

  // The public value at the group's fixed width.
  Bytes public_bytes() const;

  // Validate the peer's public value and compute the shared secret.
  //
  // Returns the secret zero-padded to the group width. The padding matters:
  // an unpadded encoding would make the shared secret's length depend on its
  // value, and that length feeds the key schedule.
  Bytes exchange(const BigNum& peer_public) const;

 private:
  DHKeyPair(const DHGroup& group, BigNum private_key, BigNum public_key);

  const DHGroup* group_;
  BigNum private_;
  BigNum public_;
};

}  // namespace airlock::akex
