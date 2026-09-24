// Finite-field Diffie-Hellman group parameters.
//
// Groups are the MODP groups from RFC 3526. Each modulus p is a safe prime
// (p = 2q + 1 with q prime), so the multiplicative group mod p has exactly one
// large prime-order subgroup of order q plus the trivial subgroup {1, p-1}.
// That structure is what makes the public-key validation in dh.cpp cheap and
// complete: a single exponentiation decides subgroup membership.
#pragma once

#include <cstddef>
#include <map>

#include "akex/bignum.hpp"

namespace airlock::akex {

struct DHGroup {
  int group_id;  // the IANA / RFC 3526 group number, carried on the wire
  BigNum p;      // the prime modulus
  BigNum g;      // the generator (2 for every RFC 3526 group)
  BigNum q;      // (p - 1) / 2, the order of the subgroup g generates
  int bits;      // size of p, which fixes the padded width of encoded values

  // Fixed encoding width for public keys and the shared secret. Every field
  // element is padded to this width so that the transcript hash and the key
  // schedule never depend on the leading-zero count of a particular value.
  std::size_t size_bytes() const { return static_cast<std::size_t>((bits + 7) / 8); }
};

const DHGroup& modp_2048();
const DHGroup& modp_3072();
inline const DHGroup& default_group() { return modp_2048(); }

// Every supported group, keyed by wire identifier.
const std::map<int, const DHGroup*>& groups();

// Look up a group by its wire identifier.
//
// Refusing unknown identifiers is the point: a peer must not be able to steer
// us into a group we have not vetted, which is how downgrade attacks on
// negotiated-group protocols usually start. Throws std::invalid_argument.
const DHGroup& get_group(int group_id);

}  // namespace airlock::akex
