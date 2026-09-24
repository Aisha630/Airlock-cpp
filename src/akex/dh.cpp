#include "akex/dh.hpp"

#include <utility>

namespace airlock::akex {

void validate_public_key(const BigNum& y, const DHGroup& group) {
  const BigNum one(1);
  if (y <= one || y >= group.p - one) {
    throw InvalidPublicKey(
        "public key outside the valid range 2 <= y <= p-2 "
        "(degenerate value forces a known shared secret)");
  }
  if (BigNum::mod_exp(y, group.q, group.p) != one) {
    throw InvalidPublicKey(
        "public key is not in the prime-order subgroup "
        "(leaks private-key bits via the Legendre symbol)");
  }
}

DHKeyPair::DHKeyPair(const DHGroup& group, BigNum private_key, BigNum public_key)
    : group_(&group), private_(std::move(private_key)), public_(std::move(public_key)) {}

DHKeyPair DHKeyPair::generate(const DHGroup& group) {
  const BigNum one(1);
  const BigNum p_minus_one = group.p - one;
  while (true) {
    // Range [2, 2^256): reject 0 and 1, which give trivial publics.
    BigNum private_key = BigNum::random_bits(EXPONENT_BITS);
    if (private_key <= one) continue;
    BigNum public_key = BigNum::mod_exp_secret(group.g, private_key, group.p);
    // g generates the order-q subgroup, so this only trips on an
    // astronomically unlikely exponent. Checked anyway.
    if (public_key > one && public_key < p_minus_one) {
      return DHKeyPair(group, std::move(private_key), std::move(public_key));
    }
  }
}

Bytes DHKeyPair::public_bytes() const { return public_.to_bytes(group_->size_bytes()); }

Bytes DHKeyPair::exchange(const BigNum& peer_public) const {
  validate_public_key(peer_public, *group_);
  BigNum shared = BigNum::mod_exp_secret(peer_public, private_, group_->p);
  if (shared <= BigNum(1)) {
    // Unreachable given the validation above; kept as a hard stop so that a
    // future change to validation cannot silently produce a degenerate secret.
    throw InvalidPublicKey("degenerate shared secret");
  }
  return shared.to_bytes(group_->size_bytes());
}

}  // namespace airlock::akex
