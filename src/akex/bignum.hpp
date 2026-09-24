// A small value-semantics wrapper around OpenSSL's BIGNUM.
//
// Only the operations the protocol needs are exposed. Exponentiation comes in
// two forms on purpose: `mod_exp` for public inputs (subgroup checks), and
// `mod_exp_secret` for anything involving a private exponent, which uses
// OpenSSL's constant-time Montgomery ladder so that the time taken does not
// depend on the exponent's bits.
#pragma once

#include <compare>
#include <cstddef>
#include <string>
#include <string_view>

#include "common/bytes.hpp"

struct bignum_st;

namespace airlock::akex {

class BigNum {
 public:
  BigNum();
  explicit BigNum(unsigned long value);
  ~BigNum();
  BigNum(const BigNum& other);
  BigNum& operator=(const BigNum& other);
  BigNum(BigNum&& other) noexcept;
  BigNum& operator=(BigNum&& other) noexcept;

  static BigNum from_bytes(ByteView big_endian);
  static BigNum from_hex(std::string_view hex);  // whitespace is ignored
  // Uniform in [0, 2^bits), drawn from OpenSSL's private-key DRBG.
  static BigNum random_bits(int bits);

  // Zero-padded big-endian encoding. Throws if the value does not fit.
  Bytes to_bytes(std::size_t width) const;
  std::string to_hex() const;
  int bit_length() const;
  bool is_negative() const;

  BigNum operator+(const BigNum& other) const;
  BigNum operator-(const BigNum& other) const;
  BigNum shifted_right(int bits) const;
  BigNum negated() const;

  friend bool operator==(const BigNum& a, const BigNum& b);
  friend std::strong_ordering operator<=>(const BigNum& a, const BigNum& b);

  // base^exponent mod modulus, for public values only.
  static BigNum mod_exp(const BigNum& base, const BigNum& exponent, const BigNum& modulus);
  // base^exponent mod modulus in constant time with respect to the
  // exponent. The modulus must be odd, which every MODP prime is.
  static BigNum mod_exp_secret(const BigNum& base, const BigNum& exponent, const BigNum& modulus);

 private:
  // Takes ownership of `raw`. The tag keeps a literal 0 from being read as
  // a null pointer and colliding with BigNum(unsigned long).
  struct Adopt {};
  BigNum(Adopt, bignum_st* raw);
  bignum_st* bn_;
};

}  // namespace airlock::akex
