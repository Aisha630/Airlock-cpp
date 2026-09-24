#include "akex/bignum.hpp"

#include <openssl/bn.h>
#include <openssl/crypto.h>

#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>

namespace airlock::akex {
namespace {

BIGNUM* checked(BIGNUM* bn) {
  if (bn == nullptr) throw std::bad_alloc();
  return bn;
}

void require(int ok, const char* what) {
  if (ok != 1) throw std::runtime_error(what);
}

struct CtxDeleter {
  void operator()(BN_CTX* ctx) const { BN_CTX_free(ctx); }
};
using Ctx = std::unique_ptr<BN_CTX, CtxDeleter>;

Ctx new_ctx() {
  Ctx ctx(BN_CTX_new());
  if (!ctx) throw std::bad_alloc();
  return ctx;
}

}  // namespace

BigNum::BigNum() : bn_(checked(BN_new())) {}

BigNum::BigNum(unsigned long value) : BigNum() { require(BN_set_word(bn_, value), "BN_set_word"); }

BigNum::BigNum(Adopt, bignum_st* raw) : bn_(checked(raw)) {}

// Values held here can be private exponents, so they are wiped on release.
BigNum::~BigNum() { BN_clear_free(bn_); }

BigNum::BigNum(const BigNum& other) : bn_(checked(BN_dup(other.bn_))) {}

BigNum& BigNum::operator=(const BigNum& other) {
  if (this != &other) {
    BigNum copy(other);
    std::swap(bn_, copy.bn_);
  }
  return *this;
}

BigNum::BigNum(BigNum&& other) noexcept : bn_(std::exchange(other.bn_, BN_new())) {}

BigNum& BigNum::operator=(BigNum&& other) noexcept {
  std::swap(bn_, other.bn_);
  return *this;
}

BigNum BigNum::from_bytes(ByteView big_endian) {
  if (big_endian.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw std::invalid_argument("integer encoding too long");
  }
  return BigNum(Adopt{},
                BN_bin2bn(big_endian.data(), static_cast<int>(big_endian.size()), nullptr));
}

BigNum BigNum::from_hex(std::string_view hex) {
  std::string digits;
  for (char c : hex) {
    if (c != ' ' && c != '\n' && c != '\t') digits.push_back(c);
  }
  BIGNUM* raw = nullptr;
  if (digits.empty() || BN_hex2bn(&raw, digits.c_str()) != static_cast<int>(digits.size())) {
    BN_free(raw);
    throw std::invalid_argument("invalid hex integer");
  }
  return BigNum(Adopt{}, raw);
}

BigNum BigNum::random_bits(int bits) {
  BigNum out;
  require(BN_priv_rand_ex(out.bn_, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, 0, nullptr),
          "BN_priv_rand_ex");
  return out;
}

Bytes BigNum::to_bytes(std::size_t width) const {
  if (BN_is_negative(bn_)) throw std::invalid_argument("cannot encode a negative integer");
  if (width > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw std::invalid_argument("encoding width too large");
  }
  Bytes out(width);
  if (BN_bn2binpad(bn_, out.data(), static_cast<int>(width)) < 0) {
    throw std::invalid_argument("integer does not fit in the requested width");
  }
  return out;
}

std::string BigNum::to_hex() const {
  char* raw = BN_bn2hex(bn_);
  if (raw == nullptr) throw std::bad_alloc();
  std::string out(raw);
  OPENSSL_free(raw);
  return out;
}

int BigNum::bit_length() const { return BN_num_bits(bn_); }

bool BigNum::is_negative() const { return BN_is_negative(bn_) != 0; }

BigNum BigNum::operator+(const BigNum& other) const {
  BigNum out;
  require(BN_add(out.bn_, bn_, other.bn_), "BN_add");
  return out;
}

BigNum BigNum::operator-(const BigNum& other) const {
  BigNum out;
  require(BN_sub(out.bn_, bn_, other.bn_), "BN_sub");
  return out;
}

BigNum BigNum::shifted_right(int bits) const {
  BigNum out;
  require(BN_rshift(out.bn_, bn_, bits), "BN_rshift");
  return out;
}

BigNum BigNum::negated() const {
  BigNum out(*this);
  BN_set_negative(out.bn_, !BN_is_negative(bn_));
  return out;
}

bool operator==(const BigNum& a, const BigNum& b) { return BN_cmp(a.bn_, b.bn_) == 0; }

std::strong_ordering operator<=>(const BigNum& a, const BigNum& b) {
  int c = BN_cmp(a.bn_, b.bn_);
  if (c < 0) return std::strong_ordering::less;
  if (c > 0) return std::strong_ordering::greater;
  return std::strong_ordering::equal;
}

BigNum BigNum::mod_exp(const BigNum& base, const BigNum& exponent, const BigNum& modulus) {
  BigNum out;
  Ctx ctx = new_ctx();
  require(BN_mod_exp(out.bn_, base.bn_, exponent.bn_, modulus.bn_, ctx.get()), "BN_mod_exp");
  return out;
}

BigNum BigNum::mod_exp_secret(const BigNum& base, const BigNum& exponent,
                              const BigNum& modulus) {
  BigNum out;
  BigNum secret(exponent);
  BN_set_flags(secret.bn_, BN_FLG_CONSTTIME);
  Ctx ctx = new_ctx();
  require(BN_mod_exp_mont_consttime(out.bn_, base.bn_, secret.bn_, modulus.bn_, ctx.get(),
                                    nullptr),
          "BN_mod_exp_mont_consttime");
  return out;
}

}  // namespace airlock::akex
