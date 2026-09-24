// HKDF-SHA256 against the official test vectors in RFC 5869 Appendix A.
//
// These are the tests that matter most in the whole suite. Everything in the
// key schedule rests on HKDF being correct, and "it produces 32 bytes that
// look random" is not evidence of that. Matching the published vectors byte
// for byte is.
#include <gtest/gtest.h>

#include <string>

#include "akex/crypto.hpp"
#include "akex/kdf.hpp"

using namespace airlock;
using namespace airlock::akex;

namespace {

Bytes range_bytes(int from, int to) {
  Bytes out;
  for (int i = from; i < to; ++i) out.push_back(static_cast<std::uint8_t>(i));
  return out;
}

struct Vector {
  std::string name;
  Bytes ikm, salt, info;
  std::size_t length;
  Bytes prk, okm;
};

// RFC 5869 Appendix A. Only the SHA-256 cases apply here; cases 4-7 use SHA-1.
std::vector<Vector> vectors() {
  return {
      {"rfc5869_case_1_basic", repeat(0x0b, 22), from_hex("000102030405060708090a0b0c"),
       from_hex("f0f1f2f3f4f5f6f7f8f9"), 42,
       from_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
       from_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865")},
      {"rfc5869_case_2_long_inputs", range_bytes(0x00, 0x50), range_bytes(0x60, 0xB0),
       range_bytes(0xB0, 0x100), 82,
       from_hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
       from_hex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                "cc30c58179ec3e87c14c01d5c1f3434f1d87")},
      {"rfc5869_case_3_empty_salt_and_info", repeat(0x0b, 22), {}, {}, 42,
       from_hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
       from_hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                "9d201395faa4b61a96c8")},
  };
}

class Rfc5869 : public ::testing::TestWithParam<Vector> {};

TEST_P(Rfc5869, HkdfMatchesTheRfc) {
  const Vector& v = GetParam();
  const Bytes prk = hkdf_extract(v.salt, v.ikm);
  EXPECT_EQ(prk, v.prk) << "extract does not match the RFC";
  EXPECT_EQ(hkdf_expand(prk, v.info, v.length), v.okm) << "expand does not match the RFC";
  EXPECT_EQ(hkdf(v.ikm, v.salt, v.info, v.length), v.okm);
}

INSTANTIATE_TEST_SUITE_P(Vectors, Rfc5869, ::testing::ValuesIn(vectors()),
                         [](const auto& info) { return info.param.name; });

}  // namespace

TEST(Kdf, EmptySaltEqualsZeroSalt) {
  // RFC 5869 Section 2.2: an absent salt means HashLen zero bytes.
  const Bytes ikm = to_bytes("input keying material");
  EXPECT_EQ(hkdf_extract({}, ikm), hkdf_extract(repeat(0, HASH_LEN), ikm));
}

TEST(Kdf, DifferentInfoGivesIndependentOutput) {
  // The property the key schedule depends on: info separates keys.
  const Bytes prk = hkdf_extract(to_bytes("salt"), to_bytes("ikm"));
  EXPECT_NE(hkdf_expand(prk, to_bytes("purpose A"), 32), hkdf_expand(prk, to_bytes("purpose B"), 32));
}

TEST(Kdf, ExpandIsDeterministic) {
  const Bytes prk = hkdf_extract(to_bytes("salt"), to_bytes("ikm"));
  EXPECT_EQ(hkdf_expand(prk, to_bytes("info"), 64), hkdf_expand(prk, to_bytes("info"), 64));
}

TEST(Kdf, ExpandOutputIsAPrefixOfALongerExpansion) {
  // HKDF is a stream: the first N bytes do not depend on the total length.
  const Bytes prk = hkdf_extract(to_bytes("salt"), to_bytes("ikm"));
  const Bytes longer = hkdf_expand(prk, to_bytes("info"), 100);
  EXPECT_EQ(Bytes(longer.begin(), longer.begin() + 32), hkdf_expand(prk, to_bytes("info"), 32));
}

TEST(Kdf, ExpandRejectsMoreThan255Blocks) {
  // RFC 5869 caps output at 255 * HashLen; the counter is one byte.
  const Bytes prk = hkdf_extract(to_bytes("salt"), to_bytes("ikm"));
  EXPECT_EQ(hkdf_expand(prk, to_bytes("info"), 255 * HASH_LEN).size(), 255 * HASH_LEN);
  EXPECT_THROW(hkdf_expand(prk, to_bytes("info"), 255 * HASH_LEN + 1), std::invalid_argument);
}

TEST(Kdf, ExpandRejectsShortPrk) {
  EXPECT_THROW(hkdf_expand(to_bytes("too short"), to_bytes("info"), 32), std::invalid_argument);
}

TEST(Kdf, ConstantTimeEq) {
  EXPECT_TRUE(constant_time_eq(to_bytes("abc"), to_bytes("abc")));
  EXPECT_FALSE(constant_time_eq(to_bytes("abc"), to_bytes("abd")));
  EXPECT_FALSE(constant_time_eq(to_bytes("abc"), to_bytes("abcd")));
}

TEST(Kdf, HmacMatchesRfc4231Case2) {
  // An HMAC-SHA256 known answer, so a broken wrapper cannot hide behind HKDF.
  EXPECT_EQ(to_hex(hmac_sha256(to_bytes("Jefe"), to_bytes("what do ya want for nothing?"))),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}
