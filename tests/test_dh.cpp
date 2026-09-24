// Diffie-Hellman arithmetic and, mostly, public-key validation.
#include <gtest/gtest.h>

#include <optional>
#include <set>
#include <string>

#include "akex/dh.hpp"
#include "akex/params.hpp"
#include "support.hpp"

using namespace airlock;
using namespace airlock::akex;

namespace {

class GroupParameters : public ::testing::TestWithParam<const DHGroup*> {};

TEST_P(GroupParameters, AreWellFormed) {
  // p must be the advertised size, and g must generate the order-q subgroup.
  const DHGroup& group = *GetParam();
  EXPECT_EQ(group.p.bit_length(), group.bits);
  EXPECT_EQ(group.size_bytes(), static_cast<std::size_t>(group.bits / 8));
  // p is a safe prime, so q = (p-1)/2 and g^q == 1 iff g is in that subgroup.
  EXPECT_EQ(group.q + group.q + BigNum(1), group.p);
  EXPECT_EQ(BigNum::mod_exp(group.g, group.q, group.p), BigNum(1));
}

INSTANTIATE_TEST_SUITE_P(Groups, GroupParameters, ::testing::Values(&modp_2048(), &modp_3072()),
                         [](const auto& info) { return "modp" + std::to_string(info.param->bits); });

}  // namespace

TEST(Dh, KeyAgreement) {
  const DHKeyPair alice = DHKeyPair::generate(modp_2048());
  const DHKeyPair bob = DHKeyPair::generate(modp_2048());
  EXPECT_EQ(alice.exchange(bob.public_key()), bob.exchange(alice.public_key()));
}

TEST(Dh, KeyAgreementIn3072) {
  const DHKeyPair alice = DHKeyPair::generate(modp_3072());
  const DHKeyPair bob = DHKeyPair::generate(modp_3072());
  EXPECT_EQ(alice.exchange(bob.public_key()), bob.exchange(alice.public_key()));
}

TEST(Dh, KeyPairsAreDistinct) {
  // A repeated key pair would mean the CSPRNG is not being used properly.
  std::set<std::string> keys;
  for (int i = 0; i < 8; ++i) keys.insert(DHKeyPair::generate(modp_2048()).private_key().to_hex());
  EXPECT_EQ(keys.size(), 8u);
}

TEST(Dh, PrivateExponentIsInRange) {
  for (int i = 0; i < 8; ++i) {
    const DHKeyPair keypair = DHKeyPair::generate(modp_2048());
    EXPECT_GE(keypair.private_key(), BigNum(2));
    EXPECT_LE(keypair.private_key().bit_length(), EXPONENT_BITS);
  }
}

TEST(Dh, PublicBytesAreFixedWidth) {
  // Encoding must be padded, or the transcript would depend on value size.
  for (int i = 0; i < 8; ++i) {
    EXPECT_EQ(DHKeyPair::generate(modp_2048()).public_bytes().size(), modp_2048().size_bytes());
  }
}

TEST(Dh, SharedSecretIsFixedWidth) {
  const DHKeyPair alice = DHKeyPair::generate(modp_2048());
  const DHKeyPair bob = DHKeyPair::generate(modp_2048());
  EXPECT_EQ(alice.exchange(bob.public_key()).size(), modp_2048().size_bytes());
}

namespace {

struct Degenerate {
  std::string name;
  BigNum value;
};

class DegeneratePublicKey : public ::testing::TestWithParam<Degenerate> {};

TEST_P(DegeneratePublicKey, IsRejected) {
  EXPECT_THROW(validate_public_key(GetParam().value, modp_2048()), InvalidPublicKey);
}

INSTANTIATE_TEST_SUITE_P(
    Values, DegeneratePublicKey,
    ::testing::Values(Degenerate{"zero", BigNum(0)},
                      Degenerate{"order_1_shared_secret_is_always_1", BigNum(1)},
                      Degenerate{"order_2_shared_secret_is_always_plus_minus_1",
                                 modp_2048().p - BigNum(1)},
                      Degenerate{"equals_the_modulus", modp_2048().p},
                      Degenerate{"above_the_modulus", modp_2048().p + BigNum(1)},
                      Degenerate{"negative", BigNum(1).negated()}),
    [](const auto& info) { return info.param.name; });

}  // namespace

TEST(Dh, NonSubgroupPublicKeyIsRejected) {
  // A quadratic non-residue is outside the order-q subgroup and leaks a bit.
  const DHGroup& group = modp_2048();
  std::optional<BigNum> non_residue;
  for (unsigned long y = 2; y < 100 && !non_residue; ++y) {
    if (BigNum::mod_exp(BigNum(y), group.q, group.p) != BigNum(1)) non_residue = BigNum(y);
  }
  ASSERT_TRUE(non_residue.has_value());
  EXPECT_THROW_WITH(validate_public_key(*non_residue, group), InvalidPublicKey,
                    "prime-order subgroup");
}

TEST(Dh, ValidSubgroupElementIsAccepted) {
  // Guard against validation that rejects everything and looks "secure".
  const DHKeyPair keypair = DHKeyPair::generate(modp_2048());
  EXPECT_NO_THROW(validate_public_key(keypair.public_key(), modp_2048()));
  // A quadratic residue (7^2) is in the subgroup by construction.
  EXPECT_NO_THROW(validate_public_key(BigNum(49), modp_2048()));
}

TEST(Dh, ExchangeValidatesBeforeComputing) {
  const DHKeyPair keypair = DHKeyPair::generate(modp_2048());
  EXPECT_THROW(keypair.exchange(BigNum(1)), InvalidPublicKey);
}

TEST(Dh, UnknownGroupIdIsRefused) {
  // Refusing unknown groups is what blocks a downgrade to a weak group.
  EXPECT_THROW(get_group(1), std::invalid_argument);  // the 768-bit MODP group, long broken
  for (const auto& [group_id, group] : groups()) EXPECT_EQ(&get_group(group_id), group);
}
