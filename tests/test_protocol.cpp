// The handshake: agreement, authentication, key separation, and ordering.
#include <gtest/gtest.h>

#include <set>
#include <string>

#include "akex/crypto.hpp"
#include "akex/dh.hpp"
#include "akex/params.hpp"
#include "akex/protocol.hpp"
#include "akex/wire.hpp"
#include "support.hpp"

using namespace airlock;
using namespace airlock::akex;

namespace {

const Bytes PSK = to_bytes("a pre-shared key for testing");

}  // namespace

TEST(Protocol, HandshakeAgreesOnAllFourKeys) {
  auto [initiator_keys, responder_keys] = run_handshake(PSK);
  EXPECT_EQ(initiator_keys, responder_keys);
}

TEST(Protocol, HandshakeAgreesIn3072) {
  auto [initiator_keys, responder_keys] = run_handshake(PSK, modp_3072());
  EXPECT_EQ(initiator_keys, responder_keys);
}

TEST(Protocol, HandshakeSurvivesAFullWireRoundTrip) {
  // Both parties must work from decoded bytes, not shared objects.
  Initiator initiator(PSK);
  Responder responder(PSK);
  const InitMessage init = InitMessage::decode(initiator.start().encode());
  auto [response, unused] = responder.respond(init);
  auto [confirm, initiator_keys] = initiator.finish(ResponseMessage::decode(response.encode()));
  const SessionKeys responder_keys = responder.confirm(ConfirmMessage::decode(confirm.encode()));
  EXPECT_EQ(initiator_keys, responder_keys);
}

TEST(Protocol, KeysArePairwiseDistinct) {
  auto [keys, unused] = run_handshake(PSK);
  const std::set<Bytes> derived = {keys.auth_i, keys.auth_r, keys.session_i2r, keys.session_r2i};
  EXPECT_EQ(derived.size(), 4u);
  for (const Bytes& key : derived) EXPECT_EQ(key.size(), 32u);
}

TEST(Protocol, EachHandshakeProducesFreshKeys) {
  // Ephemeral keys and fresh nonces: the same PSK must not repeat a session.
  auto [first, unused1] = run_handshake(PSK);
  auto [second, unused2] = run_handshake(PSK);
  EXPECT_NE(first.session_i2r, second.session_i2r);
  EXPECT_NE(first.fingerprint(), second.fingerprint());
}

TEST(Protocol, WrongPskFailsAtTheResponderTag) {
  Initiator initiator(PSK);
  Responder responder(to_bytes("the wrong key"));
  auto [response, unused] = responder.respond(initiator.start());
  EXPECT_THROW(initiator.finish(response), AuthenticationError);
}

TEST(Protocol, InitiatorTagIsCheckedByTheResponder) {
  // A responder must not accept a forged final message.
  Initiator initiator(PSK);
  Responder responder(PSK);
  auto [response, unused] = responder.respond(initiator.start());
  initiator.finish(response);
  EXPECT_THROW(responder.confirm(ConfirmMessage{repeat(0x00, 32)}), AuthenticationError);
}

namespace {

class TamperWithMessageTwo : public ::testing::TestWithParam<std::string> {};

TEST_P(TamperWithMessageTwo, IsDetected) {
  Initiator initiator(PSK);
  Responder responder(PSK);
  auto [response, unused] = responder.respond(initiator.start());
  ResponseMessage forged = response;
  Bytes& field = GetParam() == "nonce_r" ? forged.nonce_r : forged.tag_r;
  field[0] ^= 0x01;
  EXPECT_THROW(initiator.finish(forged), AuthenticationError);
}

INSTANTIATE_TEST_SUITE_P(Fields, TamperWithMessageTwo, ::testing::Values("nonce_r", "tag_r"));

}  // namespace

TEST(Protocol, TamperingWithThePublicKeyIsCaughtByValidation) {
  // Corrupting g^r trips the subgroup check before the tag is even reached.
  Initiator initiator(PSK);
  Responder responder(PSK);
  auto [response, unused] = responder.respond(initiator.start());
  ResponseMessage forged = response;
  forged.pub_r.back() ^= 0x01;
  try {
    initiator.finish(forged);
    FAIL() << "a corrupted public key was accepted";
  } catch (const AuthenticationError&) {
  } catch (const InvalidPublicKey&) {
  }
}

TEST(Protocol, GroupDowngradeIsRefused) {
  Initiator initiator(PSK, modp_3072());
  initiator.start();
  const ResponseMessage forged{14, repeat(0x00, 32), repeat(0x02, modp_2048().size_bytes()),
                               repeat(0x00, 32)};
  try {
    initiator.finish(forged);
    FAIL() << "a downgraded group was accepted";
  } catch (const ProtocolError&) {
  } catch (const AuthenticationError&) {
  }
}

TEST(Protocol, ResponderEnforcesItsGroupPolicy) {
  Responder responder(PSK, modp_3072());
  const InitMessage weak = Initiator(PSK, modp_2048()).start();
  EXPECT_THROW(responder.respond(weak), ProtocolError);
}

TEST(Protocol, ResponderRejectsAWronglySizedPublicKey) {
  Responder responder(PSK);
  EXPECT_THROW_WITH(responder.respond(InitMessage{14, repeat(0x00, 32), repeat(0x02, 16)}),
                    ProtocolError, "requires");
}

TEST(Protocol, ResponderRejectsADegeneratePublicKey) {
  Responder responder(PSK);
  EXPECT_THROW(responder.respond(
                   InitMessage{14, repeat(0x00, 32), BigNum(1).to_bytes(modp_2048().size_bytes())}),
               InvalidPublicKey);
}

TEST(Protocol, ResponderRejectsAnUnknownGroup) {
  Responder responder(PSK);
  EXPECT_THROW(responder.respond(InitMessage{1, repeat(0x00, 32), repeat(0x02, 96)}),
               std::invalid_argument);
}

TEST(Protocol, StateMachineRejectsOutOfOrderCalls) {
  EXPECT_THROW(Initiator(PSK).finish(ResponseMessage{14, repeat(0x00, 32), repeat(0x02, 256),
                                                     repeat(0x00, 32)}),
               ProtocolError);
  EXPECT_THROW(Responder(PSK).confirm(ConfirmMessage{repeat(0x00, 32)}), ProtocolError);
}

TEST(Protocol, MitmWithoutThePskCannotForgeATag) {
  // The attack the protocol exists to stop.
  Initiator initiator(PSK);
  const InitMessage init = initiator.start();
  const DHKeyPair attacker_key = DHKeyPair::generate(modp_2048());
  const ResponseMessage core{14, repeat(0x07, 32), attacker_key.public_bytes(), {}};
  const Bytes transcript = transcript_hash({init.encode(), core.core_bytes()});
  const ResponseMessage forged{14, repeat(0x07, 32), attacker_key.public_bytes(),
                               hmac_sha256(to_bytes("guessed psk"), transcript)};
  EXPECT_THROW(initiator.finish(forged), AuthenticationError);
}

TEST(Protocol, KeyDerivationBindsEveryInput) {
  // Changing any one input must change every derived key.
  const Bytes shared = repeat(0x01, 256), psk = to_bytes("psk"), nonce_i = repeat(0x02, 32),
              nonce_r = repeat(0x03, 32), transcript = repeat(0x04, 32);
  const SessionKeys reference = derive_keys(shared, psk, nonce_i, nonce_r, transcript);
  const SessionKeys changed[] = {
      derive_keys(repeat(0x09, 256), psk, nonce_i, nonce_r, transcript),
      derive_keys(shared, to_bytes("other"), nonce_i, nonce_r, transcript),
      derive_keys(shared, psk, repeat(0x09, 32), nonce_r, transcript),
      derive_keys(shared, psk, nonce_i, repeat(0x09, 32), transcript),
      derive_keys(shared, psk, nonce_i, nonce_r, repeat(0x09, 32)),
  };
  const char* names[] = {"shared_secret", "psk", "nonce_i", "nonce_r", "transcript"};
  for (int i = 0; i < 5; ++i) {
    EXPECT_NE(changed[i].auth_i, reference.auth_i) << names[i] << " is not bound";
    EXPECT_NE(changed[i].auth_r, reference.auth_r) << names[i] << " is not bound";
    EXPECT_NE(changed[i].session_i2r, reference.session_i2r) << names[i] << " is not bound";
    EXPECT_NE(changed[i].session_r2i, reference.session_r2i) << names[i] << " is not bound";
  }
}

TEST(Protocol, KeyDerivationIsDeterministic) {
  const Bytes shared = repeat(0x01, 256), psk = to_bytes("psk"), nonce_i = repeat(0x02, 32),
              nonce_r = repeat(0x03, 32), transcript = repeat(0x04, 32);
  EXPECT_EQ(derive_keys(shared, psk, nonce_i, nonce_r, transcript),
            derive_keys(shared, psk, nonce_i, nonce_r, transcript));
}
