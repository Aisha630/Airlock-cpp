#include "akex/attacks.hpp"

#include <format>
#include <utility>

#include "akex/channel.hpp"
#include "akex/crypto.hpp"
#include "akex/dh.hpp"
#include "akex/params.hpp"
#include "akex/protocol.hpp"
#include "akex/wire.hpp"

namespace airlock::akex {
namespace {

const Bytes& psk() {
  static const Bytes value = to_bytes("correct horse battery staple");
  return value;
}

}  // namespace

std::string AttackResult::render() const {
  return std::format(
      "[{:>9}] {}\n"
      "             what happened: {}\n"
      "             mechanism:     {}",
      defended ? "BLOCKED" : "SUCCEEDED", name, detail, defense);
}

// Control case: an honest handshake must actually work.
AttackResult baseline() {
  auto [initiator_keys, responder_keys] = run_handshake(psk());
  return {
      "Honest handshake (control)",
      initiator_keys == responder_keys,
      "both parties derived identical keys; session fingerprint " + initiator_keys.fingerprint(),
      "Diffie-Hellman agreement over MODP group 14, keys via HKDF-SHA256",
  };
}

// A peer with the wrong pre-shared key must not complete the handshake.
AttackResult wrong_psk() {
  Initiator initiator(psk());
  Responder responder(to_bytes("a different pre-shared key"));
  auto [response, unused] = responder.respond(initiator.start());
  try {
    initiator.finish(response);
  } catch (const AuthenticationError& exc) {
    return {
        "Peer with the wrong PSK",
        true,
        exc.what(),
        "the PSK is hashed into the HKDF salt, so a different PSK yields a different auth key "
        "and an unverifiable tag",
    };
  }
  return {"Peer with the wrong PSK", false, "handshake completed", "none"};
}

// Flipping a single bit of the responder's nonce must be caught.
//
// The nonce is the right field to target. Corrupting the public key instead
// would trip the subgroup check in dh.cpp first, which is a real defense but
// a different one. Tampering with the nonce leaves every structural check
// satisfied, so the transcript tag is the only thing between the attacker and
// a completed handshake.
AttackResult tamper_with_transcript() {
  const std::string name = "Single-bit tamper with the handshake transcript (nonce)";
  Initiator initiator(psk());
  Responder responder(psk());
  auto [response, unused] = responder.respond(initiator.start());

  ResponseMessage forged = response;
  forged.nonce_r.back() ^= 0x01;  // one bit
  try {
    initiator.finish(forged);
  } catch (const AuthenticationError& exc) {
    return {name, true, std::string("AuthenticationError: ") + exc.what(),
            "every handshake field is hashed into the transcript that both tags commit to; one "
            "flipped bit changes the digest"};
  } catch (const InvalidPublicKey& exc) {
    return {name, true, std::string("InvalidPublicKey: ") + exc.what(),
            "every handshake field is hashed into the transcript that both tags commit to; one "
            "flipped bit changes the digest"};
  }
  return {name, false, "accepted", "none"};
}

// Modifying application data after the handshake must be caught.
AttackResult tamper_with_record() {
  auto [initiator_keys, responder_keys] = run_handshake(psk());
  auto sender = AuthenticatedChannel::for_initiator(initiator_keys);
  auto receiver = AuthenticatedChannel::for_responder(responder_keys);

  Bytes record = sender.seal(to_bytes("TRANSFER 100 TO ACCOUNT 4471"));
  // Rewrite the amount in flight, just past the sequence/length header.
  record[RECORD_HEADER_LEN + 9] = '9';
  try {
    receiver.open_record(record);
  } catch (const RecordError& exc) {
    return {"Tamper with an application record in flight", true, exc.what(),
            "HMAC-SHA256 over header plus payload, compared in constant time"};
  }
  return {"Tamper with an application record in flight", false, "accepted", "none"};
}

// Re-sending a captured, perfectly valid record must be caught.
AttackResult replay_record() {
  auto [initiator_keys, responder_keys] = run_handshake(psk());
  auto sender = AuthenticatedChannel::for_initiator(initiator_keys);
  auto receiver = AuthenticatedChannel::for_responder(responder_keys);

  const Bytes record = sender.seal(to_bytes("UNLOCK DOOR"));
  receiver.open_record(record);  // legitimate delivery
  try {
    receiver.open_record(record);  // attacker rebroadcasts the same bytes
  } catch (const RecordError& exc) {
    return {"Replay of a captured valid record", true, exc.what(),
            "the sequence number is inside the MAC input and the receiver requires it to "
            "strictly increase, so a valid tag is not enough"};
  }
  return {"Replay of a captured valid record", false, "accepted", "none"};
}

// A machine-in-the-middle without the PSK substitutes its own DH key.
//
// The attacker runs a clean exchange with each side. The DH math works
// perfectly, as it always does. The attacker fails at the tag, because
// forging one requires the PSK.
AttackResult mitm_against_akex() {
  Initiator initiator(psk());
  Responder responder(psk());
  const DHKeyPair attacker_key = DHKeyPair::generate(default_group());

  const InitMessage init = initiator.start();
  // The attacker swaps in its own public key toward the responder...
  responder.respond(InitMessage{init.group_id, init.nonce_i, attacker_key.public_bytes()});
  // ...and forges a response toward the initiator, with the best tag it can
  // produce: an HMAC under a key derived from a guessed PSK.
  const Bytes attacker_nonce = random_bytes(NONCE_LEN);
  const ResponseMessage core{init.group_id, attacker_nonce, attacker_key.public_bytes(), {}};
  const Bytes guessed_transcript = transcript_hash({init.encode(), core.core_bytes()});
  const ResponseMessage forged{
      init.group_id, attacker_nonce, attacker_key.public_bytes(),
      hmac_sha256(to_bytes("attacker's guess at the PSK"), guessed_transcript)};
  try {
    initiator.finish(forged);
  } catch (const AuthenticationError& exc) {
    return {"Machine-in-the-middle without the PSK", true,
            std::string("the attacker completed the DH exchange with both sides but could not "
                        "produce a valid tag: ") +
                exc.what(),
            "authentication binds the exchange to the PSK; DH agreement alone proves nothing "
            "about identity"};
  }
  return {"Machine-in-the-middle without the PSK", false, "relayed", "none"};
}

// The control case: the same attack on bare DH, which it wins.
//
// This is the most important function here. It is the evidence that the tags
// in AKEX are load-bearing and not decoration.
AttackResult mitm_unauthenticated_dh() {
  const DHGroup& group = default_group();
  const DHKeyPair alice = DHKeyPair::generate(group);
  const DHKeyPair bob = DHKeyPair::generate(group);
  const DHKeyPair mallory_to_alice = DHKeyPair::generate(group);
  const DHKeyPair mallory_to_bob = DHKeyPair::generate(group);

  // Neither side ever sees the other's real public key.
  const Bytes alice_secret = alice.exchange(mallory_to_alice.public_key());
  const Bytes bob_secret = bob.exchange(mallory_to_bob.public_key());
  const Bytes mallory_with_alice = mallory_to_alice.exchange(alice.public_key());
  const Bytes mallory_with_bob = mallory_to_bob.exchange(bob.public_key());

  const bool owned = alice_secret == mallory_with_alice && bob_secret == mallory_with_bob &&
                     alice_secret != bob_secret;
  return {
      "Machine-in-the-middle against UNAUTHENTICATED DH (control)",
      !owned,
      owned ? "the attacker holds both session secrets and can read and rewrite everything; "
              "neither party detects anything wrong"
            : "attack unexpectedly failed",
      "none -- this is plain DH with the authentication removed, shown to make the case that "
      "the tags above are what stop the attack",
  };
}

// Degenerate and non-subgroup public keys must be rejected.
AttackResult invalid_public_key() {
  const DHGroup& group = default_group();
  const DHKeyPair victim = DHKeyPair::generate(group);
  // y = p-1 has order 2: the shared secret collapses to +/-1 whatever the
  // victim's private exponent is. y = 11 is a non-residue for this modulus,
  // so it sits outside the prime-order subgroup and leaks an exponent bit.
  const std::vector<std::pair<std::string, BigNum>> hostile = {
      {"y = 1 (order 1)", BigNum(1)},
      {"y = p-1 (order 2)", group.p - BigNum(1)},
      {"y = 11 (outside the prime-order subgroup)", BigNum(11)},
  };
  for (const auto& [label, value] : hostile) {
    try {
      victim.exchange(value);
    } catch (const InvalidPublicKey&) {
      continue;
    }
    return {"Small-subgroup / degenerate public key", false, "accepted " + label, "none"};
  }
  return {"Small-subgroup / degenerate public key", true,
          std::format("all {} hostile values rejected", hostile.size()),
          "range check plus the subgroup test y^q mod p == 1 before the shared secret is ever "
          "computed"};
}

// A responder switching to a different group mid-handshake must be caught.
AttackResult group_downgrade() {
  Initiator initiator(psk(), modp_3072());
  initiator.start();
  // The attacker rewrites the group id in message 2 to the weaker group.
  const DHGroup& weak = default_group();
  const ResponseMessage forged{static_cast<std::uint16_t>(weak.group_id),
                               random_bytes(NONCE_LEN), repeat(0x02, weak.size_bytes()),
                               repeat(0x00, TAG_LEN)};
  const char* defense =
      "the negotiated group id is pinned by policy and also hashed into the transcript both "
      "tags cover";
  try {
    initiator.finish(forged);
  } catch (const ProtocolError& exc) {
    return {"Downgrade to a weaker DH group", true, std::string("ProtocolError: ") + exc.what(),
            defense};
  } catch (const AuthenticationError& exc) {
    return {"Downgrade to a weaker DH group", true,
            std::string("AuthenticationError: ") + exc.what(), defense};
  }
  return {"Downgrade to a weaker DH group", false, "accepted", "none"};
}

const std::vector<Attack>& attacks() {
  static const std::vector<Attack> all = {
      {"baseline", baseline},
      {"wrong_psk", wrong_psk},
      {"tamper_with_transcript", tamper_with_transcript},
      {"tamper_with_record", tamper_with_record},
      {"replay_record", replay_record},
      {"mitm_against_akex", mitm_against_akex},
      {"invalid_public_key", invalid_public_key},
      {"group_downgrade", group_downgrade},
      {"mitm_unauthenticated_dh", mitm_unauthenticated_dh},
  };
  return all;
}

std::vector<AttackResult> run_all() {
  std::vector<AttackResult> results;
  for (const Attack& attack : attacks()) results.push_back(attack.run());
  return results;
}

}  // namespace airlock::akex
