#include "akex/protocol.hpp"

#include <string>

#include "akex/crypto.hpp"
#include "akex/kdf.hpp"

namespace airlock::akex {
namespace {

Bytes label_with(std::string_view label, ByteView transcript) {
  return concat({to_bytes(label), transcript});
}

const char* const TAG_FAILURE_SUFFIX =
    " tag verification failed: wrong PSK, a tampered transcript, or a machine-in-the-middle";

}  // namespace

std::string SessionKeys::fingerprint() const {
  const Bytes digest = sha256(concat({to_bytes("AKEX v1 fingerprint"), session_i2r, session_r2i}));
  return to_hex(digest).substr(0, 32);
}

SessionKeys derive_keys(ByteView shared_secret, ByteView psk, ByteView nonce_i, ByteView nonce_r,
                        ByteView transcript) {
  const Bytes salt = sha256(concat({to_bytes(LABEL_SALT), nonce_i, nonce_r, psk}));
  const Bytes prk = hkdf_extract(salt, shared_secret);
  return SessionKeys{
      hkdf_expand(prk, label_with(LABEL_INITIATOR_AUTH, transcript), KEY_LEN),
      hkdf_expand(prk, label_with(LABEL_RESPONDER_AUTH, transcript), KEY_LEN),
      hkdf_expand(prk, label_with(LABEL_SESSION_I2R, transcript), KEY_LEN),
      hkdf_expand(prk, label_with(LABEL_SESSION_R2I, transcript), KEY_LEN),
  };
}

// --- initiator ------------------------------------------------------------

Initiator::Initiator(Bytes psk, const DHGroup& group) : psk_(std::move(psk)), group_(&group) {}

InitMessage Initiator::start() {
  keypair_ = DHKeyPair::generate(*group_);
  nonce_i_ = random_bytes(NONCE_LEN);
  InitMessage message{static_cast<std::uint16_t>(group_->group_id), nonce_i_,
                      keypair_->public_bytes()};
  init_bytes_ = message.encode();
  return message;
}

std::pair<ConfirmMessage, SessionKeys> Initiator::finish(const ResponseMessage& response) {
  if (init_bytes_.empty() || !keypair_) throw ProtocolError("finish() called before start()");
  if (response.group_id != group_->group_id) {
    // The group id is inside the transcript, so this would also be caught by
    // the tag check. Failing early gives a clearer error and avoids a
    // pointless 2048-bit modexp.
    throw ProtocolError("responder changed group: sent " + std::to_string(response.group_id) +
                        ", expected " + std::to_string(group_->group_id));
  }

  const Bytes shared = keypair_->exchange(BigNum::from_bytes(response.pub_r));  // validates

  const Bytes transcript = transcript_hash({init_bytes_, response.core_bytes()});
  SessionKeys keys = derive_keys(shared, psk_, nonce_i_, response.nonce_r, transcript);

  const Bytes expected = hmac_sha256(keys.auth_r, transcript);
  if (!constant_time_eq(expected, response.tag_r)) {
    throw AuthenticationError(std::string("responder") + TAG_FAILURE_SUFFIX);
  }

  // The initiator's tag covers the responder's tag too, so it confirms the
  // exact message 2 we accepted, not merely its unauthenticated core.
  const Bytes final_transcript = transcript_hash({init_bytes_, response.encode()});
  ConfirmMessage confirm{hmac_sha256(keys.auth_i, final_transcript)};
  keys_ = keys;
  return {confirm, keys};
}

// --- responder ------------------------------------------------------------

Responder::Responder(Bytes psk) : psk_(std::move(psk)), group_(nullptr) {}

Responder::Responder(Bytes psk, const DHGroup& required)
    : psk_(std::move(psk)), group_(&required) {}

std::pair<ResponseMessage, SessionKeys> Responder::respond(const InitMessage& init) {
  const DHGroup& group = get_group(init.group_id);  // rejects unknown ids outright
  if (group_ != nullptr && group.group_id != group_->group_id) {
    throw ProtocolError("initiator requested group " + std::to_string(group.group_id) +
                        ", policy requires " + std::to_string(group_->group_id));
  }
  group_ = &group;

  if (init.pub_i.size() != group.size_bytes()) {
    throw ProtocolError("public key is " + std::to_string(init.pub_i.size()) + " bytes, group " +
                        std::to_string(group.group_id) + " requires " +
                        std::to_string(group.size_bytes()));
  }

  keypair_ = DHKeyPair::generate(group);
  nonce_r_ = random_bytes(NONCE_LEN);

  const Bytes shared = keypair_->exchange(BigNum::from_bytes(init.pub_i));  // validates

  ResponseMessage response{static_cast<std::uint16_t>(group.group_id), nonce_r_,
                           keypair_->public_bytes(), {}};
  init_bytes_ = init.encode();
  const Bytes transcript = transcript_hash({init_bytes_, response.core_bytes()});
  SessionKeys keys = derive_keys(shared, psk_, init.nonce_i, nonce_r_, transcript);

  response.tag_r = hmac_sha256(keys.auth_r, transcript);
  response_bytes_ = response.encode();
  keys_ = keys;
  return {response, keys};
}

SessionKeys Responder::confirm(const ConfirmMessage& confirm) {
  if (response_bytes_.empty() || !keys_) throw ProtocolError("confirm() called before respond()");

  const Bytes final_transcript = transcript_hash({init_bytes_, response_bytes_});
  const Bytes expected = hmac_sha256(keys_->auth_i, final_transcript);
  if (!constant_time_eq(expected, confirm.tag_i)) {
    throw AuthenticationError(std::string("initiator") + TAG_FAILURE_SUFFIX);
  }
  return *keys_;
}

std::pair<SessionKeys, SessionKeys> run_handshake(ByteView psk, const DHGroup& group) {
  Initiator initiator(Bytes(psk.begin(), psk.end()), group);
  Responder responder(Bytes(psk.begin(), psk.end()), group);

  const InitMessage init = initiator.start();
  auto [response, responder_keys] = responder.respond(InitMessage::decode(init.encode()));
  auto [confirm, initiator_keys] = initiator.finish(ResponseMessage::decode(response.encode()));
  responder.confirm(ConfirmMessage::decode(confirm.encode()));
  return {initiator_keys, responder_keys};
}

}  // namespace airlock::akex
