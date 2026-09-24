#include "akex/wire.hpp"

#include <algorithm>
#include <limits>

#include "akex/crypto.hpp"

namespace airlock::akex {
namespace {

constexpr std::size_t HEADER_LEN = 9;  // magic, type, group id, public key length

void check(bool condition, const char* message) {
  if (!condition) throw WireError(message);
}

bool has_magic(ByteView raw) {
  return raw.size() >= MAGIC.size() && std::equal(MAGIC.begin(), MAGIC.end(), raw.begin());
}

Bytes header(std::uint8_t type, std::uint16_t group_id, std::size_t pub_len) {
  check(pub_len <= std::numeric_limits<std::uint16_t>::max(), "public key too long to encode");
  Bytes out = to_bytes(MAGIC);
  out.push_back(type);
  put_be16(out, group_id);
  put_be16(out, static_cast<std::uint16_t>(pub_len));
  return out;
}

}  // namespace

Bytes InitMessage::encode() const {
  check(nonce_i.size() == NONCE_LEN, "bad initiator nonce length");
  Bytes out = header(MSG_INIT, group_id, pub_i.size());
  append(out, nonce_i);
  append(out, pub_i);
  return out;
}

InitMessage InitMessage::decode(ByteView raw) {
  check(raw.size() >= HEADER_LEN, "init message truncated");
  check(has_magic(raw), "bad magic");
  check(raw[4] == MSG_INIT, "not an init message");
  const std::uint16_t group_id = get_be16(raw, 5);
  const std::size_t pub_len = get_be16(raw, 7);
  ByteView body = raw.subspan(HEADER_LEN);
  check(body.size() == NONCE_LEN + pub_len, "init message length mismatch");
  return InitMessage{group_id, slice(body, 0, NONCE_LEN), slice(body, NONCE_LEN, pub_len)};
}

Bytes ResponseMessage::core_bytes() const {
  check(nonce_r.size() == NONCE_LEN, "bad responder nonce length");
  Bytes out = header(MSG_RESPONSE, group_id, pub_r.size());
  append(out, nonce_r);
  append(out, pub_r);
  return out;
}

Bytes ResponseMessage::encode() const {
  check(tag_r.size() == TAG_LEN, "bad responder tag length");
  Bytes out = core_bytes();
  append(out, tag_r);
  return out;
}

ResponseMessage ResponseMessage::decode(ByteView raw) {
  check(raw.size() >= HEADER_LEN, "response message truncated");
  check(has_magic(raw), "bad magic");
  check(raw[4] == MSG_RESPONSE, "not a response message");
  const std::uint16_t group_id = get_be16(raw, 5);
  const std::size_t pub_len = get_be16(raw, 7);
  ByteView body = raw.subspan(HEADER_LEN);
  check(body.size() == NONCE_LEN + pub_len + TAG_LEN, "response message length mismatch");
  return ResponseMessage{group_id, slice(body, 0, NONCE_LEN), slice(body, NONCE_LEN, pub_len),
                         slice(body, NONCE_LEN + pub_len, TAG_LEN)};
}

Bytes ConfirmMessage::encode() const {
  check(tag_i.size() == TAG_LEN, "bad initiator tag length");
  Bytes out = to_bytes(MAGIC);
  out.push_back(MSG_CONFIRM);
  append(out, tag_i);
  return out;
}

ConfirmMessage ConfirmMessage::decode(ByteView raw) {
  check(raw.size() == 5 + TAG_LEN, "confirm message length mismatch");
  check(has_magic(raw), "bad magic");
  check(raw[4] == MSG_CONFIRM, "not a confirm message");
  return ConfirmMessage{slice(raw, 5, TAG_LEN)};
}

Bytes transcript_hash(std::initializer_list<ByteView> chunks) {
  Sha256 hash;
  for (ByteView chunk : chunks) {
    check(chunk.size() <= std::numeric_limits<std::uint32_t>::max(), "transcript chunk too long");
    Bytes prefix;
    put_be32(prefix, static_cast<std::uint32_t>(chunk.size()));
    hash.update(prefix);
    hash.update(chunk);
  }
  return hash.digest();
}

}  // namespace airlock::akex
