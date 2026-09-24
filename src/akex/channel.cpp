#include "akex/channel.hpp"

#include <limits>
#include <string>
#include <utility>

#include "akex/crypto.hpp"
#include "akex/wire.hpp"

namespace airlock::akex {
namespace {

constexpr std::uint64_t MAX_SEQ = std::numeric_limits<std::uint64_t>::max();

// Build the authenticated header.
//
// The direction and the sequence number are covered by the tag, not merely
// transmitted. Leaving either out of the MAC input would allow reflection
// (bouncing a record back at its sender) and reordering respectively. The
// payload length is included so that a truncated record cannot be passed off
// as a shorter valid one.
Bytes mac_input(std::uint8_t direction, std::uint64_t seq, ByteView payload) {
  Bytes out = to_bytes(LABEL_RECORD);
  out.push_back(direction);
  put_be64(out, seq);
  put_be32(out, static_cast<std::uint32_t>(payload.size()));
  append(out, payload);
  return out;
}

}  // namespace

AuthenticatedChannel::AuthenticatedChannel(Bytes send_key, Bytes recv_key,
                                           std::uint8_t send_direction,
                                           std::uint8_t recv_direction)
    : send_key_(std::move(send_key)),
      recv_key_(std::move(recv_key)),
      send_direction_(send_direction),
      recv_direction_(recv_direction) {}

AuthenticatedChannel AuthenticatedChannel::for_initiator(const SessionKeys& keys) {
  return AuthenticatedChannel(keys.session_i2r, keys.session_r2i, DIR_I2R, DIR_R2I);
}

AuthenticatedChannel AuthenticatedChannel::for_responder(const SessionKeys& keys) {
  return AuthenticatedChannel(keys.session_r2i, keys.session_i2r, DIR_R2I, DIR_I2R);
}

Bytes AuthenticatedChannel::seal(ByteView payload) {
  if (send_exhausted_) throw RecordError("sequence number space exhausted; rekey required");
  if (payload.size() > std::numeric_limits<std::uint32_t>::max()) {
    throw RecordError("payload too large for one record");
  }
  const Bytes tag = hmac_sha256(send_key_, mac_input(send_direction_, send_seq_, payload));

  Bytes record;
  record.reserve(RECORD_HEADER_LEN + payload.size() + TAG_LEN);
  put_be64(record, send_seq_);
  put_be32(record, static_cast<std::uint32_t>(payload.size()));
  append(record, payload);
  append(record, tag);

  if (send_seq_ == MAX_SEQ) {
    send_exhausted_ = true;
  } else {
    ++send_seq_;
  }
  return record;
}

Bytes AuthenticatedChannel::open_record(ByteView record) {
  if (record.size() < RECORD_HEADER_LEN + TAG_LEN) throw RecordError("record truncated");
  const std::uint64_t seq = get_be64(record, 0);
  const std::size_t payload_len = get_be32(record, 8);
  if (record.size() != RECORD_HEADER_LEN + payload_len + TAG_LEN) {
    throw RecordError("record length mismatch");
  }
  ByteView payload = record.subspan(RECORD_HEADER_LEN, payload_len);
  ByteView tag = record.subspan(RECORD_HEADER_LEN + payload_len);

  const Bytes expected = hmac_sha256(recv_key_, mac_input(recv_direction_, seq, payload));
  if (!constant_time_eq(expected, tag)) {
    throw RecordError(
        "MAC verification failed: the record was modified in transit, "
        "forged, or reflected from the other direction");
  }

  // Strictly increasing sequence numbers. This rejects both a verbatim replay
  // and any attempt to reorder records, which for an authenticated but
  // unencrypted channel is the remaining way to change what the application
  // sees without breaking a MAC.
  if (recv_exhausted_ || seq < recv_seq_) {
    throw RecordError("replay or reorder detected: got sequence " + std::to_string(seq) +
                      ", expected at least " +
                      (recv_exhausted_ ? std::string("2^64") : std::to_string(recv_seq_)));
  }
  if (seq == MAX_SEQ) {
    recv_exhausted_ = true;
  } else {
    recv_seq_ = seq + 1;
  }
  return Bytes(payload.begin(), payload.end());
}

}  // namespace airlock::akex
