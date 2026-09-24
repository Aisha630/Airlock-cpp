#include "wifi/eapol.hpp"

#include <algorithm>
#include <format>

#include "wifi/text.hpp"

namespace airlock::wifi {
namespace {

// Fixed EAPOL-Key body: descriptor type through key data length.
constexpr std::size_t KEY_BODY_LEN = 95;

}  // namespace

bool EapolKeyFrame::nonce_is_zero() const {
  return nonce.size() == 32 && std::all_of(nonce.begin(), nonce.end(), [](auto b) { return b == 0; });
}

std::optional<int> EapolKeyFrame::message_number() const {
  if (!pairwise()) return std::nullopt;  // group key handshake, not the four-way
  if (ack() && !has_mic()) return 1;
  if (has_mic() && !ack() && !secure()) return 2;
  if (has_mic() && ack()) return 3;
  if (has_mic() && !ack() && secure()) return 4;
  return std::nullopt;
}

std::optional<Bytes> EapolKeyFrame::pmkid() const {
  if (message_number() != 1 || key_data.empty()) return std::nullopt;
  const Bytes& data = key_data;
  std::size_t offset = 0;
  while (offset + 2 <= data.size()) {
    const int element_id = data[offset];
    const std::size_t length = data[offset + 1];
    if (offset + 2 + length > data.size()) return std::nullopt;
    ByteView body = ByteView(data).subspan(offset + 2, length);
    // A PMKID KDE: vendor element 221 with OUI 00-0F-AC and data type 4.
    if (element_id == 221 && body.size() >= 4 && body[0] == 0x00 && body[1] == 0x0f &&
        body[2] == 0xac) {
      if (body[3] == 4 && body.size() >= 20) return slice(body, 4, 16);
    }
    offset += 2 + length;
  }
  return std::nullopt;
}

EapolKeyFrame parse_eapol_key(ByteView payload) {
  if (payload.size() < 4) throw EapolParseError("EAPOL header truncated");
  const int packet_type = payload[1];
  if (packet_type != EAPOL_TYPE_KEY) {
    throw EapolParseError(std::format("EAPOL packet type {} is not Key", packet_type));
  }

  ByteView body = payload.subspan(4);
  if (body.size() < KEY_BODY_LEN) throw EapolParseError("EAPOL-Key body truncated");

  EapolKeyFrame frame;
  frame.descriptor_type = body[0];
  frame.key_info = get_be16(body, 1);
  frame.key_length = get_be16(body, 3);
  frame.replay_counter = get_be64(body, 5);
  frame.nonce = slice(body, 13, 32);
  // body[45:61] Key IV, body[61:69] Key RSC, body[69:77] reserved.
  frame.key_mic = slice(body, 77, 16);
  frame.key_data_length = get_be16(body, 93);
  const auto key_data_length = static_cast<std::size_t>(frame.key_data_length);
  if (body.size() < KEY_BODY_LEN + key_data_length) {
    throw EapolParseError("EAPOL-Key data field truncated");
  }
  frame.key_data = slice(body, KEY_BODY_LEN, key_data_length);
  return frame;
}

bool Handshake::complete() const {
  return messages.size() == 4 && messages.count(1) && messages.count(2) && messages.count(3) &&
         messages.count(4);
}

std::vector<int> Handshake::observed() const {
  std::vector<int> out;
  for (const auto& [number, unused] : messages) out.push_back(number);
  return out;
}

std::optional<double> Handshake::duration_ms() const {
  if (!complete()) return std::nullopt;
  return (messages.at(4) - messages.at(1)) * 1000.0;
}

std::vector<std::string> Handshake::notes() const {
  std::vector<std::string> out;
  if (complete()) {
    out.push_back(std::format(
        "complete four-way handshake in {:.1f} ms; an observer who records this and later "
        "guesses the passphrase can derive the PTK and decrypt the session offline",
        *duration_ms()));
  } else {
    std::vector<int> missing;
    for (int n : {1, 2, 3, 4}) {
      if (!messages.count(n)) missing.push_back(n);
    }
    out.push_back(std::format(
        "incomplete: saw messages {}, missing {} (capture may have started late, or the "
        "handshake failed)",
        int_list(observed()), int_list(missing)));
  }
  if (pmkid) {
    out.push_back(std::format(
        "AP volunteered a PMKID ({}...) in message 1; this single frame is enough for an "
        "offline dictionary attack, with no client interaction needed",
        to_hex(*pmkid).substr(0, 16)));
  }
  // Each message should advance or match the AP's replay counter.
  std::vector<std::uint64_t> counters;
  for (int n : observed()) counters.push_back(replay_counters.at(n));
  if (!std::is_sorted(counters.begin(), counters.end())) {
    std::string list = "[";
    for (std::size_t i = 0; i < counters.size(); ++i) {
      if (i) list += ", ";
      list += std::to_string(counters[i]);
    }
    out.push_back("replay counters out of order across messages: " + list +
                  "]; consistent with a replayed or injected EAPOL frame");
  }
  return out;
}

std::optional<int> HandshakeTracker::observe(const EapolKeyFrame& frame,
                                             const std::string& transmitter,
                                             const std::string& receiver, double timestamp,
                                             std::size_t index) {
  const std::optional<int> number = frame.message_number();
  if (!number) return std::nullopt;

  const bool from_ap = *number == 1 || *number == 3;
  const std::string& ap = from_ap ? transmitter : receiver;
  const std::string& station = from_ap ? receiver : transmitter;
  const auto key = std::make_pair(ap, station);

  // A fresh message 1 starts a new session (a rekey or a reconnection) rather
  // than continuing the old one. The previous handshake stays in the list;
  // only the "currently open" slot is replaced.
  auto it = active_.find(key);
  if (it == active_.end() || *number == 1) {
    handshakes_.push_back(Handshake{ap, station, {}, {}, {}, {}, {}, {}});
    active_[key] = handshakes_.size() - 1;
  }
  Handshake& handshake = handshakes_[active_[key]];

  handshake.messages[*number] = timestamp;
  handshake.replay_counters[*number] = frame.replay_counter;
  handshake.frame_indices[*number] = index;
  if (*number == 1) {
    handshake.anonce = frame.nonce;
    handshake.pmkid = frame.pmkid();
  } else if (*number == 2) {
    handshake.snonce = frame.nonce;
  }
  return number;
}

}  // namespace airlock::wifi
