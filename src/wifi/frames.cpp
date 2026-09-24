#include "wifi/frames.hpp"

#include <cctype>
#include <string>
#include <vector>

namespace airlock::wifi {
namespace {

const std::map<int, std::string>& management_subtypes() {
  static const std::map<int, std::string> table = {
      {0, "assoc-request"},  {1, "assoc-response"},   {2, "reassoc-request"},
      {3, "reassoc-response"}, {4, "probe-request"},  {5, "probe-response"},
      {6, "timing-advertisement"}, {8, "beacon"},     {9, "atim"},
      {10, "disassociation"}, {11, "authentication"}, {12, "deauthentication"},
      {13, "action"},        {14, "action-no-ack"},
  };
  return table;
}

const std::map<int, std::string>& control_subtypes() {
  static const std::map<int, std::string> table = {
      {2, "trigger"},
      {4, "beamforming-report-poll"},
      {5, "vht-he-ndp-announcement"},
      {6, "control-frame-extension"},
      {7, "control-wrapper"},
      {8, "block-ack-request"},
      {9, "block-ack"},
      {10, "ps-poll"},
      {11, "rts"},
      {12, "cts"},
      {13, "ack"},
      {14, "cf-end"},
      {15, "cf-end-cf-ack"},
  };
  return table;
}

const std::map<int, std::string>& data_subtypes() {
  static const std::map<int, std::string> table = {
      {0, "data"},          {1, "data-cf-ack"},          {2, "data-cf-poll"},
      {3, "data-cf-ack-poll"}, {4, "null"},              {5, "cf-ack"},
      {6, "cf-poll"},       {7, "cf-ack-poll"},          {8, "qos-data"},
      {9, "qos-data-cf-ack"}, {10, "qos-data-cf-poll"}, {11, "qos-data-cf-ack-poll"},
      {12, "qos-null"},     {14, "qos-cf-poll"},         {15, "qos-cf-ack-poll"},
  };
  return table;
}

}  // namespace

const std::map<int, std::string>& type_names() {
  static const std::map<int, std::string> table = {
      {TYPE_MANAGEMENT, "management"},
      {TYPE_CONTROL, "control"},
      {TYPE_DATA, "data"},
      {TYPE_EXTENSION, "extension"},
  };
  return table;
}

std::string type_name(int frame_type) {
  auto it = type_names().find(frame_type);
  return it != type_names().end() ? it->second : "type-" + std::to_string(frame_type);
}

std::string subtype_name(int frame_type, int subtype) {
  const std::map<int, std::string>* table = nullptr;
  if (frame_type == TYPE_MANAGEMENT) table = &management_subtypes();
  if (frame_type == TYPE_CONTROL) table = &control_subtypes();
  if (frame_type == TYPE_DATA) table = &data_subtypes();
  if (table != nullptr) {
    auto it = table->find(subtype);
    if (it != table->end()) return it->second;
  }
  return "subtype-" + std::to_string(subtype);
}

const std::map<int, std::string>& reason_codes() {
  static const std::map<int, std::string> table = {
      {1, "unspecified"},
      {2, "previous authentication no longer valid"},
      {3, "deauthenticated because sending STA is leaving"},
      {4, "disassociated due to inactivity"},
      {5, "disassociated because AP is out of resources"},
      {6, "class 2 frame received from nonauthenticated STA"},
      {7, "class 3 frame received from nonassociated STA"},
      {8, "disassociated because sending STA is leaving"},
      {9, "STA requesting association is not authenticated"},
      {15, "4-way handshake timeout"},
      {16, "group key handshake timeout"},
      {23, "IEEE 802.1X authentication failed"},
  };
  return table;
}

const std::map<int, std::string>& status_codes() {
  static const std::map<int, std::string> table = {
      {0, "success"},
      {1, "unspecified failure"},
      {17, "association denied: too many STAs"},
      {43, "invalid pairwise cipher"},
      {53, "invalid PMKID"},
      {76, "authentication rejected: anti-clogging token required"},
      {77, "authentication rejected: unsupported finite cyclic group"},
  };
  return table;
}

std::string reason_text(int code) {
  auto it = reason_codes().find(code);
  return it != reason_codes().end() ? it->second : "unknown";
}

bool FrameInfo::transmitter_is_valid() const {
  if (!addr2 || addr2->empty()) return true;  // ACK and CTS legitimately carry no addr2
  const std::string first = addr2->substr(0, addr2->find(':'));
  if (first.empty()) return false;
  for (char c : first) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
  }
  // The Individual/Group bit is the low bit of the octet, so only the last
  // hex digit decides it.
  const char last = static_cast<char>(std::tolower(static_cast<unsigned char>(first.back())));
  const int value = last <= '9' ? last - '0' : last - 'a' + 10;
  return (value & 0x01) == 0;
}

std::string FrameInfo::describe() const {
  std::vector<std::string> parts = {type_name + "/" + subtype_name};
  if (ssid) parts.push_back("ssid=\"" + *ssid + "\"");
  if (transmitter() && !transmitter()->empty()) parts.push_back("from " + *transmitter());
  if (receiver() && !receiver()->empty()) parts.push_back("to " + *receiver());
  if (is_protected) parts.push_back("protected");
  if (reason_code) {
    parts.push_back("reason=" + std::to_string(*reason_code) + " (" + reason_text(*reason_code) +
                    ")");
  }
  std::string out;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i) out += ' ';
    out += parts[i];
  }
  return out;
}

}  // namespace airlock::wifi
