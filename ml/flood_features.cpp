// Extract flood-model features through the production library, for training.
//
// Input is the labeled replay format written by ml/prepare.py: a WINDOW line
// per five-second window, then one line per disconnect frame (timestamp,
// transmitter, receiver, subtype, protected, reason, attack label). Output is
// one row per (window, transmitter, receiver) group with its frame count,
// attack-labeled frame count, features and the current model's probability.
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "wifi/flood_model.hpp"

using namespace airlock::wifi;

std::vector<std::string> fields(const std::string& line) {
  std::vector<std::string> out;
  std::istringstream stream(line);
  std::string field;
  while (std::getline(stream, field, '\t')) out.push_back(field);
  return out;
}

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  std::ifstream input(argv[1]);
  if (!input) throw std::runtime_error("Cannot read input");

  std::cout << "window\ttransmitter\treceiver\tframes\tattack_frames";
  for (std::string_view name : flood_feature_names()) std::cout << '\t' << name;
  std::cout << "\tprobability\n";

  std::string window;
  std::vector<FrameInfo> frames;
  std::vector<bool> attack;
  auto emit = [&]() {
    std::map<std::pair<std::string, std::string>, std::vector<std::size_t>> groups;
    for (std::size_t i = 0; i < frames.size(); ++i) {
      groups[{frames[i].addr2.value_or("-"), frames[i].addr1.value_or("-")}].push_back(i);
    }
    for (const auto& [key, members] : groups) {
      std::vector<const FrameInfo*> group;
      std::size_t attacks = 0;
      for (std::size_t i : members) {
        group.push_back(&frames[i]);
        attacks += attack[i];
      }
      const FloodFeatures features = flood_features(group);
      std::cout << window << '\t' << key.first << '\t' << key.second << '\t' << group.size()
                << '\t' << attacks;
      for (float value : features) std::cout << '\t' << std::format("{:.9g}", value);
      std::cout << '\t' << std::format("{:.9g}", flood_probability(features)) << '\n';
    }
    frames.clear();
    attack.clear();
  };

  std::string line;
  while (std::getline(input, line)) {
    auto parts = fields(line);
    if (parts.at(0) == "WINDOW") {
      emit();
      window = parts.at(1);
      continue;
    }
    FrameInfo frame;
    frame.timestamp = std::stod(parts.at(0));
    if (parts.at(1) != "-") frame.addr2 = parts.at(1);
    if (parts.at(2) != "-") frame.addr1 = parts.at(2);
    frame.subtype_name = parts.at(3) == "12" ? "deauthentication" : "disassociation";
    frame.is_protected = parts.at(4) == "1";
    if (parts.at(5) != "-") frame.reason_code = std::stoi(parts.at(5));
    frames.push_back(std::move(frame));
    attack.push_back(parts.at(6) == "1");
  }
  emit();
}
