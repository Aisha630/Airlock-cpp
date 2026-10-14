// Run the production flood detector on metadata extracted from AWID3 CSVs.
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include "wifi/anomalies.hpp"

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
  Capture capture("AWID3 metadata");
  std::string line;
  std::string id;
  bool attack = false;
  auto emit = [&]() {
    if (id.empty()) return;
    auto findings = detect_deauth_flood(capture);
    std::cout << id << '\t' << attack << '\t' << findings.size() << '\n';
    capture.frames.clear();
  };
  while (std::getline(input, line)) {
    auto parts = fields(line);
    if (parts.at(0) == "WINDOW") {
      emit();
      id = parts.at(1);
      attack = parts.at(2) == "1";
      continue;
    }
    FrameInfo frame;
    frame.timestamp = std::stod(parts.at(0));
    frame.addr2 = parts.at(1) == "-" ? std::optional<std::string>{} : parts.at(1);
    frame.addr1 = parts.at(2) == "-" ? std::optional<std::string>{} : parts.at(2);
    frame.subtype_name = parts.at(3) == "12" ? "deauthentication" : "disassociation";
    frame.is_protected = parts.at(4) == "1";
    if (parts.at(5) != "-") frame.reason_code = std::stoi(parts.at(5));
    capture.frames.push_back(std::move(frame));
  }
  emit();
}
