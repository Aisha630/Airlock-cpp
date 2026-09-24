// Command line 802.11 capture analyzer.
//
//     wifi analyze captures/synthetic.pcap
//     wifi analyze capture.pcap --json report.json [--fail-on-high]
//     wifi synth captures/synthetic.pcap
#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "wifi/anomalies.hpp"
#include "wifi/capture.hpp"
#include "wifi/report.hpp"
#include "wifi/synth.hpp"

using namespace airlock::wifi;

namespace {

constexpr const char* USAGE =
    "usage: wifi {analyze,synth} ...\n"
    "\n"
    "802.11 capture analyzer: classification, security posture, anomalies.\n"
    "\n"
    "commands:\n"
    "  analyze PCAP [--json PATH] [--fail-on-high]  analyze a pcap/pcapng of 802.11 frames\n"
    "  synth [OUTPUT]                               generate the synthetic capture\n";

int usage_error(const std::string& message) {
  std::cerr << USAGE << "wifi: error: " << message << "\n";
  return 2;
}

int cmd_analyze(const std::string& pcap, const std::optional<std::string>& json_path,
                bool fail_on_high) {
  const Capture capture = load_capture(pcap);
  const HandshakeTracker tracker = track_handshakes(capture);
  const std::vector<Finding> findings = run_all_detectors(capture, tracker.all());

  std::cout << render_report(capture, tracker, findings);

  if (json_path) {
    std::ofstream out(*json_path);
    if (!out) throw std::runtime_error("cannot write " + *json_path);
    out << build_json(capture, tracker, findings);
    std::cout << "\nJSON report written to " << *json_path << "\n";
  }

  // A non-zero exit on high-severity findings makes this usable as a check
  // in a pipeline, not just as something a person reads.
  std::size_t high = 0;
  for (const Finding& f : findings) high += f.severity == "high";
  if (high && fail_on_high) {
    std::cout << "\n" << high << " high-severity findings\n";
    return 1;
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> args(argv + 1, argv + argc);
  if (args.empty()) return usage_error("the following arguments are required: command");
  if (args[0] == "-h" || args[0] == "--help") {
    std::cout << USAGE;
    return 0;
  }

  try {
    if (args[0] == "analyze") {
      std::optional<std::string> pcap, json_path;
      bool fail_on_high = false;
      for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--json") {
          if (i + 1 >= args.size()) return usage_error("argument --json: expected one argument");
          json_path = args[++i];
        } else if (args[i] == "--fail-on-high") {
          fail_on_high = true;
        } else if (args[i] == "-h" || args[i] == "--help") {
          std::cout << USAGE;
          return 0;
        } else if (!pcap && !args[i].starts_with("--")) {
          pcap = args[i];
        } else {
          return usage_error("unrecognized arguments: " + args[i]);
        }
      }
      if (!pcap) return usage_error("the following arguments are required: pcap");
      return cmd_analyze(*pcap, json_path, fail_on_high);
    }
    if (args[0] == "synth") {
      if (args.size() > 2) return usage_error("unrecognized arguments: " + args[2]);
      const std::string output = args.size() == 2 ? args[1] : "captures/synthetic.pcap";
      const std::size_t count = synth::write_capture(output);
      std::cout << "wrote " << count << " synthetic frames to " << output << "\n";
      return 0;
    }
    return usage_error("argument command: invalid choice: '" + args[0] +
                       "' (choose from analyze, synth)");
  } catch (const std::exception& exc) {
    std::cerr << "wifi: " << exc.what() << "\n";
    return 1;
  }
}
