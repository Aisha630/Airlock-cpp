// The analyzer's report, as text for a person and JSON for a pipeline.
#pragma once

#include <string>
#include <vector>

#include "wifi/anomalies.hpp"
#include "wifi/capture.hpp"
#include "wifi/eapol.hpp"

namespace airlock::wifi {

// Feed every EAPOL-Key frame through the handshake tracker in order.
HandshakeTracker track_handshakes(const Capture& capture);

std::vector<std::string> report_overview(const Capture& capture);
// The management / control / data breakdown. This is the headline table: it
// is the part of the traffic that stays readable however strong the
// encryption is.
std::vector<std::string> report_frame_classes(const Capture& capture);
std::vector<std::string> report_networks(const Capture& capture);
// Walk the management exchanges that bring a client onto a network.
std::vector<std::string> report_association(const Capture& capture);
std::vector<std::string> report_handshakes(const Capture& capture,
                                           const HandshakeTracker& tracker);
std::vector<std::string> report_findings(const std::vector<Finding>& findings);

// Every section, joined into the full text report.
std::string render_report(const Capture& capture, const HandshakeTracker& tracker,
                          const std::vector<Finding>& findings);

// Machine-readable form of the same report.
std::string build_json(const Capture& capture, const HandshakeTracker& tracker,
                       const std::vector<Finding>& findings);

}  // namespace airlock::wifi
