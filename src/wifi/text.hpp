// Text helpers for the analyzer's reports.
//
// SSIDs are arbitrary bytes that come off the air, so they are decoded
// defensively. The report formatting also follows a few fixed conventions
// (how a missing value prints, how a float is written in JSON) so that the
// text and JSON output are stable across runs and platforms.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "common/bytes.hpp"

namespace airlock::wifi {

// Decode bytes as UTF-8, replacing each maximal invalid subsequence with
// U+FFFD as the Unicode standard recommends. Never throws.
std::string decode_utf8_lossy(ByteView raw);

// Number of code points in a UTF-8 string, which is its width on a terminal
// for the text this analyzer prints.
std::size_t display_width(const std::string& text);

// An optional string for display: the value, or "None" when absent.
std::string or_none(const std::optional<std::string>& value);
std::string or_none(const std::optional<int>& value);

// A quoted, escaped rendering of an optional string, 'like this' (or "None").
std::string quoted_repr(const std::optional<std::string>& value);

// "[1, 2, 3]"
std::string int_list(const std::vector<int>& values);
std::string join(const std::vector<std::string>& parts, const std::string& separator);

// The shortest decimal string that round-trips to `value`, always with a
// decimal point or exponent ("3.1", "21.0", "1e-05").
std::string shortest_float(double value);

// `value` rounded half-to-even at `digits` decimal places, computed on the
// exact binary value so the result is the double nearest the rounded decimal.
double round_to(double value, int digits);

}  // namespace airlock::wifi
