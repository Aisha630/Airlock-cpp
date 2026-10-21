// A learned classifier for deauthentication / disassociation floods.
//
// The flood detector used to be a fixed rule: eight disconnect frames from one
// source to one destination inside five seconds. That rule has one number to
// tune and no way to weigh anything else it sees, and on AWID2 it fires on
// dataset-labeled normal bursts. This replaces the rule with a small neural
// network trained in PyTorch on labeled AWID2 and AWID3 traffic. ml/README.md
// has the training protocol, the results against the rule, and the dataset
// shortcuts that earlier versions of this model learned.
//
// The network is tiny, one hidden layer over a handful of header-derived
// features. ml/train.py exports its weights as constant arrays in
// flood_model_weights.inc, and the forward pass is written by hand in
// flood_model.cpp, so the analyzer needs neither LibTorch nor any other
// inference runtime. Tests check it against PyTorch's own outputs.
//
// The features below are the single definition used both to train the model
// and to run it: the training pipeline extracts them through this library
// rather than reimplementing them in Python, so the two cannot drift apart.
#pragma once

#include <array>
#include <cstddef>
#include <string_view>
#include <vector>

#include "wifi/frames.hpp"

namespace airlock::wifi {

// The span of traffic the model scores: the densest stretch of this length in
// one (source, destination) group of disconnect frames.
inline constexpr double FLOOD_SPAN_SECONDS = 5.0;

// Spans with fewer frames are never scored. An unacknowledged unicast frame
// is retransmitted up to dot11ShortRetryLimit (7) times, so one ordinary
// disconnect can appear as eight captured frames; only more than that is
// evidence of more than one disconnect. This is a floor from the standard,
// not a tuned threshold: it was fixed before evaluating its effect, after
// the model, which AWID's labels had taught that a two-frame disconnect can
// be an attack, called three forged deauths a flood. The model still learns
// from smaller groups, which hold nearly all of the datasets' benign
// disconnects; the floor only limits what is reported.
inline constexpr std::size_t FLOOD_MIN_FRAMES = 9;

inline constexpr std::size_t FLOOD_FEATURE_COUNT = 10;
using FloodFeatures = std::array<float, FLOOD_FEATURE_COUNT>;

// Human-readable names, in feature order, for evidence and for training.
const std::array<std::string_view, FLOOD_FEATURE_COUNT>& flood_feature_names();

// Features of one span of disconnect frames from a single (source,
// destination) pair. Frames need not be sorted. Counts and durations are
// log-scaled so that a 10,000-frame flood does not dwarf everything else.
//
// MAC addresses, specific reason codes and the deauthentication /
// disassociation split are deliberately not features: a model allowed to see
// them learns the attack tool, the testbed hardware or which of two
// equivalent disconnect frames its training data happened to contain, rather
// than the behaviour. The last was learned in practice: trained with AWID3's
// deauthentication attacks, a model with that feature missed most of AWID3's
// disassociation attacks.
FloodFeatures flood_features(const std::vector<const FrameInfo*>& frames);

// The model's probability that the span is an attack, in [0, 1].
double flood_probability(const FloodFeatures& features);

// Probability at or above which a span is reported. Chosen on held-out
// training data by ml/train.py and compiled in with the weights.
double flood_threshold();

// How much each feature pushed this prediction up: the drop in probability
// when that feature alone is reset to its training mean. Positive values
// argue for "attack". A cheap, model-agnostic explanation, so a finding can
// say why it fired rather than only that it did.
std::array<double, FLOOD_FEATURE_COUNT> flood_attribution(const FloodFeatures& features);

// Fixed (features, expected probability) pairs computed by PyTorch at export
// time, so the test suite can check that C++ inference matches training.
struct FloodParityCase {
  FloodFeatures features;
  double probability;
};
const std::vector<FloodParityCase>& flood_parity_cases();

}  // namespace airlock::wifi
