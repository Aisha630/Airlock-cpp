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
// features. Inference runs in PyTorch itself: the analyzer computes features
// here and hands them to ml/score.py, which loads the model ml/train.py saved
// and returns a probability and an explanation for each span. The model is
// consulted only when a capture contains a span worth scoring, so most
// analyses never start Python.
//
// The features below are the single definition used both to train the model
// and to run it: the training pipeline extracts them through this library
// rather than reimplementing them in Python, so the two cannot drift apart.
#pragma once

#include <array>
#include <cstddef>
#include <stdexcept>
#include <string>
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

// Where the scorer lives. The defaults point into this source tree;
// AIRLOCK_PYTHON and AIRLOCK_FLOOD_MODEL override the interpreter and the
// model file.
struct FloodModelConfig {
  std::string python;
  std::string script;
  std::string model;
};
FloodModelConfig flood_model_config();

// The model's verdict on one span.
struct FloodScore {
  // Probability that the span is an attack, in [0, 1].
  double probability = 0.0;
  // How much each feature pushed this prediction up: the drop in probability
  // when that feature alone is reset to its training mean. Positive values
  // argue for "attack", so a finding can say why it fired rather than only
  // that it did.
  std::array<double, FLOOD_FEATURE_COUNT> attribution{};
};

struct FloodScores {
  // Probability at or above which a span is reported, chosen on held-out
  // training data by ml/train.py and saved with the model.
  double threshold = 1.0;
  std::vector<FloodScore> scores;  // one per input span, in order
};

// The scorer could not run: no interpreter, no PyTorch, no model file, or
// output that does not parse. The message says which.
class FloodModelUnavailable : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Score spans with the PyTorch model by running the scorer once for all of
// them. The interpreter is started directly, never through a shell, and in
// isolated mode (-I), so neither a crafted path nor the environment's
// PYTHONPATH can change what runs. Throws FloodModelUnavailable.
FloodScores score_flood_spans(const std::vector<FloodFeatures>& spans,
                              const FloodModelConfig& config = flood_model_config());

}  // namespace airlock::wifi
