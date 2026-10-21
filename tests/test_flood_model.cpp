// The learned flood model: the C++ side computes features and runs the
// PyTorch scorer, and the detector built on it must keep its guarantees
// whatever the model says, including when the model cannot run at all.
//
// ctest runs each test in its own process, so tests that point the scorer at
// a missing model or interpreter through the environment do not leak.
#include <gtest/gtest.h>

#include <stdlib.h>

#include <algorithm>
#include <string>
#include <vector>

#include "support.hpp"
#include "wifi/anomalies.hpp"
#include "wifi/flood_model.hpp"

using namespace airlock::wifi;
using airlock::testing::contains;

namespace {

FrameInfo disconnect(double time, const std::string& tx, const std::string& rx, int reason = 7) {
  FrameInfo frame;
  frame.timestamp = time;
  frame.subtype_name = "deauthentication";
  frame.addr2 = tx;
  frame.addr1 = rx;
  frame.reason_code = reason;
  return frame;
}

// `count` deauths from an AP to one client, `gap` seconds apart.
Capture burst(int count, double gap = 0.05) {
  Capture capture("burst");
  for (int i = 0; i < count; ++i) {
    capture.frames.push_back(disconnect(i * gap, "02:00:00:aa:00:01", "02:00:00:11:11:11"));
  }
  return capture;
}

std::vector<const FrameInfo*> pointers(const Capture& capture) {
  std::vector<const FrameInfo*> out;
  for (const FrameInfo& f : capture.frames) out.push_back(&f);
  return out;
}

}  // namespace

TEST(FloodModel, PyTorchScorerReturnsOneScorePerSpan) {
  const Capture a = burst(12);
  const Capture b = burst(40, 0.01);
  const FloodScores scored =
      score_flood_spans({flood_features(pointers(a)), flood_features(pointers(b))});
  EXPECT_GT(scored.threshold, 0.0);
  EXPECT_LT(scored.threshold, 1.0);
  ASSERT_EQ(scored.scores.size(), 2u);
  for (const FloodScore& s : scored.scores) {
    EXPECT_GE(s.probability, 0.0);
    EXPECT_LE(s.probability, 1.0);
    for (double a_i : s.attribution) EXPECT_LE(a_i, s.probability + 1e-9);
  }
}

TEST(FloodModel, MissingModelIsReportedNotSilent) {
  FloodModelConfig config = flood_model_config();
  config.model = "/nonexistent/flood-model.pt";
  EXPECT_THROW(score_flood_spans({FloodFeatures{}}, config), FloodModelUnavailable);

  setenv("AIRLOCK_FLOOD_MODEL", "/nonexistent/flood-model.pt", 1);
  const auto findings = detect_deauth_flood(burst(40, 0.01));
  ASSERT_EQ(findings.size(), 1u);
  EXPECT_EQ(findings[0].title, "Flood detection skipped");
  EXPECT_EQ(findings[0].severity, "info");
}

TEST(FloodModel, MissingInterpreterIsReportedNotSilent) {
  setenv("AIRLOCK_PYTHON", "/nonexistent/python3", 1);
  const auto findings = detect_deauth_flood(burst(40, 0.01));
  ASSERT_EQ(findings.size(), 1u);
  EXPECT_EQ(findings[0].title, "Flood detection skipped");
}

TEST(FloodModel, CapturesWithoutCandidateSpansNeverStartPython) {
  // With the interpreter unusable, any attempt to score would surface as a
  // "skipped" finding; a quiet capture must not even try.
  setenv("AIRLOCK_PYTHON", "/nonexistent/python3", 1);
  EXPECT_TRUE(detect_deauth_flood(burst(FLOOD_MIN_FRAMES - 1)).empty());
}

TEST(FloodModel, FeaturesDoNotDependOnFrameOrder) {
  Capture capture = burst(12);
  capture.frames[3].reason_code = 1;
  auto frames = pointers(capture);
  const FloodFeatures forward = flood_features(frames);
  std::reverse(frames.begin(), frames.end());
  EXPECT_EQ(flood_features(frames), forward);
}

TEST(FloodModel, FeaturesSeeTargetingAndReasons) {
  Capture unicast = burst(10);
  Capture broadcast = burst(10);
  for (FrameInfo& f : broadcast.frames) f.addr1 = "ff:ff:ff:ff:ff:ff";
  broadcast.frames[0].reason_code = 1;
  const FloodFeatures a = flood_features(pointers(unicast));
  const FloodFeatures b = flood_features(pointers(broadcast));
  EXPECT_EQ(a[3], 0.0f);  // group-addressed target
  EXPECT_EQ(b[3], 1.0f);
  EXPECT_LT(a[5], b[5]);  // distinct reason codes
}

TEST(FloodModel, SpansAtTheRetryLimitAreNeverReported) {
  // One unacknowledged deauth plus its seven retransmissions is eight frames.
  // Even with the threshold at zero, that must not be called a flood.
  EXPECT_TRUE(detect_deauth_flood(burst(FLOOD_MIN_FRAMES - 1), 0.0).empty());
  EXPECT_EQ(detect_deauth_flood(burst(FLOOD_MIN_FRAMES), 0.0).size(), 1u);
}

TEST(FloodModel, OnlyTheDensestSpanCounts) {
  // Twenty deauths spread over a minute never put nine inside five seconds.
  EXPECT_TRUE(detect_deauth_flood(burst(20, 3.0), 0.0).empty());
}

TEST(FloodModel, FindingsCarryTheModelsEvidence) {
  const auto findings = detect_deauth_flood(burst(40, 0.01), 0.0);
  ASSERT_EQ(findings.size(), 1u);
  std::string evidence;
  for (const std::string& line : findings[0].evidence) evidence += line + "\n";
  EXPECT_TRUE(contains(evidence, "learned flood model: attack probability"));
  EXPECT_TRUE(contains(evidence, "strongest evidence:"));
}
