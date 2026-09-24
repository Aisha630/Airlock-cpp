// Every adversary simulation must land the way the README claims it does.
#include <gtest/gtest.h>

#include <string>

#include "akex/attacks.hpp"
#include "support.hpp"

using namespace airlock::akex;
using airlock::testing::contains;

TEST(Attacks, EveryDefendedAttackIsBlocked) {
  for (const AttackResult& result : run_all()) {
    if (contains(result.name, "UNAUTHENTICATED")) continue;
    EXPECT_TRUE(result.defended) << result.name << " was not blocked";
  }
}

TEST(Attacks, TheUnauthenticatedControlSucceeds) {
  // If this ever starts failing, the control has stopped being a control.
  //
  // The point of the demo is the contrast between the two
  // machine-in-the-middle runs. A control that silently stopped working would
  // make the authenticated result look meaningful when it was not.
  int controls = 0;
  for (const AttackResult& result : run_all()) {
    if (!contains(result.name, "UNAUTHENTICATED")) continue;
    ++controls;
    EXPECT_FALSE(result.defended);
  }
  EXPECT_EQ(controls, 1);
}

namespace {

class EachAttack : public ::testing::TestWithParam<Attack> {};

TEST_P(EachAttack, ReportsAMechanism) {
  // Every result explains itself; a bare pass/fail is not a finding.
  const AttackResult result = GetParam().run();
  EXPECT_FALSE(result.detail.empty());
  EXPECT_FALSE(result.defense.empty());
  const std::string rendered = result.render();
  EXPECT_TRUE(contains(rendered, "BLOCKED") || contains(rendered, "SUCCEEDED"));
}

INSTANTIATE_TEST_SUITE_P(All, EachAttack, ::testing::ValuesIn(attacks()),
                         [](const auto& info) { return std::string(info.param.id); });

}  // namespace
