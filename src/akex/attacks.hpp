// Adversary simulations against AKEX.
//
// Each function plays one attack and returns a short verdict. The point is not
// that the attacks fail: it is that the reason each one fails maps to one
// specific design decision, and that removing that decision makes the attack
// succeed. `mitm_unauthenticated_dh` is the control: the same
// machine-in-the-middle, run against a key exchange with the authentication
// taken out, and it wins.
#pragma once

#include <string>
#include <vector>

namespace airlock::akex {

// Outcome of one simulated attack.
struct AttackResult {
  std::string name;
  bool defended = false;
  std::string detail;
  std::string defense;

  std::string render() const;
};

AttackResult baseline();
AttackResult wrong_psk();
AttackResult tamper_with_transcript();
AttackResult tamper_with_record();
AttackResult replay_record();
AttackResult mitm_against_akex();
AttackResult invalid_public_key();
AttackResult group_downgrade();
AttackResult mitm_unauthenticated_dh();

struct Attack {
  const char* id;
  AttackResult (*run)();
};

// Every simulation, in the order they are reported.
const std::vector<Attack>& attacks();

std::vector<AttackResult> run_all();

}  // namespace airlock::akex
