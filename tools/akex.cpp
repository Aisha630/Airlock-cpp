// Command line entry point for the key exchange.
//
//     akex handshake [--psk TEXT] [--group {14,15}]   run a handshake and use the session
//     akex attacks                                     run every adversary simulation
#include <algorithm>
#include <cstdio>
#include <exception>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "akex/attacks.hpp"
#include "akex/channel.hpp"
#include "akex/params.hpp"
#include "akex/protocol.hpp"
#include "akex/wire.hpp"

using namespace airlock;
using namespace airlock::akex;

namespace {

constexpr const char* USAGE =
    "usage: akex {handshake,attacks} ...\n"
    "\n"
    "Authenticated Diffie-Hellman key exchange demo.\n"
    "\n"
    "commands:\n"
    "  handshake [--psk TEXT] [--group {14,15}]  run one handshake and use the session\n"
    "  attacks                                   run every adversary simulation\n";

std::string rule(std::string_view title) {
  return std::format("\n{}\n{}", title, std::string(title.size(), '-'));
}

std::string head_hex(ByteView data, std::size_t count) {
  return to_hex(data.first(std::min(count, data.size())));
}

// Python-style bytes literal, so a payload prints the way it was written.
std::string bytes_literal(ByteView data) {
  const bool has_single = std::find(data.begin(), data.end(), '\'') != data.end();
  const bool has_double = std::find(data.begin(), data.end(), '"') != data.end();
  const char quote = has_single && !has_double ? '"' : '\'';
  std::string out = "b";
  out.push_back(quote);
  for (std::uint8_t c : data) {
    if (c == '\\' || c == quote) {
      out += '\\';
      out += static_cast<char>(c);
    } else if (c == '\t') {
      out += "\\t";
    } else if (c == '\n') {
      out += "\\n";
    } else if (c == '\r') {
      out += "\\r";
    } else if (c < 0x20 || c >= 0x7f) {
      out += std::format("\\x{:02x}", c);
    } else {
      out += static_cast<char>(c);
    }
  }
  out.push_back(quote);
  return out;
}

// Run one handshake message by message, printing the wire exchange.
int cmd_handshake(const std::string& psk_text, int group_id) {
  const DHGroup& group = get_group(group_id);
  const Bytes psk = to_bytes(psk_text);
  Initiator initiator(psk, group);
  Responder responder(psk, group);

  std::cout << rule("AKEX handshake") << "\n";
  std::cout << std::format("group:  MODP-{} (id {})\n", group.bits, group.group_id);
  std::cout << std::format("psk:    {} bytes\n", psk.size());

  const InitMessage init = initiator.start();
  Bytes on_wire = init.encode();
  std::cout << std::format("\n  1. I -> R  init      {:>4} bytes  nonce_i={}...  g^i={}...\n",
                           on_wire.size(), head_hex(init.nonce_i, 8), head_hex(init.pub_i, 8));

  // Decode from bytes at each hop: the parties only ever see the wire form.
  auto [response, unused] = responder.respond(InitMessage::decode(on_wire));
  on_wire = response.encode();
  std::cout << std::format("  2. R -> I  response  {:>4} bytes  nonce_r={}...  tag_r={}...\n",
                           on_wire.size(), head_hex(response.nonce_r, 8),
                           head_hex(response.tag_r, 8));

  auto [confirm, initiator_keys] = initiator.finish(ResponseMessage::decode(on_wire));
  on_wire = confirm.encode();
  std::cout << std::format("  3. I -> R  confirm   {:>4} bytes  tag_i={}...\n", on_wire.size(),
                           head_hex(confirm.tag_i, 8));

  const SessionKeys responder_keys = responder.confirm(ConfirmMessage::decode(on_wire));

  std::cout << rule("Derived keys") << "\n";
  if (initiator_keys != responder_keys) {
    std::cout << "MISMATCH: the two sides derived different keys\n";
    return 1;
  }
  std::cout << "both sides agree; session fingerprint " << initiator_keys.fingerprint() << "\n";
  const std::pair<const char*, const Bytes*> labelled[] = {
      {"auth_i      ", &initiator_keys.auth_i},
      {"auth_r      ", &initiator_keys.auth_r},
      {"session_i2r ", &initiator_keys.session_i2r},
      {"session_r2i ", &initiator_keys.session_r2i},
  };
  for (const auto& [label, key] : labelled) {
    // First bytes only. Enough to show the keys differ, not enough to be a
    // habit worth forming with real key material.
    std::cout << std::format("  {} {}...  ({} bits)\n", label, head_hex(*key, 12),
                             key->size() * 8);
  }

  std::cout << rule("Authenticated session") << "\n";
  auto sender = AuthenticatedChannel::for_initiator(initiator_keys);
  auto receiver = AuthenticatedChannel::for_responder(responder_keys);
  for (const char* text : {"application message one", "application message two"}) {
    const Bytes record = sender.seal(to_bytes(text));
    const Bytes delivered = receiver.open_record(record);
    std::cout << std::format("  seq {}: {:>3} bytes on the wire -> {} verified\n",
                             receiver.recv_seq() - 1, record.size(), bytes_literal(delivered));
  }
  std::cout << "\nnote: this channel authenticates, it does not encrypt (see channel.hpp)\n";
  return 0;
}

// Run the adversary simulations and summarise.
int cmd_attacks() {
  std::cout << rule("Adversary simulations") << "\n";
  const std::vector<AttackResult> results = run_all();
  for (const AttackResult& result : results) {
    std::cout << "\n" << result.render() << "\n";
  }

  // Two of the nine scenarios are controls, not attacks, and neither belongs
  // in the pass count. The honest handshake must succeed, and the
  // unauthenticated-DH machine-in-the-middle must win: that one is the
  // evidence that the tags in the other scenarios are doing the work.
  auto is_control = [](const AttackResult& r) {
    return r.name.find("(control)") != std::string::npos;
  };
  std::vector<const AttackResult*> controls, blocked, unblocked;
  std::size_t attack_count = 0;
  for (const AttackResult& r : results) {
    if (is_control(r)) {
      controls.push_back(&r);
      continue;
    }
    ++attack_count;
    (r.defended ? blocked : unblocked).push_back(&r);
  }

  std::cout << rule("Summary") << "\n";
  std::cout << std::format("{}/{} attacks blocked by AKEX\n", blocked.size(), attack_count);
  for (const AttackResult* failure : unblocked) {
    std::cout << "  UNBLOCKED: " << failure->name << "\n";
  }

  std::cout << std::format("\n{} controls (excluded from the count above):\n", controls.size());
  bool baseline_ok = true;
  const AttackResult* mitm_control = nullptr;
  for (const AttackResult* r : controls) {
    if (r->name.find("Honest") != std::string::npos) baseline_ok = baseline_ok && r->defended;
    if (r->name.find("UNAUTHENTICATED") != std::string::npos && mitm_control == nullptr) {
      mitm_control = r;
    }
  }
  std::cout << "  honest handshake completed and agreed keys: "
            << (baseline_ok ? "yes" : "NO -- the protocol itself is broken") << "\n";
  if (mitm_control != nullptr) {
    std::cout << "  the same MITM against unauthenticated DH succeeded: "
              << (!mitm_control->defended ? "yes, as expected"
                                          : "NO -- the control is not working")
              << "\n";
  }
  return unblocked.empty() ? 0 : 1;
}

int usage_error(const std::string& message) {
  std::cerr << USAGE << "akex: error: " << message << "\n";
  return 2;
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
    if (args[0] == "handshake") {
      std::string psk = "example pre-shared key";
      int group_id = 14;
      for (std::size_t i = 1; i < args.size(); ++i) {
        const std::string& arg = args[i];
        if ((arg == "--psk" || arg == "--group") && i + 1 >= args.size()) {
          return usage_error("argument " + arg + ": expected one argument");
        }
        if (arg == "--psk") {
          psk = args[++i];
        } else if (arg == "--group") {
          const std::string& value = args[++i];
          if (value != "14" && value != "15") {
            return usage_error("argument --group: invalid choice: '" + value +
                               "' (choose from 14, 15)");
          }
          group_id = std::stoi(value);
        } else if (arg == "-h" || arg == "--help") {
          std::cout << USAGE;
          return 0;
        } else {
          return usage_error("unrecognized arguments: " + arg);
        }
      }
      return cmd_handshake(psk, group_id);
    }
    if (args[0] == "attacks") {
      if (args.size() > 1) return usage_error("unrecognized arguments: " + args[1]);
      return cmd_attacks();
    }
    return usage_error("argument command: invalid choice: '" + args[0] +
                       "' (choose from handshake, attacks)");
  } catch (const std::exception& exc) {
    std::cerr << "akex: " << exc.what() << "\n";
    return 1;
  }
}
