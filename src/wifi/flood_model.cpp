#include "wifi/flood_model.hpp"

#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <optional>
#include <set>
#include <sstream>
#include <string>

extern char** environ;

namespace airlock::wifi {
namespace {

// The Individual/Group bit is the low bit of the first octet.
bool is_group_address(const std::optional<std::string>& address) {
  if (!address || address->size() < 2) return false;
  int first = 0;
  const char* begin = address->data();
  const auto [end, error] = std::from_chars(begin, begin + 2, first, 16);
  return error == std::errc{} && end == begin + 2 && (first & 1) != 0;
}

double share(std::size_t part, std::size_t whole) {
  return whole == 0 ? 0.0 : static_cast<double>(part) / static_cast<double>(whole);
}

// Peak number of `times` (sorted) inside any `window`-second span.
std::size_t peak_within(const std::vector<double>& times, double window) {
  std::size_t best = 0;
  std::size_t left = 0;
  for (std::size_t right = 0; right < times.size(); ++right) {
    while (times[right] - times[left] > window) ++left;
    best = std::max(best, right - left + 1);
  }
  return best;
}

}  // namespace

const std::array<std::string_view, FLOOD_FEATURE_COUNT>& flood_feature_names() {
  static const std::array<std::string_view, FLOOD_FEATURE_COUNT> names = {
      "frame count (log)",
      "peak frames in any 1 s (log)",
      "protected share",
      "group-addressed target",
      "transmitter missing",
      "distinct reason codes (log)",
      "reason code missing share",
      "median gap in ms (log)",
      "gap irregularity",
      "span occupied",
  };
  return names;
}

FloodFeatures flood_features(const std::vector<const FrameInfo*>& frames) {
  FloodFeatures out{};
  const std::size_t n = frames.size();
  if (n == 0) return out;

  std::vector<double> times;
  std::set<int> reasons;
  std::size_t protected_count = 0, no_reason = 0;
  for (const FrameInfo* f : frames) {
    times.push_back(f->timestamp);
    if (f->is_protected) ++protected_count;
    if (f->reason_code) {
      reasons.insert(*f->reason_code);
    } else {
      ++no_reason;
    }
  }
  std::sort(times.begin(), times.end());

  double median_gap_ms = 0.0, irregularity = 0.0;
  if (n >= 2) {
    std::vector<double> gaps;
    for (std::size_t i = 1; i < n; ++i) gaps.push_back((times[i] - times[i - 1]) * 1000.0);
    std::vector<double> sorted = gaps;
    std::nth_element(sorted.begin(), sorted.begin() + sorted.size() / 2, sorted.end());
    median_gap_ms = sorted[sorted.size() / 2];
    if (gaps.size() >= 2) {
      double mean = 0.0;
      for (double g : gaps) mean += g;
      mean /= static_cast<double>(gaps.size());
      double variance = 0.0;
      for (double g : gaps) variance += (g - mean) * (g - mean);
      variance /= static_cast<double>(gaps.size());
      // Coefficient of variation: a tool sending on a timer is regular, a
      // client reacting to events is not. Capped so one outlier cannot
      // dominate the input.
      irregularity = mean > 0.0 ? std::min(std::sqrt(variance) / mean, 10.0) : 0.0;
    }
  }

  const FrameInfo& first = *frames.front();
  out[0] = static_cast<float>(std::log1p(static_cast<double>(n)));
  out[1] = static_cast<float>(std::log1p(static_cast<double>(peak_within(times, 1.0))));
  out[2] = static_cast<float>(share(protected_count, n));
  out[3] = is_group_address(first.receiver()) ? 1.0f : 0.0f;
  out[4] = first.transmitter() && !first.transmitter()->empty() ? 0.0f : 1.0f;
  out[5] = static_cast<float>(std::log1p(static_cast<double>(reasons.size())));
  out[6] = static_cast<float>(share(no_reason, n));
  out[7] = static_cast<float>(std::log1p(median_gap_ms));
  out[8] = static_cast<float>(irregularity);
  out[9] = static_cast<float>(std::clamp((times.back() - times.front()) / FLOOD_SPAN_SECONDS,
                                          0.0, 1.0));
  return out;
}

FloodModelConfig flood_model_config() {
  auto setting = [](const char* name, std::string fallback) {
    const char* value = std::getenv(name);
    return value && *value ? std::string(value) : fallback;
  };
  const std::string ml = AIRLOCK_ML_DIR;
  return {setting("AIRLOCK_PYTHON", "python3"), ml + "/score.py",
          setting("AIRLOCK_FLOOD_MODEL", ml + "/flood-model.pt")};
}

namespace {

// Ignore SIGPIPE for this scope, so a scorer that exits before reading its
// input produces an error here instead of killing the analyzer.
class IgnoreSigpipe {
 public:
  IgnoreSigpipe() {
    struct sigaction ignore {};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    sigaction(SIGPIPE, &ignore, &previous_);
  }
  ~IgnoreSigpipe() { sigaction(SIGPIPE, &previous_, nullptr); }
  IgnoreSigpipe(const IgnoreSigpipe&) = delete;
  IgnoreSigpipe& operator=(const IgnoreSigpipe&) = delete;

 private:
  struct sigaction previous_ {};
};

// Run `argv` with `input` on stdin; return its exit status and everything it
// wrote to stdout and stderr. The scorer reads all of its input before
// writing, so writing first and then reading cannot deadlock.
std::pair<int, std::string> run(std::vector<std::string> argv, const std::string& input) {
  int to_child[2], from_child[2];
  if (pipe(to_child) != 0) throw FloodModelUnavailable("cannot create a pipe");
  if (pipe(from_child) != 0) {
    close(to_child[0]);
    close(to_child[1]);
    throw FloodModelUnavailable("cannot create a pipe");
  }
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, to_child[0], STDIN_FILENO);
  posix_spawn_file_actions_adddup2(&actions, from_child[1], STDOUT_FILENO);
  posix_spawn_file_actions_adddup2(&actions, from_child[1], STDERR_FILENO);
  for (int fd : {to_child[0], to_child[1], from_child[0], from_child[1]}) {
    posix_spawn_file_actions_addclose(&actions, fd);
  }
  std::vector<char*> args;
  for (std::string& arg : argv) args.push_back(arg.data());
  args.push_back(nullptr);
  pid_t pid = 0;
  const int spawned = posix_spawnp(&pid, args[0], &actions, nullptr, args.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  close(to_child[0]);
  close(from_child[1]);
  if (spawned != 0) {
    close(to_child[1]);
    close(from_child[0]);
    throw FloodModelUnavailable(std::format("cannot start {}: {}", argv[0], std::strerror(spawned)));
  }

  {
    IgnoreSigpipe guard;
    std::size_t written = 0;
    while (written < input.size()) {
      const ssize_t n = write(to_child[1], input.data() + written, input.size() - written);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) break;  // the scorer stopped reading; its exit status says why
      written += static_cast<std::size_t>(n);
    }
    close(to_child[1]);
  }

  std::string output;
  char buffer[4096];
  for (;;) {
    const ssize_t n = read(from_child[0], buffer, sizeof buffer);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    output.append(buffer, static_cast<std::size_t>(n));
  }
  close(from_child[0]);

  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  return {WIFEXITED(status) ? WEXITSTATUS(status) : -1, output};
}

std::string last_line(const std::string& text) {
  std::string line, last;
  std::istringstream lines(text);
  while (std::getline(lines, line)) {
    if (!line.empty()) last = line;
  }
  return last.empty() ? std::string("no output") : last;
}

}  // namespace

FloodScores score_flood_spans(const std::vector<FloodFeatures>& spans,
                              const FloodModelConfig& config) {
  FloodScores result;
  if (spans.empty()) return result;
  if (!std::filesystem::is_regular_file(config.model)) {
    throw FloodModelUnavailable("no model file at " + config.model + " (run ml/train.py)");
  }
  std::string input;
  for (const FloodFeatures& span : spans) {
    for (std::size_t i = 0; i < span.size(); ++i) {
      input += std::format("{}{:.9g}", i ? "\t" : "", span[i]);
    }
    input += '\n';
  }
  const auto [status, output] = run({config.python, "-I", config.script, config.model}, input);
  if (status != 0) {
    throw FloodModelUnavailable(
        std::format("the PyTorch scorer failed (exit {}): {}", status, last_line(output)));
  }

  bool have_threshold = false;
  std::string line;
  std::istringstream lines(output);
  while (std::getline(lines, line)) {
    std::istringstream fields(line);
    std::string tag;
    std::getline(fields, tag, '\t');
    if (tag == "threshold") {
      fields >> result.threshold;
      have_threshold = !fields.fail();
    } else if (tag == "score") {
      FloodScore score;
      fields >> score.probability;
      for (double& a : score.attribution) fields >> a;
      if (fields.fail()) throw FloodModelUnavailable("unreadable scorer output: " + line);
      result.scores.push_back(score);
    }
  }
  if (!have_threshold || result.scores.size() != spans.size()) {
    throw FloodModelUnavailable(std::format("the scorer returned {} scores for {} spans",
                                            result.scores.size(), spans.size()));
  }
  return result;
}

}  // namespace airlock::wifi
