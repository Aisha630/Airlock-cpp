// Shared helpers for the test suite.
#pragma once

#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <string>
#include <string_view>

#include "common/bytes.hpp"

namespace airlock::testing {

// A fresh directory under the system temp dir, removed when the test ends.
class TempDir {
 public:
  TempDir() {
    static std::atomic<int> counter{0};
    const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
    std::string name = "airlock-";
    name += info ? info->name() : "suite";
    name += "-" + std::to_string(::getpid()) + "-" + std::to_string(counter++);
    for (char& c : name) {
      if (c == '/') c = '_';
    }
    path_ = std::filesystem::temp_directory_path() / name;
    std::filesystem::create_directories(path_);
  }
  ~TempDir() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  std::string file(std::string_view name) const { return (path_ / name).string(); }

 private:
  std::filesystem::path path_;
};

// Assert that `statement` throws `Exception` with `fragment` in its message.
#define EXPECT_THROW_WITH(statement, Exception, fragment)                              \
  do {                                                                                 \
    try {                                                                              \
      statement;                                                                       \
      ADD_FAILURE() << "expected " #Exception " containing \"" << (fragment) << "\""; \
    } catch (const Exception& exc) {                                                   \
      EXPECT_NE(std::string(exc.what()).find(fragment), std::string::npos)             \
          << "message was: " << exc.what();                                            \
    }                                                                                  \
  } while (0)

inline bool contains(std::string_view haystack, std::string_view needle) {
  return haystack.find(needle) != std::string_view::npos;
}

}  // namespace airlock::testing
