cmake_minimum_required(VERSION 3.20)
project(airlock VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(AIRLOCK_BUILD_TESTS "Build the GoogleTest suite" ON)

# Homebrew installs OpenSSL keg-only, so point CMake at it when present.
if(APPLE AND NOT OPENSSL_ROOT_DIR)
  foreach(prefix /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3)
    if(EXISTS "${prefix}")
      set(OPENSSL_ROOT_DIR "${prefix}")
      break()
    endif()
  endforeach()
endif()
find_package(OpenSSL 3.0 REQUIRED)

add_library(airlock_warnings INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(airlock_warnings INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion)
endif()

add_library(airlock_akex STATIC
  src/akex/attacks.cpp
  src/akex/bignum.cpp
  src/akex/channel.cpp
  src/akex/crypto.cpp
  src/akex/dh.cpp
  src/akex/kdf.cpp
  src/akex/params.cpp
  src/akex/protocol.cpp
  src/akex/wire.cpp
)
target_include_directories(airlock_akex PUBLIC src)
target_link_libraries(airlock_akex PUBLIC OpenSSL::Crypto PRIVATE airlock_warnings)

add_library(airlock_wifi STATIC
  src/wifi/anomalies.cpp
  src/wifi/build.cpp
  src/wifi/capture.cpp
  src/wifi/eapol.cpp
  src/wifi/frames.cpp
  src/wifi/json.cpp
  src/wifi/pcap.cpp
  src/wifi/report.cpp
  src/wifi/rsn.cpp
  src/wifi/synth.cpp
  src/wifi/text.cpp
)
target_include_directories(airlock_wifi PUBLIC src)
target_link_libraries(airlock_wifi PRIVATE airlock_warnings)

add_executable(akex tools/akex.cpp)
target_link_libraries(akex PRIVATE airlock_akex airlock_warnings)

add_executable(wifi tools/wifi.cpp)
target_link_libraries(wifi PRIVATE airlock_wifi airlock_warnings)

if(AIRLOCK_BUILD_TESTS)
  enable_testing()
  find_package(GTest CONFIG QUIET)
  if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(googletest
      URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
  endif()

  add_executable(airlock_tests
    tests/test_analyze.cpp
    tests/test_attacks.cpp
    tests/test_channel.cpp
    tests/test_dh.cpp
    tests/test_eapol.cpp
    tests/test_frames.cpp
    tests/test_kdf.cpp
    tests/test_pcap.cpp
    tests/test_protocol.cpp
    tests/test_robustness.cpp
    tests/test_rsn.cpp
    tests/test_wire.cpp
  )
  target_link_libraries(airlock_tests PRIVATE airlock_akex airlock_wifi GTest::gtest_main airlock_warnings)
  include(GoogleTest)
  gtest_discover_tests(airlock_tests)
endif()
