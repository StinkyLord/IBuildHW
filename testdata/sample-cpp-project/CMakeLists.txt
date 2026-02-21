cmake_minimum_required(VERSION 3.16)
project(SampleCppProject VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find packages (these would be resolved by Conan or system)
find_package(Boost 1.82.0 REQUIRED COMPONENTS system filesystem)
find_package(OpenSSL 3.1.4 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json 3.11.2 REQUIRED)
find_package(spdlog REQUIRED)

# Fetch googletest via FetchContent
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
)
FetchContent_MakeAvailable(googletest)

add_executable(sample_app
    src/main.cpp
    src/crypto_utils.cpp
    src/http_client.cpp
)

target_link_libraries(sample_app
    PRIVATE
    Boost::system
    Boost::filesystem
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    nlohmann_json::nlohmann_json
    spdlog::spdlog
)

# Tests
add_executable(sample_tests
    tests/test_crypto.cpp
    tests/test_http.cpp
)

target_link_libraries(sample_tests
    PRIVATE
    GTest::gtest_main
    OpenSSL::SSL
    Boost::system
)
