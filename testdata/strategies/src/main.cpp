// Sample C++ source file for header scan testing.
// This file includes a mix of:
//   - Standard library headers (should be ignored)
//   - Known third-party library headers (should be detected)
//   - A quoted internal header (should be ignored)

#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <cstdint>

// Third-party: should be detected
#include <boost/algorithm/string.hpp>
#include <openssl/ssl.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

// Internal project header: should NOT be detected (it exists in the project)
#include "internal_utils.h"

int main() {
    return 0;
}
