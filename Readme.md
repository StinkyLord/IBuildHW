# cpp-sbom-builder

A **Software Bill of Materials (SBOM) Generation Engine** for C++ projects.

Unlike languages with universal package managers (npm, pip), C++ dependency management is fragmented. `cpp-sbom-builder` solves this by running **multiple detection strategies** against a project's build outputs, filesystem, and configuration files to infer third-party dependencies — without requiring a compiler to be present.

Output is a valid **CycloneDX 1.4 JSON** SBOM.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Detection Strategies](#detection-strategies)
- [Installation](#installation)
- [Running Locally](#running-locally)
- [Executing Against a Sample Project](#executing-against-a-sample-project)
- [Running the Test Suite](#running-the-test-suite)
- [Output Format](#output-format)
- [Design Decisions & Guiding Questions](#design-decisions--guiding-questions)

---

## How It Works

```
C++ Project Directory
        │
        ▼
┌───────────────────────────────────────────────────────┐
│                   SBOM Inference Engine                │
│                                                       │
│  ┌─────────────────────┐  ┌──────────────────────┐   │
│  │ compile_commands.json│  │  Linker Map (.map)   │   │
│  │  (compiler -I paths) │  │  (linked .lib/.so)   │   │
│  └─────────────────────┘  └──────────────────────┘   │
│  ┌─────────────────────┐  ┌──────────────────────┐   │
│  │   Build Logs         │  │   CMake Cache        │   │
│  │  (link.txt, .tlog,  │  │  (CMakeCache.txt,    │   │
│  │   build.ninja)       │  │   CMakeLists.txt)    │   │
│  └─────────────────────┘  └──────────────────────┘   │
│  ┌─────────────────────┐  ┌──────────────────────┐   │
│  │   Conan              │  │   vcpkg              │   │
│  │  (conan.lock,        │  │  (vcpkg.json,        │   │
│  │   conanfile.txt/py)  │  │   vcpkg-lock.json)   │   │
│  └─────────────────────┘  └──────────────────────┘   │
│  ┌─────────────────────┐  ┌──────────────────────┐   │
│  │   Meson              │  │   Header Scan        │   │
│  │  (meson.build,       │  │  (#include analysis, │   │
│  │   .wrap files)       │  │   fallback only)     │   │
│  └─────────────────────┘  └──────────────────────┘   │
│                                                       │
│              Merge & Deduplicate                      │
└───────────────────────────────────────────────────────┘
        │
        ▼
  CycloneDX 1.4 JSON SBOM
```

All strategies run **concurrently**. Results are merged and deduplicated by library name, with higher-confidence sources (package manager manifests > compiler artifacts > header scan) winning on version information.

---

## Detection Strategies

| Strategy | Files Parsed | Externality Signal |
|---|---|---|
| **compile_commands.json** | `compile_commands.json` | `-I` paths outside project root = external |
| **Linker Map** | `*.map` | Library paths outside project root |
| **Build Logs** | `CMakeFiles/*/link.txt`, `*.tlog`, `build.ninja`, `Makefile` | `-l` flags, `/DEFAULTLIB:`, absolute `.lib` paths |
| **CMake** | `CMakeCache.txt`, `CMakeLists.txt` | `find_package()`, `FetchContent_Declare()`, `_DIR` cache entries |
| **Conan** | `conan.lock`, `conanfile.txt`, `conanfile.py` | All declared dependencies are external |
| **vcpkg** | `vcpkg.json`, `vcpkg-lock.json`, `installed/vcpkg/status` | All declared dependencies are external |
| **Meson** | `meson.build`, `*.wrap` | `dependency()`, `subproject()` calls |
| **Header Scan** | `*.cpp`, `*.h`, `*.hpp`, etc. | Angle-bracket includes matching known library fingerprints, not resolvable inside project |

### Version Detection

Versions are detected from (in priority order):
1. Package manager lock files (exact versions)
2. CMakeCache.txt `_VERSION` entries
3. Path-encoded versions (e.g. `boost_1_82_0`, `openssl-3.1.4`)
4. MSVC-decorated library names (e.g. `boost_system-vc143-mt-x64-1_82.lib`)
5. FetchContent `GIT_TAG` values
6. Header `#define *_VERSION*` macros
7. Falls back to `"unknown"`

---

## Installation

### Prerequisites

- [Go 1.21+](https://go.dev/dl/)

### Build from source

```bash
git clone https://github.com/StinkyLord/IBuildHW.git
cd IBuildHW
go build -o cpp-sbom-builder .
```

On Windows:
```powershell
git clone https://github.com/StinkyLord/IBuildHW.git
cd IBuildHW
go build -o cpp-sbom-builder.exe .
```

### Install to PATH

```bash
go install github.com/StinkyLord/cpp-sbom-builder@latest
```

---

## Running Locally

```bash
# Basic scan — writes sbom.json in the current directory
cpp-sbom-builder scan --dir /path/to/cpp/project

# Specify output file
cpp-sbom-builder scan --dir /path/to/cpp/project --output /tmp/my-sbom.json

# Print SBOM to stdout
cpp-sbom-builder scan --dir /path/to/cpp/project --output -

# Verbose mode (shows which strategies fired and what files were parsed)
cpp-sbom-builder scan --dir /path/to/cpp/project --verbose

# Show strategy summary after scan
cpp-sbom-builder scan --dir /path/to/cpp/project --show-strategies
```

### All flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--dir` | `-d` | `.` | Path to the C++ project root |
| `--output` | `-o` | `sbom.json` | Output file path (`-` for stdout) |
| `--format` | `-f` | `cyclonedx` | Output format (`cyclonedx`) |
| `--verbose` | `-v` | `false` | Verbose logging |
| `--show-strategies` | | `false` | Print strategy summary |

---

## Executing Against a Sample Project

You can run `cpp-sbom-builder` against any real-world open-source C++ project. Here are some good examples:

### Example 1: nlohmann/json (header-only, CMake)

```bash
git clone https://github.com/nlohmann/json.git /tmp/nlohmann-json
cpp-sbom-builder scan --dir /tmp/nlohmann-json --output sbom-nlohmann.json --show-strategies
```

### Example 2: A project with Conan (e.g. after `conan install`)

```bash
git clone https://github.com/conan-io/examples2.git /tmp/conan-examples
cpp-sbom-builder scan --dir /tmp/conan-examples/examples/libraries/boost/boost_header_only --output sbom-boost.json --verbose
```

### Example 3: A CMake project with compile_commands.json

```bash
# Build the project first to generate compile_commands.json
cmake -S /path/to/project -B /path/to/project/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build /path/to/project/build

# Then scan
cpp-sbom-builder scan --dir /path/to/project --output sbom.json --show-strategies
```

> **Tip:** The more build artifacts are present (compile_commands.json, .map files, CMakeCache.txt), the more accurate the results. The tool works best on a **post-build** project directory.

---

## Running the Test Suite

```bash
go test ./... -v
```

Expected output:
```
=== RUN   TestCycloneDXSchema
--- PASS: TestCycloneDXSchema
=== RUN   TestCycloneDXComponents
--- PASS: TestCycloneDXComponents
=== RUN   TestCycloneDXProperties
--- PASS: TestCycloneDXProperties
=== RUN   TestCycloneDXStdout
--- PASS: TestCycloneDXStdout
=== RUN   TestCycloneDXSorted
--- PASS: TestCycloneDXSorted
=== RUN   TestCycloneDXMetadata
--- PASS: TestCycloneDXMetadata
PASS
ok      github.com/StinkyLord/cpp-sbom-builder/internal/output
```

The tests verify:
- Output is valid JSON
- All required CycloneDX 1.4 fields are present (`bomFormat`, `specVersion`, `version`, `serialNumber`, `metadata`, `components`)
- All detected components appear in the output with correct fields
- Detection metadata is included as CycloneDX `properties`
- Components are sorted alphabetically (deterministic output)
- Metadata block contains correct tool name and version

---

## Output Format

The tool produces **CycloneDX 1.4 JSON**. Example:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "serialNumber": "urn:uuid:5f3a2b1c-...",
  "metadata": {
    "timestamp": "2026-02-20T13:00:00Z",
    "tools": [
      {
        "vendor": "StinkyLord",
        "name": "cpp-sbom-builder",
        "version": "1.0.0"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "boost",
      "version": "1.82.0",
      "purl": "pkg:conan/boost@1.82.0",
      "description": "Boost C++ Libraries",
      "properties": [
        { "name": "sbom:detectionSource", "value": "conan" },
        { "name": "sbom:includePath",     "value": "/usr/include/boost" },
        { "name": "sbom:linkLibrary",     "value": "boost_system" }
      ]
    },
    {
      "type": "library",
      "name": "openssl",
      "version": "3.1.4",
      "purl": "pkg:conan/openssl@3.1.4",
      "description": "OpenSSL cryptography library",
      "properties": [
        { "name": "sbom:detectionSource", "value": "compile_commands.json" },
        { "name": "sbom:includePath",     "value": "/usr/include/openssl" }
      ]
    }
  ]
}
```

Each component includes custom `properties` that record **how** it was detected, which include paths triggered the detection, and which libraries were linked.

---

## Design Decisions & Guiding Questions

### False Positives and Inaccuracies

**How do we distinguish standard library headers from third-party ones?**

Three-layer filter in the header scan strategy:
1. **Stdlib allowlist** — a hardcoded set of ~120 standard C/C++ and POSIX headers (`<vector>`, `<stdio.h>`, `<pthread.h>`, etc.) is checked first and immediately excluded.
2. **Project-internal resolution** — the include path is checked against the project filesystem. If a file matching the include exists inside the project root (relative to the source file, the project root, or common dirs like `include/`, `src/`), it is treated as internal and excluded.
3. **Fingerprint matching** — only includes that match a known third-party library fingerprint (e.g. `boost/`, `openssl/`, `nlohmann/json.hpp`) are reported.

**Other potential inaccuracies:**
- A library vendored inside the project (e.g. `third_party/zlib/`) may be reported as external if its headers match a fingerprint but the files don't exist at the expected path.
- Conditional compilation (`#ifdef`) may cause some includes to be missed or over-counted.
- The fingerprint database only covers ~50 well-known libraries; unknown libraries are not reported by the header scan (though they may be caught by compiler/linker artifact strategies).

### Version Detection

When a dependency is detected via header files only:
1. The tool scans the resolved include directory for `version.h`, `*_version.h`, `*_config.h` files and looks for `#define *VERSION* "x.y.z"` macros.
2. If the include path contains a version string (e.g. `/usr/local/include/boost_1_82_0/`), it is extracted via regex.
3. Falls back to `"unknown"` if no version can be determined.

### Performance

For a 10 GB monorepo:
- **All strategies run concurrently** via goroutines, so I/O-bound strategies (file walking) overlap.
- **String search, not AST parsing** — we only need `#include` lines, so a line-by-line `bufio.Scanner` is used. This is orders of magnitude faster than a full C++ AST parser and avoids the complexity of handling preprocessor macros.
- **Early directory skipping** — `.git`, `node_modules`, `CMakeFiles`, and build output directories are skipped during `filepath.WalkDir`.
- **Compiler artifacts first** — `compile_commands.json` and linker map files are small and parsed first. If they cover all dependencies, the header scan (which touches every source file) adds little new information.
- For extreme scale, the worker pool could be bounded with a semaphore to limit concurrent file handles, and results could be streamed to the output file rather than accumulated in memory.
