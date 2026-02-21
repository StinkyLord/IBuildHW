# cpp-sbom-builder

A **Software Bill of Materials (SBOM) Generation Engine** for C++ projects.

Unlike languages with universal package managers (npm, pip), C++ dependency management is fragmented. `cpp-sbom-builder` solves this by running **multiple detection strategies** against a project's build outputs, filesystem, and configuration files to infer third-party dependencies — without requiring a compiler to be present.

Output is a valid **CycloneDX 1.4 JSON** SBOM.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Detection Strategies](#detection-strategies)
- [Running with Docker (Recommended)](#running-with-docker-recommended)
- [Installation (Local Build)](#installation-local-build)
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
│  │   Conan Graph        │  │   Meson              │   │
│  │  (graph.json via     │  │  (meson.build,       │   │
│  │   conan graph info)  │  │   .wrap files)       │   │
│  └─────────────────────┘  └──────────────────────┘   │
│  ┌─────────────────────┐                             │
│  │   Header Scan        │                             │
│  │  (#include analysis, │                             │
│  │   fallback only)     │                             │
│  └─────────────────────┘                             │
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
| **Conan Graph** | `graph.json` (from `conan graph info . --format=json`) | Full resolved tree with direct/transitive edges, exact versions, license metadata |
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

---

## Running with Docker (Recommended)

The easiest way to use `cpp-sbom-builder` is via the pre-built Docker image. The image contains **all required tools pre-installed** — Python, Conan, CMake, GCC, Clang, binutils (`nm`, `objdump`, `readelf`, `ldd`) — so you need **nothing on your machine except Docker**.

Your project directory is mounted **read-only**. Nothing is installed on your machine.

### Quick start

```bash
# build the image using docker
docker build -t philip/cpp-sbom-builder:latest .

# Scan a project — output goes to ./sbom.json
docker run --rm \
  -v /path/to/my/cpp/project:/project:ro \
  -v $(pwd):/output \
  philip/cpp-sbom-builder:latest \
  scan --dir /project --output /output/sbom.json
```

On Windows (PowerShell):
```powershell
docker run --rm `
  -v C:\path\to\my\project:/project:ro `
  -v ${PWD}:/output `
  philip/cpp-sbom-builder:latest `
  scan --conan-graph --verbose --dir /project --output /output/sbom.json
```

### With Conan graph resolution

```bash
docker run --rm \
  -v /path/to/my/project:/project:ro \
  -v $(pwd):/output \
  philip/cpp-sbom-builder:latest \
  scan --dir /project --conan-graph --output /output/sbom.json
```

When `--conan-graph` is passed, the entrypoint automatically:
1. Runs `conan install` to resolve all dependencies
2. Runs `conan graph info . --format=json` to produce the full dependency tree
3. Passes the result to the scanner

### With CMake configure (MAP-equivalent linker data)

```bash
docker run --rm \
  -v /path/to/my/project:/project:ro \
  -v $(pwd):/output \
  philip/cpp-sbom-builder:latest \
  scan --dir /project --cmake-configure --output /output/sbom.json
```

When `--cmake-configure` is passed, the entrypoint runs:
```
cmake -S /project -B /tmp/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```
This is a **configure-only step** (no compilation). It generates:
- `compile_commands.json` — all `-I` include paths and compiler flags
- `CMakeFiles/*/link.txt` — the full linker command line for each target

The `link.txt` files are the **closest equivalent to linker MAP files** that can be produced without a full build. They contain every `-l` flag and library path the linker would use.

### With LDD runtime dependency analysis

```bash
docker run --rm \
  -v /path/to/my/project:/project:ro \
  -v $(pwd):/output \
  philip/cpp-sbom-builder:latest \
  scan --dir /project --ldd --output /output/sbom.json
```

When `--ldd` is passed, the entrypoint runs `ldd` on every `.so` file found in the project, producing the full **transitive runtime dependency tree**. This is richer than a linker MAP file because it shows the actual resolved runtime dependencies.

### Full scan (all strategies)

```bash
docker run --rm \
  -v /path/to/my/project:/project:ro \
  -v $(pwd):/output \
  philip/cpp-sbom-builder:latest \
  scan --dir /project \
       --conan-graph \
       --cmake-configure \
       --ldd \
       --output /output/sbom.json \
       --show-strategies \
       --verbose
```

### Using docker-compose

```bash
# Clone the repo to get docker-compose.yml
git clone https://github.com/StinkyLord/IBuildHW.git
cd IBuildHW

# Scan a project
PROJECT_DIR=/path/to/my/project docker compose run --rm sbom-builder

# With all strategies
PROJECT_DIR=/path/to/my/project \
SBOM_CONAN_GRAPH=1 \
SBOM_CMAKE_CONFIGURE=1 \
SBOM_LDD=1 \
docker compose run --rm sbom-builder
```

### Environment variables (alternative to flags)

| Variable | Flag equivalent | Default |
|---|---|---|
| `SBOM_CONAN_GRAPH=1` | `--conan-graph` | `0` |
| `SBOM_CMAKE_CONFIGURE=1` | `--cmake-configure` | `0` |
| `SBOM_LDD=1` | `--ldd` | `0` |
| `SBOM_VERBOSE=1` | `--verbose` | `0` |

### Building the image locally

```bash
git clone https://github.com/StinkyLord/IBuildHW.git
cd IBuildHW
docker build -t philip/cpp-sbom-builder:latest .
```

---

## Installation (Local Build)

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
./cpp-sbom-builder scan --dir /path/to/cpp/project

# Specify output file
./cpp-sbom-builder scan --dir /path/to/cpp/project --output /tmp/my-sbom.json

# Print SBOM to stdout
./cpp-sbom-builder scan --dir /path/to/cpp/project --output -

# Verbose mode (shows which strategies fired and what files were parsed)
./cpp-sbom-builder scan --dir /path/to/cpp/project --verbose

# Show strategy summary after scan
./cpp-sbom-builder scan --dir /path/to/cpp/project --show-strategies

# Use conan graph info for the richest Conan dependency data (requires Docker)
./cpp-sbom-builder scan --dir /path/to/cpp/project --conan-graph --output sbom.json

# Use a custom Conan Docker image
./cpp-sbom-builder scan --dir /path/to/cpp/project --conan-graph --conan-image conanio/conan:2.0 --output sbom.json

# If you already ran `conan graph info . --format=json > graph.json` manually,
# just place graph.json in the project root — it will be picked up automatically
# without needing Docker or --conan-graph.
```

### All flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--dir` | `-d` | `.` | Path to the C++ project root |
| `--output` | `-o` | `sbom.json` | Output file path (`-` for stdout) |
| `--format` | `-f` | `cyclonedx` | Output format (`cyclonedx`) |
| `--verbose` | `-v` | `false` | Verbose logging |
| `--show-strategies` | | `false` | Print strategy summary |
| `--conan-graph` | | `false` | Run `conan graph info` (inside Docker image) for full Conan dependency tree |
| `--conan-image` | | `conanio/conan:latest` | Docker image to use with `--conan-graph` (standalone mode only) |
| `--cmake-configure` | | `false` | Run cmake configure-only to generate `compile_commands.json` + `link.txt` (MAP equivalent) |
| `--ldd` | | `false` | Run `ldd` on `.so` files for runtime dependency edges (Linux/Docker only) |

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

### Example 3: Conan project with full graph resolution (requires Docker)

```bash
# Option A: Let the tool run conan inside Docker automatically
cpp-sbom-builder scan --dir /path/to/conan-project --conan-graph --output sbom.json --verbose

# Option B: Pre-generate graph.json yourself (no Docker needed at scan time)
cd /path/to/conan-project
conan graph info . --format=json > graph.json
cpp-sbom-builder scan --dir . --output sbom.json --show-strategies
```

The `--conan-graph` strategy produces the richest Conan data:
- **Exact resolved versions** (not range-based)
- **Direct vs. transitive** classification from the actual dependency graph
- **License and description** metadata from the Conan Center recipe
- **Recipe revision hash** for reproducibility

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
