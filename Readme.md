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
- [Running the Test Suite](#running-the-test-suite)
- [Output Format](#output-format)

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

---

## Running with Docker (Recommended)

The Docker image contains **all required tools pre-installed** — Python, Conan, CMake, GCC, Clang, binutils (`nm`, `objdump`, `readelf`, `ldd`) — so you need **nothing on your machine except Docker**.

Your project directory is mounted **read-only**. Nothing is installed on your machine.

### Build the image

```bash
git clone https://github.com/StinkyLord/IBuildHW.git
cd IBuildHW
docker build -t philip/cpp-sbom-builder:latest .
```

### Run (Linux / macOS)

```bash
docker run --rm \
  -v /path/to/my/cpp/project:/project:ro \
  -v $(pwd):/output \
  philip/cpp-sbom-builder:latest \
  scan --dir /project --conan-graph --cmake-configure --ldd --output /output/sbom.json --show-strategies --verbose
```

### Run (Windows — PowerShell)

```powershell
docker run --rm `
  -v D:\path\to\my\cpp\project:/project:ro `
  -v ${PWD}:/output `
  philip/cpp-sbom-builder:latest `
  scan --dir /project --conan-graph --cmake-configure --ldd --output /output/sbom.json --show-strategies --verbose
```

### Flags reference

| Flag | Default | Description |
|---|---|---|
| `--dir` | `.` | Path to the C++ project root (inside the container) |
| `--output` | `sbom.json` | Output file path (`-` for stdout) |
| `--conan-graph` | `false` | Run `conan graph info` for full Conan dependency tree |
| `--cmake-configure` | `false` | Run cmake configure-only to generate `compile_commands.json` + `link.txt` |
| `--ldd` | `false` | Run `ldd` on `.so` files for runtime dependency edges (Linux/Docker only) |
| `--show-strategies` | `false` | Print strategy summary after scan |
| `--verbose` | `false` | Verbose logging |

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
go build -o cpp-sbom-builder.exe .
```

---

## Running Locally

> **Note:** Some strategies (`--conan-graph`, `--cmake-configure`, `--ldd`) require the respective tools to be installed on your machine. The Docker image is the easiest way to get all of them.

```bash
# Basic scan
./cpp-sbom-builder scan --dir /path/to/cpp/project

# Full scan with all strategies
./cpp-sbom-builder scan --dir /path/to/cpp/project \
  --conan-graph --cmake-configure --ldd \
  --output sbom.json --show-strategies --verbose

# Print SBOM to stdout
./cpp-sbom-builder scan --dir /path/to/cpp/project --output -
```

---

## Running the Test Suite

```bash
go test ./... -v
```

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
    "tools": [{ "vendor": "StinkyLord", "name": "cpp-sbom-builder", "version": "1.0.0" }]
  },
  "components": [
    {
      "type": "library",
      "name": "boost",
      "version": "1.82.0",
      "purl": "pkg:conan/boost@1.82.0",
      "properties": [
        { "name": "sbom:detectionSource", "value": "conan" }
      ]
    }
  ]
}
```

Each component includes `properties` recording **how** it was detected, which include paths triggered the detection, and which libraries were linked.
