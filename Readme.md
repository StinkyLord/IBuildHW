# cpp-sbom-builder

A **Software Bill of Materials (SBOM) Generation Engine** for C++ projects.

Unlike languages with universal package managers (npm, pip), C++ dependency management is fragmented. `cpp-sbom-builder` solves this by running **multiple detection strategies** against a project's build outputs, filesystem, and configuration files to infer third-party dependencies — without requiring a compiler to be present.

Output is a valid **CycloneDX 1.4 JSON** SBOM.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Detection Strategies](#detection-strategies)
- [Running with Docker (Recommended)](#running-with-docker-recommended)
- [Running with Docker + MSVC Build (Windows Containers)](#running-with-docker--msvc-build-windows-containers)
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

All strategies run **concurrently**. Results are merged and deduplicated by library name, with higher-confidence sources (package manager manifests > compiler artifacts > header scan) priority on version information.

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

## Running with Docker

The Docker image contains **all required tools pre-installed** — Python, Conan, CMake, GCC, Clang, binutils (`nm`, `objdump`, `readelf`, `ldd`) — so you need **nothing on your machine except Docker**.

Your project directory is mounted **read-only**. Nothing is installed on your machine.

### Prerequisites

- [Go 1.25+](https://go.dev/dl/)
- If you want to use docker, Docker engine
- if you want better conan results. have conan installed and add --conan-graph or run the command `conan graph info . --format=json > graph.json`
- Build the project to create Linker .map files.

### Build the executable or image locally

For simplicity I avoided creating a dockerhub public image or executables for this project.
also there will be no release or versioning.

to build image
```bash
git clone https://github.com/StinkyLord/IBuildHW.git
cd IBuildHW
#docker image
docker build -t philip/cpp-sbom-builder:latest .
#executable
go build
```

### Run (Linux / macOS)

Notes for performance:
1. --conan-graph will run a commandline to get dependency graph from conan.
you can run `conan graph info . --format=json > graph.json` to avoid running the command through the cli tool.
2. Build your project before you mount and run. it will create linker map files which will give better results.
i avoided building the project myself as every project has specific configurations to build correctly.
3. If you have everything installed on your machine and you built your project, you can run the executable, .

Tthe flags runing here are just an example. see what they do and decide what suits your project best
```bash
./${Executable} scan --dir 'D:\github\toDelete\ASM-Snippet-Univeristy' --conan-graph --cmake-configure --ldd --show-strategies --verbose
```

If you choose to run on docker

```bash
docker run --rm \
  -v ${/path/to/my/cpp/project}:/project:ro \
  -v $(pwd):/output \
  ${image}:${tag} \
  scan --dir /project --conan-graph --cmake-configure --ldd --output /output/sbom.json --show-strategies --verbose
```

### Run (Windows — PowerShell)

```powershell
docker run --rm `
  -v ${D:\path\to\my\cpp\project}:/project:ro `
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


### Ideas

1. Maybe we can build the project for the customer inside the docker to create the .map files if the customer provides how. 
2. Maybe we can get MSVC container to run linker commands to create the .map files.