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

## Running with Docker + MSVC Build (Windows Containers)

Use `dockerFileWithBuild` when you want the container to **fully compile your C++ project with the real MSVC toolchain** and generate `.map` files before scanning. This gives the `LinkerMapStrategy` the richest possible input — every library that was actually linked into your binary is recorded in the `.map` file.

### How it works

```
Your C++ source (C:\project — read-only mount)
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│              Windows Container (MSVC Build Tools)           │
│                                                             │
│  Step 1 — cmake configure                                   │
│    • Generates compile_commands.json                        │
│    • Injects /MAP into linker flags for all targets         │
│                                                             │
│  Step 2 — cmake build (cl.exe + link.exe)                   │
│    • Fully compiles the project                             │
│    • link.exe /MAP writes <target>.map next to each .exe    │
│      The .map lists every .lib that was linked in           │
│                                                             │
│  Step 3 — cpp-sbom-builder scan                             │
│    • Scans C:\project (source) + C:\build (artifacts)       │
│    • LinkerMapStrategy reads the .map files                 │
│    • All other strategies run concurrently                  │
│    • Writes sbom.json to C:\output                          │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
  C:\output\sbom.json  (CycloneDX 1.4 JSON)
```

### Prerequisites

> ⚠️ **Windows Containers mode required.**
> In Docker Desktop, go to **Settings → General** and switch to **Windows containers** (or right-click the Docker tray icon and choose *Switch to Windows containers*). This container cannot run in Linux containers mode.

- Docker Desktop on Windows with **Windows containers** mode enabled
- At least **2 GB** of memory allocated to Docker for the build step
- At least **30 GB** of free disk space (the VS Build Tools image is large)

### Step 1 — Build the image

Open a **PowerShell** or **Command Prompt** window in the repository root:

```powershell
docker build -t cpp-sbom-builder-msvc:latest -m 2GB -f dockerFileWithBuild .
```

> The first build takes **10–20 minutes** — it downloads and installs Visual Studio 2022 Build Tools and CMake inside the image. Subsequent builds are fast thanks to Docker layer caching.

### Step 2 — Run the container

```powershell
docker run --rm `
  -v C:\path\to\your\cpp\project:C:\project:ro `
  -v ${PWD}:C:\output `
  cpp-sbom-builder-msvc:latest
```

The container will:
1. Configure your project with CMake (MSVC generator, `/MAP` flag injected)
2. Compile it with `cl.exe` / `link.exe`
3. Scan the source + build output and write `sbom.json` to your current directory

### Step 3 — Read the output

```powershell
# View the SBOM
Get-Content .\sbom.json | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

### Environment variables

You can customise the build behaviour with `-e` flags:

| Variable | Default | Description |
|---|---|---|
| `BUILD_CONFIG` | `Release` | CMake build configuration: `Release`, `Debug`, `RelWithDebInfo` |
| `CMAKE_EXTRA_ARGS` | _(none)_ | Extra arguments passed to `cmake` configure, e.g. `-DSOME_OPTION=ON` |
| `SBOM_VERBOSE` | `0` | Set to `1` for verbose output from both the build and the scanner |

Example with environment variables:

```powershell
docker run --rm `
  -v C:\path\to\your\cpp\project:C:\project:ro `
  -v ${PWD}:C:\output `
  -e BUILD_CONFIG=Debug `
  -e SBOM_VERBOSE=1 `
  cpp-sbom-builder-msvc:latest
```

### What the `.map` file gives you

MSVC `link.exe /MAP` produces a file like this next to each compiled binary:

```
 sample_app.exe

 Timestamp is 65A3F210 (Fri Jan 14 10:00:00 2025)

 Preferred load address is 00400000

 Start         Length     Name                   Class
 ...

 Address         Publics by Value              Rva+Base               Lib:Object

 0001:00000000  _main                          00401000 f   sample_app.obj
 0001:00000020  _some_func                     00401020 f   boost_system.lib:ops.obj
 0001:00000080  _ssl_connect                   00401080 f   libssl.lib:ssl.obj
 ...
```

The `Lib:Object` column tells `cpp-sbom-builder` exactly which `.lib` files were linked — this is the highest-confidence signal for dependency detection.

### Troubleshooting

| Problem | Solution |
|---|---|
| `image operating system "windows" cannot be used on this platform` | Switch Docker Desktop to Windows containers mode |
| `CMake configure failed` | Your project may need dependencies (Conan/vcpkg). Pass `-e CMAKE_EXTRA_ARGS="-DCMAKE_TOOLCHAIN_FILE=..."` |
| `No .map files found` | Check that your `CMakeLists.txt` doesn't override `CMAKE_EXE_LINKER_FLAGS` |
| Build takes very long | Normal on first run — VS Build Tools is ~5 GB. Use `docker build --no-cache` only if needed |
| Out of disk space | Increase Docker Desktop disk image size to at least 60 GB in Settings → Resources |

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
