# docker-entrypoint-build.ps1
#
# PowerShell entrypoint for the cpp-sbom-builder-msvc Windows container.
#
# This script runs inside a Windows container that has MSVC Build Tools installed.
# VsDevCmd.bat has already been called by the ENTRYPOINT in the Dockerfile,
# so cl.exe, link.exe, and msbuild.exe are all on the PATH.
#
# What this script does:
#   1. CMake configure  — generates compile_commands.json, injects /MAP linker flag
#   2. CMake build      — fully compiles the project with MSVC
#                         link.exe produces a .map file for every linked target
#   3. cpp-sbom-builder — scans both the source dir and the build output dir
#                         (which now contains .map files) and writes sbom.json
#
# Volumes expected:
#   C:\project   — the user's C++ source tree (read-only recommended)
#   C:\output    — where sbom.json is written
#
# Environment variables (all optional):
#   CMAKE_EXTRA_ARGS   — extra arguments forwarded to cmake configure
#                        e.g. "-DSOME_OPTION=ON"
#   BUILD_CONFIG       — Release (default) | Debug | RelWithDebInfo
#   SBOM_VERBOSE       — set to "1" for verbose scanner output

$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

$ProjectDir   = "C:\project"
$BuildDir     = "C:\build"
$OutputDir    = "C:\output"
$SbomOutput   = "$OutputDir\sbom.json"
$BuildConfig  = if ($env:BUILD_CONFIG) { $env:BUILD_CONFIG } else { "Release" }
$Verbose      = $env:SBOM_VERBOSE -eq "1"

function Log   { param($msg) Write-Host "[entrypoint] $msg" -ForegroundColor Cyan }
function Warn  { param($msg) Write-Host "[entrypoint] WARNING: $msg" -ForegroundColor Yellow }
function Fatal { param($msg) Write-Host "[entrypoint] ERROR: $msg" -ForegroundColor Red; exit 1 }

Log "cpp-sbom-builder MSVC build entrypoint"
Log "Project dir  : $ProjectDir"
Log "Build dir    : $BuildDir"
Log "Output dir   : $OutputDir"
Log "Build config : $BuildConfig"

# ─────────────────────────────────────────────────────────────────────────────
# Sanity checks
# ─────────────────────────────────────────────────────────────────────────────

if (-not (Test-Path "$ProjectDir\CMakeLists.txt")) {
    Fatal "No CMakeLists.txt found in $ProjectDir. Mount your C++ project at C:\project."
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    Fatal "cmake not found on PATH. The image may not have built correctly."
}

if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
    Fatal "cl.exe not found on PATH. VsDevCmd.bat may not have run correctly."
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: CMake Configure
#
# Key flags:
#   -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
#       Generates compile_commands.json — used by the CompileCommandsStrategy
#
#   -DCMAKE_EXE_LINKER_FLAGS="/MAP"
#   -DCMAKE_SHARED_LINKER_FLAGS="/MAP"
#       Tells MSVC link.exe to produce a .map file for every executable and DLL.
#       The .map file lists every symbol and library that was linked in —
#       this is the primary input for the LinkerMapStrategy in cpp-sbom-builder.
#
#   -DCMAKE_MODULE_LINKER_FLAGS="/MAP"
#       Same for module (plugin) targets.
# ─────────────────────────────────────────────────────────────────────────────

Log "Step 1/3 — CMake configure (MSVC, $BuildConfig, /MAP enabled)..."

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$cmakeArgs = @(
    "-S", $ProjectDir,
    "-B", $BuildDir,
    "-G", "NMake Makefiles",          # NMake works reliably inside Windows containers
    "-DCMAKE_BUILD_TYPE=$BuildConfig",
    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    "-DCMAKE_EXE_LINKER_FLAGS=/MAP",
    "-DCMAKE_SHARED_LINKER_FLAGS=/MAP",
    "-DCMAKE_MODULE_LINKER_FLAGS=/MAP"
)

# Append any user-supplied extra args
if ($env:CMAKE_EXTRA_ARGS) {
    $cmakeArgs += $env:CMAKE_EXTRA_ARGS -split " "
}

if ($Verbose) {
    Log "cmake $($cmakeArgs -join ' ')"
}

$configResult = & cmake @cmakeArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host $configResult
    Fatal "CMake configure failed (exit code $LASTEXITCODE). Check your CMakeLists.txt and dependencies."
}

if ($Verbose) { Write-Host $configResult }
Log "CMake configure succeeded."

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: CMake Build (full compilation with MSVC)
#
# This invokes nmake which calls cl.exe and link.exe.
# link.exe sees /MAP in CMAKE_EXE_LINKER_FLAGS and writes:
#   <target>.map  — next to the .exe or .dll in the build directory
#
# The .map file format produced by MSVC link.exe looks like:
#
#   <target>.exe
#
#    Timestamp is <hex> (<date>)
#
#    Preferred load address is <addr>
#
#    Start         Length     Name                   Class
#    ...
#
#   Address         Publics by Value              Rva+Base               Lib:Object
#   ...
#
# cpp-sbom-builder's LinkerMapStrategy parses the "Lib:Object" section to
# extract which .lib files were linked, mapping them to known components.
# ─────────────────────────────────────────────────────────────────────────────

Log "Step 2/3 — CMake build (compiling with MSVC cl.exe + link.exe /MAP)..."

$buildArgs = @(
    "--build", $BuildDir,
    "--config", $BuildConfig
)

if ($Verbose) {
    $buildArgs += "--verbose"
}

$buildResult = & cmake @buildArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host $buildResult
    Warn "CMake build failed or partially failed (exit code $LASTEXITCODE)."
    Warn "Continuing with whatever artifacts were produced — the scanner will work with partial output."
} else {
    if ($Verbose) { Write-Host $buildResult }
    Log "CMake build succeeded."
}

# Report what .map files were generated
$mapFiles = Get-ChildItem -Path $BuildDir -Filter "*.map" -Recurse -ErrorAction SilentlyContinue
if ($mapFiles.Count -gt 0) {
    Log "Generated $($mapFiles.Count) .map file(s):"
    foreach ($mf in $mapFiles) {
        Log "  $($mf.FullName)"
    }
} else {
    Warn "No .map files found in $BuildDir. The /MAP flag may not have taken effect."
    Warn "The scanner will still run using other strategies (compile_commands.json, CMakeLists.txt, etc.)."
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Run cpp-sbom-builder
#
# We scan two directories:
#   --dir C:\project   — source tree (CMakeLists.txt, conanfile, vcpkg.json, etc.)
#   --build-dir C:\build — build output (.map files, compile_commands.json, link.txt)
#
# The scanner merges results from all strategies automatically.
# ─────────────────────────────────────────────────────────────────────────────

Log "Step 3/3 — Running cpp-sbom-builder scan..."

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$scanArgs = @(
    "scan",
    "--dir",        $ProjectDir,
    "--build-dir",  $BuildDir,
    "--output",     $SbomOutput,
    "--show-strategies"
)

if ($Verbose) {
    $scanArgs += "--verbose"
}

if ($Verbose) {
    Log "cpp-sbom-builder $($scanArgs -join ' ')"
}

& "C:\cpp-sbom-builder.exe" @scanArgs
$scanExit = $LASTEXITCODE

if ($scanExit -eq 0) {
    Log "Scan complete. SBOM written to $SbomOutput"
} else {
    Fatal "cpp-sbom-builder exited with code $scanExit"
}
