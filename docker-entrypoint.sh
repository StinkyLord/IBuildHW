#!/usr/bin/env bash
# docker-entrypoint.sh
#
# Smart pre-scan wrapper for cpp-sbom-builder.
#
# Runs optional pre-scan steps (conan install, cmake configure, ldd) before
# invoking the main scanner. All steps write to /tmp so the customer's project
# directory is never modified.
#
# Usage (inside the container — driven by docker run flags):
#
#   docker run --rm \
#     -v /my/project:/project:ro \
#     -v $(pwd):/output \
#     philip-abed-docker/cpp-sbom-builder \
#     scan --dir /project --output /output/sbom.json \
#          [--cmake-configure] [--conan-graph] [--ldd]
#
# Environment variables (alternative to flags):
#   SBOM_CMAKE_CONFIGURE=1   — same as --cmake-configure
#   SBOM_CONAN_GRAPH=1       — same as --conan-graph
#   SBOM_LDD=1               — same as --ldd
#   SBOM_VERBOSE=1           — same as --verbose

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

log()  { echo "[entrypoint] $*" >&2; }
warn() { echo "[entrypoint] WARNING: $*" >&2; }

# ─────────────────────────────────────────────────────────────────────────────
# Parse flags from the command line
# We intercept our own flags and pass the rest through to cpp-sbom-builder.
# ─────────────────────────────────────────────────────────────────────────────

DO_CMAKE_CONFIGURE="${SBOM_CMAKE_CONFIGURE:-0}"
DO_CONAN_GRAPH="${SBOM_CONAN_GRAPH:-0}"
DO_LDD="${SBOM_LDD:-0}"
VERBOSE="${SBOM_VERBOSE:-0}"

PROJECT_DIR="/project"
OUTPUT_DIR="/output"
PASSTHROUGH_ARGS=()

# Walk through all arguments and extract our pre-scan flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cmake-configure)
            DO_CMAKE_CONFIGURE=1
            shift
            ;;
        --conan-graph)
            DO_CONAN_GRAPH=1
            # Also pass through to cpp-sbom-builder so it picks up graph.json
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
        --ldd)
            DO_LDD=1
            # Also pass through so the LddStrategy is activated
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
        --dir)
            PROJECT_DIR="$2"
            PASSTHROUGH_ARGS+=("$1" "$2")
            shift 2
            ;;
        --dir=*)
            PROJECT_DIR="${1#--dir=}"
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
        --output)
            OUTPUT_DIR="$(dirname "$2")"
            PASSTHROUGH_ARGS+=("$1" "$2")
            shift 2
            ;;
        --output=*)
            OUTPUT_DIR="$(dirname "${1#--output=}")"
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
        --verbose|-v)
            VERBOSE=1
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
        *)
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
    esac
done

BUILD_TMP="/tmp/sbom-build-$$"
mkdir -p "$BUILD_TMP"
mkdir -p "$OUTPUT_DIR"

vlog() { [[ "$VERBOSE" == "1" ]] && log "$*" || true; }

log "cpp-sbom-builder Docker entrypoint"
log "Project dir : $PROJECT_DIR"
log "Output dir  : $OUTPUT_DIR"
log "Build tmp   : $BUILD_TMP"

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Conan install + graph info (if --conan-graph)
# ─────────────────────────────────────────────────────────────────────────────

if [[ "$DO_CONAN_GRAPH" == "1" ]]; then
    CONANFILE=""
    for candidate in \
        "$PROJECT_DIR/conanfile.py" \
        "$PROJECT_DIR/conanfile.txt"; do
        if [[ -f "$candidate" ]]; then
            CONANFILE="$candidate"
            break
        fi
    done

    if [[ -n "$CONANFILE" ]]; then
        log "Conan: found $CONANFILE"

        # Install dependencies into a temporary output folder
        CONAN_OUT="$BUILD_TMP/conan-out"
        mkdir -p "$CONAN_OUT"

        log "Conan: running conan install (this may take a while on first run)..."
        if conan install "$PROJECT_DIR" \
                --output-folder="$CONAN_OUT" \
                --build=missing \
                -s build_type=Release \
                2>&1 | ([ "$VERBOSE" = "1" ] && cat || grep -E "^(ERROR|WARN|Requirement)" || true); then
            log "Conan: install succeeded"
        else
            warn "Conan: install failed or partially failed — continuing with available data"
        fi

        # Generate the full dependency graph JSON
        GRAPH_JSON="$BUILD_TMP/graph.json"
        log "Conan: generating graph.json..."
        if conan graph info "$PROJECT_DIR" \
                --format=json \
                -s build_type=Release \
                > "$GRAPH_JSON" 2>/dev/null; then
            log "Conan: graph.json written to $GRAPH_JSON"
            # Copy to project build tmp so cpp-sbom-builder passive mode finds it
            cp "$GRAPH_JSON" "$BUILD_TMP/graph.json"
            # Also add --dir pointing to BUILD_TMP so the scanner finds graph.json
            # We inject it as an extra scan path hint via env var
            export SBOM_EXTRA_GRAPH_JSON="$GRAPH_JSON"
        else
            warn "Conan: graph info failed — will fall back to conanfile parsing"
        fi
    else
        warn "Conan: no conanfile.txt or conanfile.py found in $PROJECT_DIR — skipping conan install"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: CMake configure-only (if --cmake-configure)
#
# Goal: generate compile_commands.json and CMakeFiles/*/link.txt
# These give us all -I include paths and -l link flags without compiling.
# The link.txt files are the closest equivalent to a linker MAP file that
# we can produce without a full build.
# ─────────────────────────────────────────────────────────────────────────────

if [[ "$DO_CMAKE_CONFIGURE" == "1" ]]; then
    CMAKE_LISTS="$PROJECT_DIR/CMakeLists.txt"

    if [[ -f "$CMAKE_LISTS" ]]; then
        log "CMake: found CMakeLists.txt — running configure-only step"

        CMAKE_BUILD_DIR="$BUILD_TMP/cmake-build"
        mkdir -p "$CMAKE_BUILD_DIR"

        # Build the cmake configure command.
        # We try with the conan toolchain first (if conan install ran), then plain.
        CMAKE_EXTRA_ARGS=()
        CONAN_TOOLCHAIN="$BUILD_TMP/conan-out/conan_toolchain.cmake"
        if [[ -f "$CONAN_TOOLCHAIN" ]]; then
            log "CMake: using Conan toolchain at $CONAN_TOOLCHAIN"
            CMAKE_EXTRA_ARGS+=("-DCMAKE_TOOLCHAIN_FILE=$CONAN_TOOLCHAIN")
        fi

        log "CMake: configuring (no compilation)..."
        if cmake \
            -S "$PROJECT_DIR" \
            -B "$CMAKE_BUILD_DIR" \
            -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
            -DCMAKE_BUILD_TYPE=Release \
            -G "Ninja" \
            "${CMAKE_EXTRA_ARGS[@]}" \
            2>&1 | ([ "$VERBOSE" = "1" ] && cat || grep -E "^(CMake Error|CMake Warning|--)" | head -40 || true); then

            log "CMake: configure succeeded"

            # Copy compile_commands.json to the project root so the scanner finds it
            if [[ -f "$CMAKE_BUILD_DIR/compile_commands.json" ]]; then
                cp "$CMAKE_BUILD_DIR/compile_commands.json" "$BUILD_TMP/compile_commands.json"
                log "CMake: compile_commands.json copied to $BUILD_TMP"
            fi

            # Collect all link.txt files (linker command lines = MAP equivalent)
            # These contain the full -l flags and library paths the linker would use.
            LINK_TXT_COUNT=0
            while IFS= read -r -d '' link_txt; do
                LINK_TXT_COUNT=$((LINK_TXT_COUNT + 1))
                vlog "CMake: found link.txt: $link_txt"
            done < <(find "$CMAKE_BUILD_DIR" -name "link.txt" -print0 2>/dev/null)

            if [[ $LINK_TXT_COUNT -gt 0 ]]; then
                log "CMake: found $LINK_TXT_COUNT link.txt file(s) — these contain linker flags (MAP equivalent)"
                # The scanner's BuildLogsStrategy already parses link.txt files.
                # We point it at the cmake build dir by adding it as an extra scan path.
                export SBOM_EXTRA_BUILD_DIR="$CMAKE_BUILD_DIR"
            fi

        else
            warn "CMake: configure failed — this is common if the project needs specific toolchain settings"
            warn "CMake: continuing with other strategies"
        fi
    else
        warn "CMake: no CMakeLists.txt found in $PROJECT_DIR — skipping cmake configure"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: LDD scan (if --ldd)
#
# Run ldd on all .so files found in the project to get the full transitive
# runtime dependency tree. Results are written to a JSON file that the
# LddStrategy reads.
# ─────────────────────────────────────────────────────────────────────────────

if [[ "$DO_LDD" == "1" ]]; then
    log "LDD: scanning for .so files in $PROJECT_DIR..."

    LDD_OUTPUT="$BUILD_TMP/ldd-results.json"
    echo '{"results":[' > "$LDD_OUTPUT"
    FIRST=1

    while IFS= read -r -d '' so_file; do
        # Skip symlinks to avoid duplicates
        [[ -L "$so_file" ]] && continue

        # Check it's actually an ELF shared library
        if ! file "$so_file" 2>/dev/null | grep -q "ELF.*shared object"; then
            continue
        fi

        vlog "LDD: processing $so_file"

        # Run ldd and capture output
        LDD_OUT=$(ldd "$so_file" 2>/dev/null || true)
        if [[ -z "$LDD_OUT" ]]; then
            continue
        fi

        # Emit JSON entry
        if [[ $FIRST -eq 0 ]]; then
            echo ',' >> "$LDD_OUTPUT"
        fi
        FIRST=0

        # Escape the path for JSON
        SO_ESCAPED=$(printf '%s' "$so_file" | sed 's/\\/\\\\/g; s/"/\\"/g')
        echo -n "{\"library\":\"$SO_ESCAPED\",\"deps\":[" >> "$LDD_OUTPUT"

        DEP_FIRST=1
        while IFS= read -r ldd_line; do
            # ldd output format: "    libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x...)"
            # or:                "    libssl.so.3 => not found"
            if [[ "$ldd_line" =~ ^[[:space:]]+([^[:space:]]+)[[:space:]]+\=\>[[:space:]]+(/[^[:space:]]+) ]]; then
                DEP_NAME="${BASH_REMATCH[1]}"
                DEP_PATH="${BASH_REMATCH[2]}"
                DEP_NAME_ESC=$(printf '%s' "$DEP_NAME" | sed 's/"/\\"/g')
                DEP_PATH_ESC=$(printf '%s' "$DEP_PATH" | sed 's/"/\\"/g')
                if [[ $DEP_FIRST -eq 0 ]]; then
                    echo -n ',' >> "$LDD_OUTPUT"
                fi
                DEP_FIRST=0
                echo -n "{\"name\":\"$DEP_NAME_ESC\",\"path\":\"$DEP_PATH_ESC\"}" >> "$LDD_OUTPUT"
            fi
        done <<< "$LDD_OUT"

        echo -n ']}'  >> "$LDD_OUTPUT"

    done < <(find "$PROJECT_DIR" \( -name "*.so" -o -name "*.so.*" \) -print0 2>/dev/null)

    echo ']}'  >> "$LDD_OUTPUT"
    log "LDD: results written to $LDD_OUTPUT"
    export SBOM_LDD_RESULTS="$LDD_OUTPUT"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Run cpp-sbom-builder
#
# We pass the original args plus inject extra scan paths via env vars.
# The scanner reads SBOM_EXTRA_BUILD_DIR and SBOM_EXTRA_GRAPH_JSON to pick up
# files generated in the pre-scan steps.
# ─────────────────────────────────────────────────────────────────────────────

log "Running: cpp-sbom-builder ${PASSTHROUGH_ARGS[*]:-scan --dir /project --output /output/sbom.json}"
exec /usr/local/bin/cpp-sbom-builder "${PASSTHROUGH_ARGS[@]:-scan --dir /project --output /output/sbom.json}"
